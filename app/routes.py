from __future__ import annotations

from functools import wraps
from urllib.parse import urlsplit

from authlib.oauth2 import OAuth2Error
from authlib.oidc.core.errors import LoginRequiredError
from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    g,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    url_for,
)
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from .avatars import (
    AvatarError,
    avatar_response,
    delete_avatar_file,
    normalize_avatar_color,
    store_avatar,
)
from .backchannel import deliver_pending_jobs, queue_logout
from .extensions import authorization, db
from .models import (
    AppMembership,
    AuditLog,
    BackchannelJob,
    LegacyCredential,
    LoginAlias,
    OAuth2Client,
    User,
    utc_now,
)
from .oidc import public_jwks, require_oauth, userinfo_payload
from .security import (
    audit,
    authenticate,
    clear_session_cookie,
    create_web_session,
    csrf_token,
    hash_password,
    normalize_username,
    rate_limited,
    record_rate_event,
    revoke_user_oauth_tokens,
    revoke_user_sessions,
    safe_next,
    set_session_cookie,
    validate_csrf,
)

web = Blueprint("web", __name__)

HOME_CLIENT_META = {
    "todo": {
        "name": "TodoList",
        "preview": "previews/todolist.webp",
        "preview_alt": "TodoList 网页预览",
        "order": 0,
    },
    "techx": {
        "name": "TechX心情晴雨表",
        "preview": "previews/techx-mood.webp",
        "preview_alt": "TechX心情晴雨表网页预览",
        "order": 1,
    },
    "campus-wiki": {
        "name": "Campus Wiki",
        "preview": "previews/campus-wiki.webp",
        "preview_alt": "Campus Wiki 网页预览",
        "order": 2,
    },
    "cas": {
        "name": "Codex笔记中心",
        "preview": "previews/codex-notes.svg",
        "preview_alt": "Codex笔记中心网页预览",
        "order": 3,
    },
}


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.current_user is None:
            return redirect(url_for("web.login", next=safe_next(request.full_path.rstrip("?"))))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if not g.current_user.is_system_admin:
            abort(403)
        return view(*args, **kwargs)

    return wrapped


def require_csrf() -> None:
    if not validate_csrf(request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")):
        abort(400, "CSRF validation failed")


def continue_after_form(destination: str):
    """End a form navigation before continuing an OAuth redirect flow.

    Chromium applies ``form-action`` to every redirect in a form submission.
    Rendering a same-origin continuation page keeps the strict CSP while making
    the following OAuth navigation a regular top-level navigation.
    """
    if urlsplit(destination).path != "/oauth/authorize":
        return redirect(destination)
    response = make_response(render_template("continue.html", destination=destination))
    response.headers["Cache-Control"] = "no-store"
    return response


def record_admin_action(action: str) -> None:
    subject = str(g.current_user.id)
    if rate_limited("admin", subject, seconds=900, limit=60):
        abort(429, "管理员操作过于频繁，请稍后再试")
    record_rate_event("admin", subject, True)
    audit(action, target=g.current_user)
    db.session.commit()


def _create_user(username: str, display_name: str, password: str, *, admin: bool = False) -> User:
    username, username_key = normalize_username(username)
    display_name = display_name.strip()
    if not display_name or len(display_name) > 80:
        raise ValueError("显示名称需要在 1-80 个字符之间")
    item = User(
        username=username,
        username_key=username_key,
        display_name=display_name,
        password_hash=hash_password(password),
        is_system_admin=admin,
        terms_accepted_at=utc_now(),
    )
    db.session.add(item)
    db.session.flush()
    db.session.add(
        LoginAlias(user_id=item.id, alias=username, alias_key=username_key, source="central")
    )
    return item


@web.app_context_processor
def template_context():
    return {
        "current_user": getattr(g, "current_user", None),
        "csrf_token": csrf_token,
        "registration_enabled": current_app.config["REGISTRATION_ENABLED"],
    }


@web.get("/")
def home():
    clients = db.session.scalars(
        select(OAuth2Client).where(OAuth2Client.is_active.is_(True)).order_by(OAuth2Client.id)
    ).all()
    clients.sort(
        key=lambda client: (
            HOME_CLIENT_META.get(client.client_id, {}).get("order", len(HOME_CLIENT_META)),
            client.client_id,
        )
    )
    memberships = set()
    if g.current_user:
        memberships = set(
            db.session.scalars(
                select(AppMembership.client_id).where(AppMembership.user_id == g.current_user.id)
            ).all()
        )
    return render_template(
        "home.html",
        clients=clients,
        memberships=memberships,
        home_client_meta=HOME_CLIENT_META,
    )


@web.get("/health")
def health():
    db.session.execute(select(1)).scalar_one()
    return jsonify(status="ok")


@web.route("/register", methods=["GET", "POST"])
def register():
    if g.current_user:
        return redirect(url_for("web.account"))
    if not current_app.config["REGISTRATION_ENABLED"]:
        return render_template("register.html", disabled=True), 403
    next_url = safe_next(request.values.get("next"))
    if request.method == "POST":
        require_csrf()
        subject = request.remote_addr or "unknown"
        if rate_limited(
            "register",
            subject,
            seconds=86400,
            limit=current_app.config["REGISTER_LIMIT_PER_DAY"],
        ):
            flash("注册尝试过于频繁，请稍后再试。", "error")
            return render_template("register.html", disabled=False), 429
        if request.form.get("accept_terms") != "yes":
            flash("请先同意统一账号隐私说明。", "error")
            return render_template("register.html", disabled=False), 400
        password = request.form.get("password", "")
        if password != request.form.get("confirm_password", ""):
            flash("两次输入的密码不一致。", "error")
            return render_template("register.html", disabled=False), 400
        try:
            user = _create_user(
                request.form.get("username", ""),
                request.form.get("display_name", ""),
                password,
            )
            record_rate_event("register", subject, True)
            audit("auth.register", target=user)
            session, raw_token = create_web_session(user)
            db.session.commit()
        except ValueError as exc:
            db.session.rollback()
            record_rate_event("register", subject, False)
            db.session.commit()
            flash(str(exc), "error")
            return render_template("register.html", disabled=False), 400
        except IntegrityError:
            db.session.rollback()
            record_rate_event("register", subject, False)
            db.session.commit()
            flash("用户名已存在。", "error")
            return render_template("register.html", disabled=False), 409
        response = continue_after_form(next_url or url_for("web.account"))
        set_session_cookie(response, raw_token)
        return response
    return render_template("register.html", disabled=False)


@web.route("/login", methods=["GET", "POST"])
def login():
    next_url = safe_next(request.values.get("next"))
    if g.current_user:
        return redirect(next_url or url_for("web.account"))
    if request.method == "POST":
        require_csrf()
        username = request.form.get("username", "")
        subject = f"{request.remote_addr or ''}|{username.strip().casefold()}"
        if rate_limited(
            "login",
            subject,
            seconds=900,
            limit=current_app.config["LOGIN_LIMIT_PER_15_MINUTES"],
            failures_only=True,
        ):
            flash("登录失败次数过多，请稍后再试。", "error")
            return render_template("login.html"), 429
        user = authenticate(username, request.form.get("password", ""))
        record_rate_event("login", subject, user is not None)
        if user is None:
            audit("auth.login_failed", details={"username": username.strip()[:64]})
            db.session.commit()
            flash("用户名或密码错误。", "error")
            return render_template("login.html"), 401
        audit("auth.login", target=user)
        session, raw_token = create_web_session(user)
        db.session.commit()
        destination = next_url or url_for("web.account")
        if user.must_change_password:
            destination = url_for("web.account", next=destination)
            flash("这是临时密码，请先设置新密码。", "warning")
        response = continue_after_form(destination)
        set_session_cookie(response, raw_token)
        return response
    return render_template("login.html")


@web.post("/logout")
@login_required
def logout():
    require_csrf()
    g.auth_session.revoked_at = utc_now()
    audit("auth.logout", target=g.current_user)
    db.session.commit()
    response = redirect(url_for("web.home"))
    clear_session_cookie(response)
    return response


@web.route("/account", methods=["GET", "POST"])
@login_required
def account():
    if request.method == "POST":
        require_csrf()
        action = request.form.get("action")
        if action == "profile":
            display_name = request.form.get("display_name", "").strip()
            if not display_name or len(display_name) > 80:
                flash("显示名称需要在 1-80 个字符之间。", "error")
            else:
                g.current_user.display_name = display_name
                audit("account.profile_updated", target=g.current_user)
                db.session.commit()
                flash("资料已更新。", "success")
        elif action == "password":
            current_password = request.form.get("current_password", "")
            new_password = request.form.get("new_password", "")
            if new_password != request.form.get("confirm_password", ""):
                flash("两次输入的新密码不一致。", "error")
            elif authenticate(g.current_user.username, current_password) is None:
                flash("当前密码错误。", "error")
            else:
                try:
                    g.current_user.password_hash = hash_password(new_password)
                except ValueError as exc:
                    flash(str(exc), "error")
                else:
                    g.current_user.must_change_password = False
                    for credential in db.session.scalars(
                        select(LegacyCredential).where(
                            LegacyCredential.user_id == g.current_user.id
                        )
                    ):
                        db.session.delete(credential)
                    revoke_user_sessions(g.current_user.id)
                    revoke_user_oauth_tokens(g.current_user.id)
                    queue_logout(g.current_user, "password_changed")
                    audit("account.password_changed", target=g.current_user)
                    new_session, raw_token = create_web_session(g.current_user)
                    db.session.commit()
                    response = continue_after_form(
                        safe_next(request.args.get("next"), url_for("web.account"))
                    )
                    set_session_cookie(response, raw_token)
                    flash("密码已修改，其他会话已退出。", "success")
                    return response
        else:
            abort(400, "Unknown account action")
    memberships = db.session.execute(
        select(AppMembership, OAuth2Client)
        .join(OAuth2Client, OAuth2Client.client_id == AppMembership.client_id)
        .where(AppMembership.user_id == g.current_user.id)
        .order_by(AppMembership.first_authorized_at)
    ).all()
    aliases = db.session.scalars(
        select(LoginAlias).where(LoginAlias.user_id == g.current_user.id).order_by(LoginAlias.id)
    ).all()
    return render_template("account.html", memberships=memberships, aliases=aliases)


@web.post("/account/avatar")
@login_required
def account_avatar_upload():
    require_csrf()
    upload = request.files.get("avatar")
    if upload is None:
        flash("请选择头像文件。", "error")
        return redirect(url_for("web.account"))
    raw = upload.stream.read(current_app.config["AVATAR_UPLOAD_MAX_BYTES"] + 1)
    old_filename = g.current_user.avatar_file
    new_filename = None
    try:
        new_filename = store_avatar(g.current_user, raw)
        g.current_user.avatar_file = new_filename
        g.current_user.avatar_updated_at = utc_now()
        audit("account.avatar_updated", target=g.current_user)
        db.session.commit()
    except AvatarError as exc:
        db.session.rollback()
        if new_filename:
            delete_avatar_file(g.current_user, new_filename)
        flash(str(exc), "error")
        return redirect(url_for("web.account"))
    except Exception:
        db.session.rollback()
        if new_filename:
            delete_avatar_file(g.current_user, new_filename)
        raise
    delete_avatar_file(g.current_user, old_filename)
    flash("头像已更新。", "success")
    return redirect(url_for("web.account"))


@web.post("/account/avatar/delete")
@login_required
def account_avatar_delete():
    require_csrf()
    old_filename = g.current_user.avatar_file
    g.current_user.avatar_file = None
    g.current_user.avatar_updated_at = utc_now()
    audit("account.avatar_deleted", target=g.current_user)
    db.session.commit()
    delete_avatar_file(g.current_user, old_filename)
    flash("头像已移除。", "success")
    return redirect(url_for("web.account"))


@web.post("/account/avatar/color")
@login_required
def account_avatar_color():
    require_csrf()
    raw_color = request.form.get("avatar_color", "").strip().lower()
    color = normalize_avatar_color(raw_color)
    if color != raw_color:
        flash("请选择有效的头像背景色。", "error")
        return redirect(url_for("web.account"))
    g.current_user.avatar_color = color
    g.current_user.avatar_updated_at = utc_now()
    audit("account.avatar_color_updated", target=g.current_user)
    db.session.commit()
    flash("头像背景色已更新。", "success")
    return redirect(url_for("web.account"))


@web.get("/avatars/<uuid:subject>")
def public_avatar(subject):
    user = db.session.scalar(select(User).where(User.sub == str(subject)))
    if user is None or user.merged_into_user_id is not None:
        abort(404)
    return avatar_response(user)


@web.get("/admin")
@admin_required
def admin():
    users = db.session.scalars(select(User).order_by(User.id)).all()
    clients = db.session.scalars(select(OAuth2Client).order_by(OAuth2Client.id)).all()
    client_names = {client.client_id: client.client_name or client.client_id for client in clients}
    membership_map: dict[int, list[str]] = {}
    for membership in db.session.scalars(
        select(AppMembership).order_by(AppMembership.user_id, AppMembership.client_id)
    ):
        membership_map.setdefault(membership.user_id, []).append(
            client_names.get(membership.client_id, membership.client_id)
        )
    failed_jobs = db.session.scalar(
        select(func.count(BackchannelJob.id)).where(BackchannelJob.status == "failed")
    )
    return render_template(
        "admin.html",
        users=users,
        clients=clients,
        membership_map=membership_map,
        failed_jobs=failed_jobs or 0,
    )


@web.post("/admin/users/create")
@admin_required
def admin_create_user():
    require_csrf()
    record_admin_action("admin.create_user_attempt")
    try:
        user = _create_user(
            request.form.get("username", ""),
            request.form.get("display_name", ""),
            request.form.get("password", ""),
            admin=request.form.get("is_system_admin") == "yes",
        )
        user.must_change_password = True
        audit("admin.user_created", target=user)
        db.session.commit()
        flash("账号已创建，首次登录必须修改密码。", "success")
    except (ValueError, IntegrityError) as exc:
        db.session.rollback()
        flash(
            "无法创建账号：" + (str(exc) if isinstance(exc, ValueError) else "用户名已存在"),
            "error",
        )
    return redirect(url_for("web.admin"))


@web.post("/admin/users/<int:user_id>/toggle")
@admin_required
def admin_toggle_user(user_id: int):
    require_csrf()
    record_admin_action("admin.toggle_user_attempt")
    target = db.get_or_404(User, user_id)
    if target.id == g.current_user.id:
        abort(409, "不能停用自己的账号")
    if target.is_system_admin and target.is_active:
        admin_count = db.session.scalar(
            select(func.count(User.id)).where(
                User.is_system_admin.is_(True), User.is_active.is_(True)
            )
        )
        if int(admin_count or 0) <= 1:
            abort(409, "不能停用最后一个系统管理员")
    target.is_active = not target.is_active
    if not target.is_active:
        revoke_user_sessions(target.id)
        revoke_user_oauth_tokens(target.id)
        queue_logout(target, "account_disabled")
    audit("admin.user_toggled", target=target, details={"isActive": target.is_active})
    db.session.commit()
    flash("账号状态已更新。", "success")
    return redirect(url_for("web.admin"))


@web.post("/admin/users/<int:user_id>/reset-password")
@admin_required
def admin_reset_password(user_id: int):
    require_csrf()
    record_admin_action("admin.reset_password_attempt")
    target = db.get_or_404(User, user_id)
    try:
        target.password_hash = hash_password(request.form.get("temporary_password", ""))
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("web.admin")), 400
    target.must_change_password = True
    for credential in db.session.scalars(
        select(LegacyCredential).where(LegacyCredential.user_id == target.id)
    ):
        db.session.delete(credential)
    revoke_user_sessions(target.id)
    revoke_user_oauth_tokens(target.id)
    queue_logout(target, "password_reset")
    audit("admin.password_reset", target=target)
    db.session.commit()
    flash("临时密码已设置，用户下次登录必须修改。", "success")
    return redirect(url_for("web.admin"))


@web.post("/admin/users/<int:user_id>/delete")
@admin_required
def admin_delete_user(user_id: int):
    require_csrf()
    record_admin_action("admin.delete_user_attempt")
    target = db.get_or_404(User, user_id)
    if target.id == g.current_user.id:
        abort(409, "不能删除自己的账号")
    if target.is_active:
        abort(409, "请先停用账号，确认各网站会话退出后再删除")
    if db.session.scalar(select(User.id).where(User.merged_into_user_id == target.id)):
        abort(409, "该账号仍是其他已合并账号的目标，不能删除")
    unfinished_logout_count = db.session.scalar(
        select(func.count(BackchannelJob.id)).where(
            BackchannelJob.user_id == target.id,
            BackchannelJob.status != "delivered",
        )
    )
    if int(unfinished_logout_count or 0):
        abort(409, "该账号仍有未完成的退出通知，请处理后再删除")

    target_sub = target.sub
    target_username = target.username
    avatar_filename = target.avatar_file
    for log in db.session.scalars(
        select(AuditLog).where(
            (AuditLog.actor_user_id == target.id) | (AuditLog.target_user_id == target.id)
        )
    ):
        if log.actor_user_id == target.id:
            log.actor_user_id = None
        if log.target_user_id == target.id:
            log.target_user_id = None
    audit(
        "admin.user_deleted",
        details={"targetSub": target_sub, "targetUsername": target_username},
    )
    db.session.delete(target)
    db.session.commit()
    delete_avatar_file(target, avatar_filename)
    flash(f"账号 {target_username} 已永久删除。", "success")
    return redirect(url_for("web.admin"))


@web.post("/admin/users/merge")
@admin_required
def admin_merge_users():
    require_csrf()
    record_admin_action("admin.merge_users_attempt")
    source = db.get_or_404(User, int(request.form.get("source_user_id", "0")))
    target = db.get_or_404(User, int(request.form.get("target_user_id", "0")))
    if source.id == target.id or source.merged_into_user_id or target.merged_into_user_id:
        abort(409, "合并来源和目标无效")
    if source.id == g.current_user.id:
        abort(409, "不能把当前管理员账号作为合并来源")
    for alias in list(source.aliases):
        alias.user_id = target.id
    for credential in db.session.scalars(
        select(LegacyCredential).where(LegacyCredential.user_id == source.id)
    ):
        credential.user_id = target.id
    # Queue logout while the source still owns its memberships. The lookup in
    # queue_logout triggers an autoflush, so doing this after the transfer would
    # lose the clients whose source-account sessions must be revoked.
    queue_logout(source, "account_merged")
    for membership in db.session.scalars(
        select(AppMembership).where(AppMembership.user_id == source.id)
    ):
        existing = db.session.scalar(
            select(AppMembership).where(
                AppMembership.user_id == target.id,
                AppMembership.client_id == membership.client_id,
            )
        )
        if existing:
            existing.first_authorized_at = min(
                existing.first_authorized_at, membership.first_authorized_at
            )
            existing.last_authorized_at = max(
                existing.last_authorized_at, membership.last_authorized_at
            )
            db.session.delete(membership)
        else:
            membership.user_id = target.id
    revoke_user_sessions(source.id)
    revoke_user_oauth_tokens(source.id)
    target.is_system_admin = target.is_system_admin or source.is_system_admin
    source.is_system_admin = False
    source.is_active = False
    source.merged_into_user_id = target.id
    audit("admin.users_merged", target=target, details={"sourceSub": source.sub})
    db.session.commit()
    flash("账号已经合并；来源账号已停用。", "success")
    return redirect(url_for("web.admin"))


@web.get("/admin/audit")
@admin_required
def admin_audit():
    logs = db.session.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(200)).all()
    return render_template("audit.html", logs=logs)


@web.route("/admin/backchannel", methods=["GET", "POST"])
@admin_required
def admin_backchannel():
    if request.method == "POST":
        require_csrf()
        record_admin_action("admin.retry_backchannel")
        result = deliver_pending_jobs(50)
        flash(f"退出通知：成功 {result['delivered']}，失败 {result['failed']}。", "success")
        return redirect(url_for("web.admin_backchannel"))
    jobs = db.session.scalars(
        select(BackchannelJob).order_by(BackchannelJob.id.desc()).limit(200)
    ).all()
    return render_template("backchannel.html", jobs=jobs)


@web.get("/.well-known/openid-configuration")
def discovery():
    issuer = current_app.config["OIDC_ISSUER"]
    return jsonify(
        issuer=issuer,
        authorization_endpoint=issuer + "/oauth/authorize",
        token_endpoint=issuer + "/oauth/token",
        userinfo_endpoint=issuer + "/oauth/userinfo",
        revocation_endpoint=issuer + "/oauth/revoke",
        end_session_endpoint=issuer + "/oauth/logout",
        jwks_uri=issuer + "/.well-known/jwks.json",
        response_types_supported=["code"],
        grant_types_supported=["authorization_code"],
        subject_types_supported=["public"],
        id_token_signing_alg_values_supported=["RS256"],
        token_endpoint_auth_methods_supported=["client_secret_basic"],
        code_challenge_methods_supported=["S256"],
        scopes_supported=["openid", "profile"],
        claims_supported=[
            "sub",
            "preferred_username",
            "name",
            "picture",
            "sid",
            "auth_time",
            "nonce",
        ],
    )


@web.get("/.well-known/jwks.json")
def jwks():
    return jsonify(public_jwks())


@web.get("/oauth/authorize")
def oauth_authorize():
    if not request.args.get("state") or not request.args.get("nonce"):
        return jsonify(
            error="invalid_request", error_description="state and nonce are required"
        ), 400
    if g.current_user is None:
        next_url = safe_next(request.full_path.rstrip("?"))
        prompt_values = set(request.args.get("prompt", "").split())
        if "none" in prompt_values:
            oauth_request = authorization.create_oauth2_request(request)
            try:
                grant = authorization.get_authorization_grant(oauth_request)
                redirect_uri = grant.validate_authorization_request()
            except OAuth2Error as error:
                error.state = oauth_request.payload.state
                return authorization.handle_error_response(oauth_request, error)
            error = LoginRequiredError(redirect_uri=redirect_uri)
            error.state = oauth_request.payload.state
            return authorization.handle_error_response(oauth_request, error)
        endpoint = "web.register" if request.args.get("screen_hint") == "signup" else "web.login"
        return redirect(url_for(endpoint, next=next_url))
    if g.current_user.must_change_password:
        flash("继续授权前必须修改临时密码。", "warning")
        return redirect(url_for("web.account", next=safe_next(request.full_path.rstrip("?"))))
    g.current_user._auth_time = g.auth_session.auth_time
    g.current_user._sid = g.auth_session.sid
    oauth_request = authorization.create_oauth2_request(request)
    grant = authorization.get_authorization_grant(oauth_request)
    return authorization.create_authorization_response(
        request=oauth_request,
        grant_user=g.current_user,
        grant=grant,
    )


@web.post("/oauth/token")
def issue_token():
    return authorization.create_token_response()


@web.get("/oauth/userinfo")
@require_oauth("openid")
def userinfo():
    return jsonify(userinfo_payload())


@web.post("/oauth/revoke")
def revoke_token():
    return authorization.create_endpoint_response("revocation")


@web.route("/oauth/logout", methods=["GET", "POST"])
def oauth_logout():
    if request.method == "GET":
        return render_template("logout_all.html")
    if g.current_user is None:
        response = redirect(url_for("web.home"))
        clear_session_cookie(response)
        return response
    require_csrf()
    revoke_user_sessions(g.current_user.id)
    revoke_user_oauth_tokens(g.current_user.id)
    queue_logout(g.current_user, "logout_all")
    audit("auth.logout_all", target=g.current_user)
    db.session.commit()
    response = redirect(url_for("web.home"))
    clear_session_cookie(response)
    return response


@web.get("/oauth/backchannel-status")
@admin_required
def backchannel_status():
    counts = dict(
        db.session.execute(
            select(BackchannelJob.status, func.count(BackchannelJob.id)).group_by(
                BackchannelJob.status
            )
        ).all()
    )
    return jsonify(counts)
