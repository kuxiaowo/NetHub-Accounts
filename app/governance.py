"""Central invitation, verified-email and account restriction policy (SQLite)."""

from __future__ import annotations

import base64
import hashlib
import html
import re
import secrets
from contextlib import contextmanager, nullcontext
from datetime import datetime, timedelta

import click
import requests
from cryptography.fernet import Fernet
from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)
from sqlalchemy import delete, func, select, text, update
from sqlalchemy.exc import IntegrityError

from .backchannel import queue_logout
from .extensions import db
from .models import (
    AppMembership,
    AuditLog,
    EmailJob,
    EmailVerification,
    Invitation,
    OAuth2Client,
    User,
    utc_now,
)
from .routes import admin_required, login_required, require_csrf
from .security import (
    audit,
    client_ip,
    rate_limited,
    record_rate_event,
    revoke_user_access,
    token_digest,
)

governance = Blueprint("governance", __name__)


@governance.app_template_filter("beijing_time")
def beijing_time(value):
    return (value + timedelta(hours=8)).strftime("%Y-%m-%d %H:%M（北京时间）") if value else "—"


@governance.cli.command("cleanup")
def cleanup():
    """Run daily with the application's configured environment."""
    cleanup_records()
    click.echo("Governance retention cleanup completed")


def cleanup_records():
    now = utc_now()
    with write_lock():
        db.session.execute(
            delete(EmailVerification).where(EmailVerification.expires_at < now - timedelta(days=30))
        )
        db.session.execute(
            delete(Invitation).where(Invitation.detached_at < now - timedelta(days=180))
        )
        penalties = [
            "admin.ban",
            "admin.unban",
            "admin.suspend_invitation",
            "admin.restore_invitation",
        ]
        db.session.execute(
            delete(AuditLog).where(
                AuditLog.action.in_(penalties), AuditLog.created_at < now - timedelta(days=365)
            )
        )


@contextmanager
def write_lock():
    # Finish request-user lookup before acquiring SQLite's writer lock.
    db.session.commit()
    db.session.execute(text("BEGIN IMMEDIATE"))
    try:
        yield
        db.session.commit()
    except Exception:
        db.session.rollback()
        raise


def normalize_email(value: str) -> str:
    email = value.strip().casefold()
    if len(email) > 254 or not re.fullmatch(r"[^\s<>@]+@[^\s<>@]+\.[^\s<>@]+", email):
        raise ValueError("请输入有效邮箱地址")
    return email


def invitation_blocker(user: User, now=None) -> str:
    now = now or utc_now()
    if not user.is_active or user.merged_into_user_id:
        return "账号已封禁或停用"
    if user.invitation_suspended and (
        user.invitation_suspended_until is None or user.invitation_suspended_until > now
    ):
        return "邀请权限已暂停"
    if not user.email_verified_at or not user.first_email_verified_at:
        return "请先验证邮箱"
    unlock = user.first_email_verified_at + timedelta(hours=72)
    if unlock > now:
        return "首次邮箱验证满 72 小时后可邀请"
    return ""


def create_invitation(user_id: int) -> tuple[Invitation, str]:
    now = utc_now()
    day = (now + timedelta(hours=8)).date().isoformat()
    with write_lock():
        user = db.session.get(User, user_id, populate_existing=True)
        if not user or (reason := invitation_blocker(user, now)):
            raise ValueError(reason if user else "账号不存在")
        if db.session.scalar(
            select(Invitation.id).where(
                Invitation.inviter_id == user_id, Invitation.issued_day == day
            )
        ):
            raise ValueError("今日邀请额度已使用，明日北京时间 00:00 重置")
        token = secrets.token_urlsafe(32)
        item = Invitation(
            inviter_id=user_id,
            token_hash=token_digest(token),
            issued_day=day,
            created_at=now,
            expires_at=now + timedelta(days=7),
        )
        db.session.add(item)
        audit("invitation.created", target=user, details={"day": day})
        db.session.flush()
        return item, token


def redeem_invitation(token: str, invitee: User) -> None:
    """Caller holds the registration write lock; creation and redemption commit together."""
    now = utc_now()
    item = db.session.scalar(select(Invitation).where(Invitation.token_hash == token_digest(token)))
    if not item or item.revoked_at or item.redeemed_at or item.expires_at <= now:
        raise ValueError("邀请凭证无效、已使用或已过期")
    owner = db.session.get(User, item.inviter_id, populate_existing=True)
    if not owner or invitation_blocker(owner, now):
        raise ValueError("邀请人的账号或邀请权限不可用")
    item.invitee_id, item.redeemed_at = invitee.id, now


def cipher() -> Fernet:
    key = hashlib.sha256(current_app.config["SECRET_KEY"].encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def request_verification(user_id: int, email: str, *, locked=False) -> None:
    email = normalize_email(email)
    if not current_app.config.get("RESEND_API_KEY") or not current_app.config.get("MAIL_FROM"):
        raise ValueError("邮件验证服务尚未配置，请联系管理员")
    now = utc_now()
    day_start = datetime.combine(
        (now + timedelta(hours=8)).date(), datetime.min.time()
    ) - timedelta(hours=8)
    with nullcontext() if locked else write_lock():
        user = db.session.get(User, user_id, populate_existing=True)
        if not user or not user.is_active:
            raise ValueError("账号不可用")
        if user.email == email and user.email_verified_at:
            raise ValueError("该邮箱已经验证")
        if db.session.scalar(select(User.id).where(User.email == email, User.id != user_id)):
            raise ValueError("该邮箱已绑定其他账号")
        latest = db.session.scalar(
            select(func.max(EmailVerification.created_at)).where(
                EmailVerification.user_id == user_id
            )
        )
        count_user = db.session.scalar(
            select(func.count())
            .select_from(EmailVerification)
            .where(EmailVerification.user_id == user_id, EmailVerification.created_at >= day_start)
        )
        count_email = db.session.scalar(
            select(func.count())
            .select_from(EmailVerification)
            .where(EmailVerification.email == email, EmailVerification.created_at >= day_start)
        )
        if (latest and latest > now - timedelta(seconds=60)) or max(
            count_user or 0, count_email or 0
        ) >= 5:
            raise ValueError("验证邮件发送过于频繁，请稍后重试")
        raw = secrets.token_urlsafe(32)
        item = EmailVerification(
            user_id=user_id,
            email=email,
            token_hash=token_digest(raw),
            created_at=now,
            expires_at=now + timedelta(hours=24),
        )
        db.session.add(item)
        db.session.flush()
        link = current_app.config["OIDC_ISSUER"] + "/email/verify?token=" + raw
        payload = cipher().encrypt(link.encode()).decode()
        db.session.add(EmailJob(verification_id=item.id, payload_encrypted=payload))
        audit("email.verification_requested", target=user)


def deliver_email_jobs(limit=5):
    """Lease jobs before HTTP; use Resend idempotency keys after lost acknowledgements."""
    for _ in range(limit):
        now = utc_now()
        with write_lock():
            job = db.session.scalar(
                select(EmailJob)
                .where(
                    ((EmailJob.status == "pending") & (EmailJob.next_attempt_at <= now))
                    | ((EmailJob.status == "sending") & (EmailJob.lease_until <= now))
                )
                .order_by(EmailJob.id)
                .limit(1)
            )
            if job is None:
                return
            verification = db.session.get(EmailVerification, job.verification_id)
            if verification.expires_at <= now or verification.consumed_at or job.attempts >= 3:
                job.status, job.payload_encrypted = "failed", ""
                continue
            job.status, job.lease_until = "sending", now + timedelta(seconds=60)
            job.attempts += 1
            job_id, email, payload, attempt = (
                job.id,
                verification.email,
                job.payload_encrypted,
                job.attempts,
            )
        error = ""
        try:
            link = cipher().decrypt(payload.encode()).decode()
            response = requests.post(
                "https://api.resend.com/emails",
                timeout=15,
                headers={
                    "Authorization": "Bearer " + current_app.config["RESEND_API_KEY"],
                    "Idempotency-Key": f"nethub-email-{job_id}",
                },
                json={
                    "from": current_app.config["MAIL_FROM"],
                    "to": [email],
                    "subject": "验证你的 NetHub 邮箱",
                    "html": '<p>请在 24 小时内验证邮箱。</p><p><a href="'
                    + html.escape(link, quote=True)
                    + '">验证邮箱</a></p><p>如非本人操作，请忽略。</p>',
                },
            )
            if response.status_code not in {200, 201, 202}:
                error = f"resend_http_{response.status_code}"
        except Exception:
            error = "mail_delivery_failed"
        with write_lock():
            job = db.session.get(EmailJob, job_id, populate_existing=True)
            if job.status != "sending" or job.attempts != attempt:
                continue
            job.error_code, job.lease_until = error, None
            job.status = ("failed" if attempt >= 3 else "pending") if error else "sent"
            job.next_attempt_at = utc_now() + timedelta(seconds=60 * attempt)
            if job.status in {"sent", "failed"}:
                job.payload_encrypted = ""


def restore_expired_bans():
    if current_app.config.get("ACCOUNTS_DATABASE_BACKEND") != "sqlite":
        return
    now = utc_now()
    if not db.session.scalar(
        select(User.id).where(User.banned_until.is_not(None), User.banned_until <= now).limit(1)
    ):
        return
    db.session.execute(
        update(User)
        .where(
            User.banned_until.is_not(None),
            User.banned_until <= now,
            User.merged_into_user_id.is_(None),
        )
        .values(is_active=True, banned_until=None, ban_reason="")
    )
    db.session.commit()


@governance.get("/api/client/account-status")
def account_status():
    auth = request.authorization
    if not auth or auth.type.lower() != "basic":
        abort(401)
    client = db.session.scalar(
        select(OAuth2Client).where(
            OAuth2Client.client_id == auth.username, OAuth2Client.is_active.is_(True)
        )
    )
    if not client or not client.check_client_secret(auth.password or ""):
        abort(401)
    if rate_limited("client_status", client.client_id, seconds=60, limit=600):
        abort(429)
    record_rate_event("client_status", client.client_id, True)
    db.session.commit()
    user = db.session.scalar(
        select(User)
        .join(AppMembership)
        .where(User.sub == request.args.get("sub", ""), AppMembership.client_id == client.client_id)
    )
    if user is None:
        abort(404)
    return jsonify(
        active=bool(user.is_active and not user.merged_into_user_id),
        emailVerified=bool(user.email_verified_at),
        firstEmailVerifiedAt=user.first_email_verified_at.isoformat() + "Z"
        if user.first_email_verified_at
        else None,
    )


@governance.get("/account/community")
@login_required
def community():
    invitations = db.session.scalars(
        select(Invitation)
        .where(Invitation.inviter_id == g.current_user.id)
        .order_by(Invitation.id.desc())
        .limit(30)
    ).all()
    delivery = db.session.scalar(
        select(EmailJob)
        .join(EmailVerification)
        .where(EmailVerification.user_id == g.current_user.id)
        .order_by(EmailJob.id.desc())
        .limit(1)
    )
    return render_template(
        "community.html",
        invitations=invitations,
        blocker=invitation_blocker(g.current_user),
        now=utc_now(),
        delivery=delivery,
    )


@governance.get("/admin/invitations")
@admin_required
def invitation_relations():
    page = max(1, request.args.get("page", 1, type=int))
    items = db.session.scalars(
        select(Invitation).order_by(Invitation.id.desc()).limit(30).offset((page - 1) * 30)
    ).all()
    ids = {ident for item in items for ident in (item.inviter_id, item.invitee_id) if ident}
    users = {
        user.id: user.username for user in db.session.scalars(select(User).where(User.id.in_(ids)))
    }
    return render_template(
        "invitation_relations.html", items=items, names=users, page=page, now=utc_now()
    )


@governance.post("/account/invitations")
@login_required
def issue():
    require_csrf()
    try:
        item, raw = create_invitation(g.current_user.id)
    except (ValueError, IntegrityError) as exc:
        flash(str(exc) if isinstance(exc, ValueError) else "今日额度已使用", "error")
        return redirect(url_for("governance.community"))
    response = current_app.make_response(
        render_template(
            "invitation_created.html",
            link=current_app.config["OIDC_ISSUER"] + "/register?invite=" + raw,
            expires=item.expires_at,
        )
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@governance.post("/account/invitations/<int:invitation_id>/revoke")
@login_required
def revoke(invitation_id):
    require_csrf()
    with write_lock():
        item = db.session.get(Invitation, invitation_id)
        if not item or item.inviter_id != g.current_user.id:
            abort(404)
        if item.redeemed_at:
            abort(409, "已使用凭证不能撤销")
        item.revoked_at = item.revoked_at or utc_now()
        audit("invitation.revoked", target=g.current_user, details={"invitationId": item.id})
    return redirect(url_for("governance.community"))


@governance.post("/account/email")
@login_required
def email_request():
    require_csrf()
    ip = client_ip()
    if rate_limited("verify_email", ip, seconds=3600, limit=20):
        abort(429)
    record_rate_event("verify_email", ip, True)
    db.session.commit()
    try:
        request_verification(g.current_user.id, request.form.get("email", ""))
        flash("验证邮件已加入发送队列，请查收；链接有效期为 24 小时。", "success")
    except ValueError as exc:
        flash(str(exc), "error")
    return redirect(url_for("governance.community"))


@governance.route("/email/verify", methods=["GET", "POST"])
def verify_email():
    # Mail scanners may GET the link: only an explicit CSRF-protected POST consumes it.
    raw = request.values.get("token", "")
    if request.method == "GET":
        response = current_app.make_response(render_template("verify_email.html", token=raw))
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response
    require_csrf()
    try:
        with write_lock():
            item = db.session.scalar(
                select(EmailVerification).where(EmailVerification.token_hash == token_digest(raw))
            )
            if not item or item.consumed_at or item.expires_at <= utc_now():
                abort(400, "验证链接无效、已使用或已过期")
            user = db.session.get(User, item.user_id, populate_existing=True)
            if not user or not user.is_active:
                abort(403)
            if db.session.scalar(
                select(User.id).where(User.email == item.email, User.id != user.id)
            ):
                abort(409, "邮箱已绑定其他账号")
            now = utc_now()
            user.email, user.email_verified_at = item.email, now
            user.first_email_verified_at = user.first_email_verified_at or now
            db.session.execute(
                update(EmailVerification)
                .where(
                    EmailVerification.user_id == user.id, EmailVerification.consumed_at.is_(None)
                )
                .values(consumed_at=now)
            )
            audit("email.verified", target=user)
    except IntegrityError:
        abort(409, "邮箱已绑定其他账号")
    flash("邮箱验证成功，请返回个人中心。", "success")
    return redirect(url_for("web.account"))


@governance.post("/admin/users/<int:user_id>/restriction")
@admin_required
def restrict(user_id):
    require_csrf()
    action = request.form.get("action")
    reason = request.form.get("reason", "").strip()
    if (
        action not in {"ban", "unban", "suspend_invitation", "restore_invitation"}
        or not 1 <= len(reason) <= 500
    ):
        abort(422, "请选择操作并填写 1–500 字原因")
    duration = request.form.get("days", "0")
    if duration not in {"0", "1", "7", "30"}:
        abort(422)
    until = utc_now() + timedelta(days=int(duration)) if int(duration) else None
    with write_lock():
        user = db.session.get(User, user_id, populate_existing=True)
        if not user or user.merged_into_user_id:
            abort(404)
        if action == "ban":
            if user.id == g.current_user.id:
                abort(409, "不能封禁自己")
            admins = db.session.scalar(
                select(func.count())
                .select_from(User)
                .where(User.is_system_admin.is_(True), User.is_active.is_(True))
            )
            if user.is_system_admin and user.is_active and admins <= 1:
                abort(409, "不能封禁最后一位有效管理员")
            user.is_active, user.banned_until, user.ban_reason = False, until, reason
            revoke_user_access(user.id)
            queue_logout(user, "account_disabled")
        elif action == "unban":
            user.is_active, user.banned_until, user.ban_reason = True, None, ""
        elif action == "suspend_invitation":
            user.invitation_suspended, user.invitation_suspended_until = True, until
        else:
            user.invitation_suspended, user.invitation_suspended_until = False, None
        if action in {"ban", "suspend_invitation"}:
            db.session.execute(
                update(Invitation)
                .where(
                    Invitation.inviter_id == user.id,
                    Invitation.redeemed_at.is_(None),
                    Invitation.revoked_at.is_(None),
                )
                .values(revoked_at=utc_now())
            )
        audit(
            "admin." + action,
            target=user,
            details={"reason": reason, "until": until.isoformat() if until else None},
        )
    flash("限制已更新；全站退出通知将在后台重试直至成功。", "success")
    return redirect(url_for("web.admin"))


@governance.get("/policy")
def policy():
    return render_template("community_policy.html")
