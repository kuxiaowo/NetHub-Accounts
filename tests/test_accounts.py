from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select

from app.extensions import db
from app.models import (
    AppMembership,
    AuditLog,
    BackchannelJob,
    LoginAlias,
    OAuth2Client,
    User,
    WebSession,
    utc_now,
)
from app.security import PASSWORD_HASH
from tests.conftest import client_secret_hash, create_user, csrf_from


def register(client, username="Alice", password="password-123"):
    page = client.get("/register")
    return client.post(
        "/register",
        data={
            "csrf_token": csrf_from(page),
            "username": username,
            "display_name": "Alice Example",
            "password": password,
            "confirm_password": password,
            "accept_terms": "yes",
        },
    )


def login(client, username="alice", password="password-123", next_url="/"):
    page = client.get("/login", query_string={"next": next_url})
    return client.post(
        "/login",
        data={
            "csrf_token": csrf_from(page),
            "username": username,
            "password": password,
            "next": next_url,
        },
    )


def oauth_client(client_id: str) -> OAuth2Client:
    item = OAuth2Client(
        client_id=client_id,
        client_secret=client_secret_hash(f"{client_id}-client-secret"),
        client_id_issued_at=1,
        client_secret_expires_at=0,
        launch_uri=f"https://{client_id}.test/",
        backchannel_logout_uri=f"https://{client_id}.test/auth/backchannel-logout",
        is_active=True,
    )
    item.set_client_metadata(
        {
            "client_name": client_id,
            "redirect_uris": [f"https://{client_id}.test/auth/callback"],
            "scope": "openid profile",
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_basic",
        }
    )
    return item


def test_registration_normalizes_username_and_uses_argon2(app, client):
    response = register(client, "Ａlice")
    assert response.status_code == 302
    with app.app_context():
        user = db.session.scalar(select(User))
        assert user.username == "Alice"
        assert user.username_key == "alice"
        assert PASSWORD_HASH.verify("password-123", user.password_hash)
        assert db.session.scalar(select(AuditLog).where(AuditLog.action == "auth.register"))


def test_health(client):
    assert client.get("/health").get_json() == {"status": "ok"}


def test_registration_is_case_insensitive(app, client):
    assert register(client, "Alice").status_code == 302
    other = app.test_client()
    response = register(other, "alice")
    assert response.status_code == 409


def test_registration_rate_limit_is_persistent_per_ip(app, client):
    app.config["REGISTER_LIMIT_PER_DAY"] = 1
    assert register(client, "Alice").status_code == 302
    second_browser = app.test_client()
    assert register(second_browser, "Bob").status_code == 429


def test_registration_can_be_disabled(app, client):
    app.config["REGISTRATION_ENABLED"] = False
    assert client.get("/register").status_code == 403


def test_login_rejects_external_next_url(app, client):
    with app.app_context():
        create_user()
    response = login(client, next_url="https://evil.example/")
    assert response.status_code == 302
    assert response.location.endswith("/")


def test_admin_reset_forces_password_change_and_revokes_sessions(app, client):
    with app.app_context():
        admin = create_user("admin", admin=True)
        target = create_user("target")
        admin_id = admin.id
        target_id = target.id
    assert login(client, "admin").status_code == 302
    page = client.get("/admin")
    response = client.post(
        f"/admin/users/{target_id}/reset-password",
        data={"csrf_token": csrf_from(page), "temporary_password": "temporary-123"},
    )
    assert response.status_code == 302
    target_client = app.test_client()
    response = login(target_client, "target", "temporary-123", "/oauth/authorize")
    assert response.status_code == 302
    assert response.location.startswith("/account")
    with app.app_context():
        target = db.session.get(User, target_id)
        assert target.must_change_password is True
        assert db.session.scalars(select(WebSession).where(WebSession.user_id == admin_id)).all()

    account_page = target_client.get("/account")
    changed = target_client.post(
        "/account",
        data={
            "csrf_token": csrf_from(account_page),
            "action": "password",
            "current_password": "temporary-123",
            "new_password": "new-password-456",
            "confirm_password": "new-password-456",
        },
    )
    assert changed.status_code == 302
    with app.app_context():
        assert db.session.get(User, target_id).must_change_password is False
    fresh_browser = app.test_client()
    assert login(fresh_browser, "target", "temporary-123").status_code == 401
    assert login(fresh_browser, "target", "new-password-456").status_code == 302


def test_admin_can_merge_accounts_and_preserve_memberships(app, client):
    with app.app_context():
        create_user("admin", admin=True)
        source = create_user("old-name", "source-password")
        target = create_user("new-name", "target-password")
        source_id = source.id
        target_id = target.id
        now = utc_now()
        db.session.add_all(
            [
                oauth_client("todo"),
                oauth_client("techx"),
                AppMembership(
                    user_id=source.id,
                    client_id="todo",
                    first_authorized_at=now - timedelta(days=10),
                    last_authorized_at=now - timedelta(days=1),
                ),
                AppMembership(
                    user_id=target.id,
                    client_id="todo",
                    first_authorized_at=now - timedelta(days=5),
                    last_authorized_at=now,
                ),
                AppMembership(user_id=source.id, client_id="techx"),
            ]
        )
        db.session.commit()

    assert login(client, "admin").status_code == 302
    page = client.get("/admin")
    response = client.post(
        "/admin/users/merge",
        data={
            "csrf_token": csrf_from(page),
            "source_user_id": source_id,
            "target_user_id": target_id,
        },
    )
    assert response.status_code == 302
    with app.app_context():
        source = db.session.get(User, source_id)
        assert source.is_active is False
        assert source.merged_into_user_id == target_id
        alias = db.session.scalar(select(LoginAlias).where(LoginAlias.alias_key == "old-name"))
        assert alias.user_id == target_id
        memberships = db.session.scalars(
            select(AppMembership).where(AppMembership.user_id == target_id)
        ).all()
        assert {item.client_id for item in memberships} == {"todo", "techx"}
        todo = next(item for item in memberships if item.client_id == "todo")
        assert todo.first_authorized_at == now - timedelta(days=10)
        assert todo.last_authorized_at == now
        jobs = db.session.scalars(
            select(BackchannelJob).where(BackchannelJob.user_id == source_id)
        ).all()
        assert {job.client_id for job in jobs} == {"todo", "techx"}
        assert all(job.reason == "account_merged" for job in jobs)
        assert db.session.scalar(select(AuditLog).where(AuditLog.action == "admin.users_merged"))

    merged_browser = app.test_client()
    assert login(merged_browser, "old-name", "source-password").status_code == 401
    assert login(merged_browser, "old-name", "target-password").status_code == 302


def test_admin_can_create_disable_and_restore_account(app, client):
    with app.app_context():
        create_user("admin", admin=True)
    assert login(client, "admin").status_code == 302
    page = client.get("/admin")
    created = client.post(
        "/admin/users/create",
        data={
            "csrf_token": csrf_from(page),
            "username": "managed-user",
            "display_name": "Managed User",
            "password": "temporary-123",
        },
    )
    assert created.status_code == 302
    with app.app_context():
        managed = db.session.scalar(select(User).where(User.username_key == "managed-user"))
        managed_id = managed.id
        assert managed.must_change_password is True

    page = client.get("/admin")
    assert (
        client.post(
            f"/admin/users/{managed_id}/toggle",
            data={"csrf_token": csrf_from(page)},
        ).status_code
        == 302
    )
    with app.app_context():
        assert db.session.get(User, managed_id).is_active is False
    assert login(app.test_client(), "managed-user", "temporary-123").status_code == 401

    page = client.get("/admin")
    assert (
        client.post(
            f"/admin/users/{managed_id}/toggle",
            data={"csrf_token": csrf_from(page)},
        ).status_code
        == 302
    )
    with app.app_context():
        assert db.session.get(User, managed_id).is_active is True
    assert login(app.test_client(), "managed-user", "temporary-123").status_code == 302


def test_csrf_is_required(client):
    response = client.post(
        "/register",
        data={
            "username": "alice",
            "display_name": "Alice",
            "password": "password-123",
            "confirm_password": "password-123",
            "accept_terms": "yes",
        },
    )
    assert response.status_code == 400


def test_login_rate_limit_counts_failures_only(app, client):
    with app.app_context():
        create_user()
    app.config["LOGIN_LIMIT_PER_15_MINUTES"] = 2
    assert login(client, password="wrong-one").status_code == 401
    assert login(client, password="wrong-two").status_code == 401
    assert login(client).status_code == 429


def test_successful_logins_do_not_consume_failure_limit(app, client):
    with app.app_context():
        create_user()
    app.config["LOGIN_LIMIT_PER_15_MINUTES"] = 1
    assert login(client).status_code == 302
    client.post("/logout", data={"csrf_token": csrf_from(client.get("/account"))})
    assert login(client).status_code == 302
