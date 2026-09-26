from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import unicodedata
from datetime import timedelta
from urllib.parse import urlsplit

from flask import current_app, g, has_request_context, request, session
from pwdlib import PasswordHash
from sqlalchemy import delete, select
from werkzeug.security import check_password_hash as check_werkzeug_password

from .account_repository import account_repository
from .extensions import db
from .models import (
    AuthorizationCode,
    LegacyCredential,
    OAuth2Token,
    RateLimitEvent,
    User,
    WebSession,
    utc_now,
)
from .security_repository import D1SecurityRepository, SqlAlchemySecurityRepository

PASSWORD_HASH = PasswordHash.recommended()
USERNAME_PATTERN = re.compile(r"^[\w.\-]{2,32}$", re.UNICODE)
SESSION_COOKIE = "nethub_session"


def _security_repository():
    if current_app.config.get("ACCOUNTS_DATABASE_BACKEND", "sqlite") == "d1":
        client = current_app.extensions.get("d1_gateway_client")
        if client is not None:
            return D1SecurityRepository(client)
    return SqlAlchemySecurityRepository()


def normalize_username(value: str) -> tuple[str, str]:
    username = unicodedata.normalize("NFKC", value.strip())
    if not USERNAME_PATTERN.fullmatch(username):
        raise ValueError("用户名需为 2-32 位，只能包含文字、数字、下划线、点或连字符")
    return username, username.casefold()


def normalize_imported_alias(value: str) -> tuple[str, str]:
    alias = unicodedata.normalize("NFKC", value.strip())
    if (
        not alias
        or len(alias) > 64
        or any(unicodedata.category(ch).startswith("C") for ch in alias)
    ):
        raise ValueError("旧用户名为空、过长或包含控制字符")
    return alias, alias.casefold()


def validate_password(password: str) -> None:
    if len(password) < 8 or len(password) > 128:
        raise ValueError("密码长度需要在 8-128 个字符之间")


def hash_password(password: str) -> str:
    validate_password(password)
    return PASSWORD_HASH.hash(password)


def _verify_todo_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations, salt_text, digest_text = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        salt = base64.urlsafe_b64decode(salt_text + "=" * (-len(salt_text) % 4))
        expected = base64.urlsafe_b64decode(digest_text + "=" * (-len(digest_text) % 4))
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(iterations))
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def verify_legacy_password(credential: LegacyCredential, password: str) -> bool:
    if credential.algorithm == "todo_pbkdf2_sha256":
        return _verify_todo_password(password, credential.password_hash)
    if credential.algorithm == "werkzeug":
        try:
            return check_werkzeug_password(credential.password_hash, password)
        except (ValueError, TypeError):
            return False
    return False


def authenticate(username: str, password: str) -> User | None:
    try:
        _, key = normalize_imported_alias(username)
    except ValueError:
        return None
    found = account_repository().find_login(key)
    if found is None:
        return None
    user, legacy_items = found
    if not user.is_active or user.merged_into_user_id is not None:
        return None
    if user.password_hash:
        try:
            if PASSWORD_HASH.verify(password, user.password_hash):
                return user
        except Exception:  # An unknown/corrupt hash must behave like a failed login.
            return None
    if any(verify_legacy_password(item, password) for item in legacy_items):
        # A legacy password may predate the central 8-128 character policy.
        # It has already been verified against the imported hash, so migrate it
        # without rejecting the login and require the user to choose a compliant
        # password before authorizing any application.
        try:
            validate_password(password)
        except ValueError:
            user.must_change_password = True
        upgraded_hash = PASSWORD_HASH.hash(password)
        repository = _security_repository()
        repository.upgrade_password(
            user.id,
            upgraded_hash,
            user.must_change_password,
            actor_user_id=None,
            ip_address=client_ip() if has_request_context() else "",
        )
        user.password_hash = upgraded_hash
        if current_app.config.get("ACCOUNTS_DATABASE_BACKEND", "sqlite") != "d1":
            audit("auth.legacy_password_upgraded", target=user)
        # SQLite commits the unit of work here. D1 already committed its batch;
        # its session facade must not be treated as a transaction boundary.
        if current_app.config.get("ACCOUNTS_DATABASE_BACKEND", "sqlite") != "d1":
            db.session.commit()
        return user
    return None


def token_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def create_web_session(user: User) -> tuple[WebSession, str]:
    now = utc_now()
    raw_token = secrets.token_urlsafe(48)
    item = WebSession(
        token_hash=token_digest(raw_token),
        user_id=user.id,
        csrf_token=secrets.token_urlsafe(32),
        auth_time=int(now.timestamp()),
        created_at=now,
        last_seen_at=now,
        idle_expires_at=now + timedelta(seconds=current_app.config["SESSION_IDLE_SECONDS"]),
        absolute_expires_at=now + timedelta(seconds=current_app.config["SESSION_ABSOLUTE_SECONDS"]),
    )
    repository = _security_repository()
    if current_app.config.get("ACCOUNTS_DATABASE_BACKEND", "sqlite") == "d1":
        item = repository.create_web_session(
            {
                "token_hash": item.token_hash,
                "user_id": item.user_id,
                "csrf_token": item.csrf_token,
                "auth_time": item.auth_time,
                "created_at": item.created_at,
                "last_seen_at": item.last_seen_at,
                "idle_expires_at": item.idle_expires_at,
                "absolute_expires_at": item.absolute_expires_at,
            }
        )
    else:
        db.session.add(item)
        db.session.flush()
    return item, raw_token


def revoke_user_sessions(user_id: int) -> None:
    now = utc_now()
    _security_repository().revoke_sessions(user_id, now)


def revoke_session(sid: str) -> None:
    _security_repository().revoke_session(sid, utc_now())


def revoke_user_access(user_id: int) -> None:
    """Revoke all browser and OAuth access in one repository operation."""
    _security_repository().revoke_access(user_id, utc_now())


def revoke_user_oauth_tokens(user_id: int) -> None:
    now = int(utc_now().timestamp())
    if current_app.config.get("ACCOUNTS_DATABASE_BACKEND", "sqlite") == "d1":
        _security_repository().revoke_oauth_tokens(user_id, now)
        return
    for item in db.session.scalars(
        select(OAuth2Token).where(
            OAuth2Token.user_id == user_id,
            OAuth2Token.access_token_revoked_at == 0,
        )
    ):
        item.access_token_revoked_at = now


def load_request_user() -> None:
    g.auth_session = None
    g.current_user = None
    raw = request.cookies.get(SESSION_COOKIE, "")
    if not raw:
        return
    repository = _security_repository()
    item = (
        repository.load_web_session(token_digest(raw), utc_now())
        if current_app.config.get("ACCOUNTS_DATABASE_BACKEND", "sqlite") == "d1"
        else db.session.scalar(select(WebSession).where(WebSession.token_hash == token_digest(raw)))
    )
    now = utc_now()
    if (
        item is None
        or item.revoked_at is not None
        or item.idle_expires_at <= now
        or item.absolute_expires_at <= now
        or not item.user.is_active
        or item.user.merged_into_user_id is not None
    ):
        return
    item.last_seen_at = now
    item.idle_expires_at = min(
        now + timedelta(seconds=current_app.config["SESSION_IDLE_SECONDS"]),
        item.absolute_expires_at,
    )
    if current_app.config.get("ACCOUNTS_DATABASE_BACKEND", "sqlite") == "d1":
        repository.refresh_web_session(item.sid, item.last_seen_at, item.idle_expires_at)
    else:
        db.session.commit()
    g.auth_session = item
    g.current_user = item.user


def set_session_cookie(response, raw_token: str) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        raw_token,
        max_age=current_app.config["SESSION_ABSOLUTE_SECONDS"],
        secure=current_app.config["SESSION_COOKIE_SECURE"],
        httponly=True,
        samesite="Lax",
        path="/",
    )


def clear_session_cookie(response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/")


def csrf_token() -> str:
    if getattr(g, "auth_session", None):
        return g.auth_session.csrf_token
    if "anonymous_csrf" not in session:
        session["anonymous_csrf"] = secrets.token_urlsafe(32)
    return session["anonymous_csrf"]


def validate_csrf(value: str | None) -> bool:
    if not value:
        return False
    if getattr(g, "auth_session", None):
        return hmac.compare_digest(value, g.auth_session.csrf_token)
    expected = session.get("anonymous_csrf", "")
    return bool(expected) and hmac.compare_digest(value, expected)


def safe_next(value: str | None, default: str = "/") -> str:
    if not value:
        return default
    parsed = urlsplit(value)
    if parsed.scheme or parsed.netloc or not value.startswith("/") or value.startswith("//"):
        return default
    return value


def client_ip() -> str:
    return (request.remote_addr or "")[:64]


def rate_limited(
    action: str,
    subject: str,
    *,
    seconds: int,
    limit: int,
    failures_only: bool = False,
) -> bool:
    cutoff = utc_now() - timedelta(seconds=seconds)
    return _security_repository().rate_count(action, subject, cutoff, failures_only) >= limit


def record_rate_event(action: str, subject: str, succeeded: bool) -> None:
    _security_repository().add_rate_event(action, subject, succeeded)


def audit(action: str, *, target: User | None = None, details: dict | None = None) -> None:
    actor = getattr(g, "current_user", None)
    _security_repository().add_audit(
        actor.id if actor else None,
        target.id if target else None,
        action,
        client_ip() if request else "",
        details or {},
    )


def cleanup_expired() -> None:
    now = utc_now()
    now_epoch = int(now.timestamp())
    if current_app.config.get("ACCOUNTS_DATABASE_BACKEND") == "d1":
        _security_repository().cleanup_expired(now)
        return
    db.session.execute(
        delete(WebSession).where(
            (WebSession.absolute_expires_at <= now)
            | (
                (WebSession.revoked_at.is_not(None))
                & (WebSession.revoked_at < now - timedelta(days=7))
            )
        )
    )
    db.session.execute(
        delete(RateLimitEvent).where(RateLimitEvent.created_at < now - timedelta(days=2))
    )
    db.session.execute(
        delete(AuthorizationCode).where(AuthorizationCode.issued_at < now_epoch - 300)
    )
    db.session.execute(delete(OAuth2Token).where(OAuth2Token.issued_at < now_epoch - 86400))
    db.session.commit()
