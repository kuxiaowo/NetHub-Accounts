from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import unicodedata
from datetime import timedelta
from urllib.parse import urlsplit

from flask import current_app, g, request, session
from pwdlib import PasswordHash
from sqlalchemy import delete, func, select
from werkzeug.security import check_password_hash as check_werkzeug_password

from .extensions import db
from .models import (
    AuditLog,
    AuthorizationCode,
    LegacyCredential,
    LoginAlias,
    OAuth2Token,
    RateLimitEvent,
    User,
    WebSession,
    utc_now,
)

PASSWORD_HASH = PasswordHash.recommended()
USERNAME_PATTERN = re.compile(r"^[\w.\-]{2,32}$", re.UNICODE)
SESSION_COOKIE = "nethub_session"


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
    alias = db.session.scalar(select(LoginAlias).where(LoginAlias.alias_key == key))
    if alias is None or not alias.user.is_active or alias.user.merged_into_user_id is not None:
        return None
    user = alias.user
    if user.password_hash:
        try:
            if PASSWORD_HASH.verify(password, user.password_hash):
                return user
        except Exception:  # An unknown/corrupt hash must behave like a failed login.
            return None
    legacy_items = db.session.scalars(
        select(LegacyCredential).where(
            LegacyCredential.user_id == user.id,
            LegacyCredential.login_alias_key == key,
            LegacyCredential.is_active.is_(True),
        )
    ).all()
    if any(verify_legacy_password(item, password) for item in legacy_items):
        user.password_hash = hash_password(password)
        for item in db.session.scalars(
            select(LegacyCredential).where(LegacyCredential.user_id == user.id)
        ):
            db.session.delete(item)
        audit("auth.legacy_password_upgraded", target=user)
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
        idle_expires_at=now + timedelta(seconds=current_app.config["SESSION_IDLE_SECONDS"]),
        absolute_expires_at=now + timedelta(seconds=current_app.config["SESSION_ABSOLUTE_SECONDS"]),
    )
    db.session.add(item)
    db.session.flush()
    return item, raw_token


def revoke_user_sessions(user_id: int) -> None:
    now = utc_now()
    for item in db.session.scalars(
        select(WebSession).where(WebSession.user_id == user_id, WebSession.revoked_at.is_(None))
    ):
        item.revoked_at = now


def revoke_user_oauth_tokens(user_id: int) -> None:
    now = int(utc_now().timestamp())
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
    item = db.session.scalar(select(WebSession).where(WebSession.token_hash == token_digest(raw)))
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
    query = select(func.count(RateLimitEvent.id)).where(
        RateLimitEvent.action == action,
        RateLimitEvent.subject == subject,
        RateLimitEvent.created_at >= cutoff,
    )
    if failures_only:
        query = query.where(RateLimitEvent.succeeded.is_(False))
    count = db.session.scalar(query)
    return int(count or 0) >= limit


def record_rate_event(action: str, subject: str, succeeded: bool) -> None:
    db.session.add(RateLimitEvent(action=action, subject=subject, succeeded=succeeded))


def audit(action: str, *, target: User | None = None, details: dict | None = None) -> None:
    actor = getattr(g, "current_user", None)
    db.session.add(
        AuditLog(
            actor_user_id=actor.id if actor else None,
            target_user_id=target.id if target else None,
            action=action,
            ip_address=client_ip() if request else "",
            details_json=json.dumps(details or {}, ensure_ascii=False, separators=(",", ":")),
        )
    )


def cleanup_expired() -> None:
    now = utc_now()
    now_epoch = int(now.timestamp())
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
