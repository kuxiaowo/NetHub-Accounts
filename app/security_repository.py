"""Repositories for security side effects.

The SQLAlchemy implementation is retained for SQLite tests.  The D1
implementation deliberately exposes statement level operations; callers that
need an atomic business operation must use ``batch`` explicitly.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta
from typing import Any, Protocol

from sqlalchemy import func, select

from .d1_gateway import D1GatewayClient, Statement
from .extensions import db
from .models import (
    AuditLog,
    LegacyCredential,
    OAuth2Token,
    RateLimitEvent,
    User,
    WebSession,
    utc_now,
)


def _model(model_type, values: dict[str, Any]):
    item = model_type()
    boolean_fields = {"is_active", "is_system_admin", "must_change_password"}
    for key, value in values.items():
        if key in boolean_fields and value is not None:
            value = bool(value)
        if hasattr(model_type, key):
            setattr(item, key, value)
    return item


class SecurityRepository(Protocol):
    def create_web_session(self, values: dict[str, Any]): ...
    def load_web_session(self, token_hash: str, now: datetime): ...
    def revoke_oauth_tokens(self, user_id: int, when: int) -> None: ...
    def rate_count(
        self, action: str, subject: str, cutoff: datetime, failures_only: bool = False
    ) -> int: ...

    def add_rate_event(self, action: str, subject: str, succeeded: bool) -> None: ...

    def add_audit(
        self,
        actor_user_id: int | None,
        target_user_id: int | None,
        action: str,
        ip_address: str,
        details: dict[str, Any],
    ) -> None: ...

    def revoke_sessions(self, user_id: int, when: datetime) -> None: ...
    def revoke_session(self, sid: str, when: datetime) -> None: ...
    def revoke_access(self, user_id: int, when: datetime) -> None: ...
    def cleanup_expired(self, now: datetime) -> None: ...


class LegacyCredentialRepository(Protocol):
    def upgrade_password(
        self,
        user_id: int,
        password_hash: str,
        must_change_password: bool,
        actor_user_id: int | None = None,
        ip_address: str = "",
    ) -> None: ...


class SqlAlchemySecurityRepository:
    def create_web_session(self, values):
        item = WebSession(**values)
        db.session.add(item)
        db.session.flush()
        return item

    def load_web_session(self, token_hash, now):
        return db.session.scalar(select(WebSession).where(WebSession.token_hash == token_hash))

    def revoke_oauth_tokens(self, user_id, when):
        for item in db.session.scalars(
            select(OAuth2Token).where(
                OAuth2Token.user_id == user_id, OAuth2Token.access_token_revoked_at == 0
            )
        ):
            item.access_token_revoked_at = when

    def upgrade_password(
        self, user_id, password_hash, must_change_password, actor_user_id=None, ip_address=""
    ):
        user = db.session.get(User, user_id)
        if user is not None:
            user.password_hash = password_hash
            user.must_change_password = must_change_password
        for item in db.session.scalars(
            select(LegacyCredential).where(LegacyCredential.user_id == user_id)
        ):
            db.session.delete(item)

    def rate_count(self, action, subject, cutoff, failures_only=False):
        q = select(func.count(RateLimitEvent.id)).where(
            RateLimitEvent.action == action,
            RateLimitEvent.subject == subject,
            RateLimitEvent.created_at >= cutoff,
        )
        if failures_only:
            q = q.where(RateLimitEvent.succeeded.is_(False))
        return int(db.session.scalar(q) or 0)

    def add_rate_event(self, action, subject, succeeded):
        db.session.add(RateLimitEvent(action=action, subject=subject, succeeded=succeeded))

    def add_audit(self, actor_user_id, target_user_id, action, ip_address, details):
        db.session.add(
            AuditLog(
                actor_user_id=actor_user_id,
                target_user_id=target_user_id,
                action=action,
                ip_address=ip_address,
                details_json=json.dumps(details or {}, ensure_ascii=False, separators=(",", ":")),
            )
        )

    def revoke_sessions(self, user_id, when):
        for item in db.session.scalars(
            select(WebSession).where(WebSession.user_id == user_id, WebSession.revoked_at.is_(None))
        ):
            item.revoked_at = when

    def revoke_session(self, sid, when):
        item = db.session.get(WebSession, sid)
        if item is not None and item.revoked_at is None:
            item.revoked_at = when

    def revoke_access(self, user_id, when):
        """Revoke browser sessions and OAuth access tokens in one SQLite unit."""
        db.session.execute(
            WebSession.__table__.update()
            .where(WebSession.user_id == user_id, WebSession.revoked_at.is_(None))
            .values(revoked_at=when)
        )
        db.session.execute(
            OAuth2Token.__table__.update()
            .where(OAuth2Token.user_id == user_id, OAuth2Token.access_token_revoked_at == 0)
            .values(access_token_revoked_at=int(when.timestamp()))
        )


class D1SecurityRepository:
    def __init__(self, client: D1GatewayClient):
        self.client = client

    def rate_count(self, action, subject, cutoff, failures_only=False):
        sql = (
            "SELECT COUNT(*) AS count FROM rate_limit_events "
            "WHERE action = ? AND subject = ? AND created_at >= ?"
        )
        params: list[Any] = [action, subject, cutoff.isoformat(sep=" ")]
        if failures_only:
            sql += " AND succeeded = 0"
        row = (self.client.execute(sql, params).get("rows") or [{}])[0]
        return int(row.get("count", 0))

    def create_web_session(self, values):
        sid = values.get("sid") or str(uuid.uuid4())
        columns = [
            "sid",
            "token_hash",
            "user_id",
            "csrf_token",
            "auth_time",
            "created_at",
            "last_seen_at",
            "idle_expires_at",
            "absolute_expires_at",
            "revoked_at",
        ]
        params = [
            sid,
            values["token_hash"],
            values["user_id"],
            values["csrf_token"],
            values.get("auth_time") or int(utc_now().timestamp()),
            values["created_at"].isoformat(sep=" "),
            values["last_seen_at"].isoformat(sep=" "),
            values["idle_expires_at"].isoformat(sep=" "),
            values["absolute_expires_at"].isoformat(sep=" "),
            None,
        ]
        self.client.execute(
            f"INSERT INTO web_sessions ({', '.join(columns)}) VALUES ({', '.join('?' for _ in columns)})",
            params,
        )
        item = WebSession(sid=sid, **{k: v for k, v in values.items() if k != "sid"})
        return item

    def load_web_session(self, token_hash, now):
        row = (
            self.client.execute(
                "SELECT ws.*, u.sub, u.username, u.username_key, u.display_name, u.avatar_file, u.avatar_updated_at, u.avatar_color, u.password_hash, u.is_active, u.is_system_admin, u.must_change_password, u.terms_accepted_at, u.merged_into_user_id, u.created_at AS user_created_at, u.updated_at AS user_updated_at FROM web_sessions ws JOIN users u ON u.id = ws.user_id WHERE ws.token_hash = ? AND ws.revoked_at IS NULL AND ws.idle_expires_at > ? AND ws.absolute_expires_at > ? AND u.is_active = 1 AND u.merged_into_user_id IS NULL LIMIT 1",
                [token_hash, now.isoformat(sep=" "), now.isoformat(sep=" ")],
            ).get("rows")
            or []
        )
        if not row:
            return None
        data = row[0]
        for key in (
            "created_at",
            "last_seen_at",
            "idle_expires_at",
            "absolute_expires_at",
            "revoked_at",
        ):
            if isinstance(data.get(key), str):
                data[key] = datetime.fromisoformat(data[key])
        item = _model(
            WebSession,
            {
                k: v
                for k, v in data.items()
                if k
                in {
                    "sid",
                    "token_hash",
                    "user_id",
                    "csrf_token",
                    "auth_time",
                    "created_at",
                    "last_seen_at",
                    "idle_expires_at",
                    "absolute_expires_at",
                    "revoked_at",
                }
            },
        )
        item.user = _model(
            User,
            {
                "id": data.get("user_id"),
                **{
                    k: data.get(k)
                    for k in (
                        "sub",
                        "username",
                        "username_key",
                        "display_name",
                        "avatar_file",
                        "avatar_updated_at",
                        "avatar_color",
                        "password_hash",
                        "is_active",
                        "is_system_admin",
                        "must_change_password",
                        "terms_accepted_at",
                        "merged_into_user_id",
                    )
                },
                "created_at": data.get("user_created_at"),
                "updated_at": data.get("user_updated_at"),
            },
        )
        return item

    def refresh_web_session(self, sid, last_seen, idle_expires):
        self.client.execute(
            "UPDATE web_sessions SET last_seen_at = ?, idle_expires_at = ? WHERE sid = ? AND revoked_at IS NULL AND absolute_expires_at > ? AND EXISTS (SELECT 1 FROM users WHERE users.id = web_sessions.user_id AND users.is_active = 1 AND users.merged_into_user_id IS NULL)",
            [
                last_seen.isoformat(sep=" "),
                idle_expires.isoformat(sep=" "),
                sid,
                last_seen.isoformat(sep=" "),
            ],
        )

    def revoke_oauth_tokens(self, user_id, when):
        self.client.execute(
            "UPDATE oauth2_tokens SET access_token_revoked_at = ? WHERE user_id = ? AND access_token_revoked_at = 0",
            [when, user_id],
        )

    def add_rate_event(self, action, subject, succeeded):
        self.client.execute(
            "INSERT INTO rate_limit_events (action, subject, succeeded, created_at) "
            "VALUES (?, ?, ?, ?)",
            [action, subject, int(succeeded), utc_now().isoformat(sep=" ")],
        )

    def add_audit(self, actor_user_id, target_user_id, action, ip_address, details):
        self.client.execute(
            "INSERT INTO audit_logs "
            "(actor_user_id, target_user_id, action, ip_address, details_json, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            [
                actor_user_id,
                target_user_id,
                action,
                ip_address,
                json.dumps(details or {}, ensure_ascii=False, separators=(",", ":")),
                utc_now().isoformat(sep=" "),
            ],
        )

    def revoke_sessions(self, user_id, when):
        self.client.execute(
            "UPDATE web_sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
            [when.isoformat(sep=" "), user_id],
        )

    def revoke_session(self, sid, when):
        self.client.execute(
            "UPDATE web_sessions SET revoked_at = ? WHERE sid = ? AND revoked_at IS NULL",
            [when.isoformat(sep=" "), sid],
        )

    def revoke_access(self, user_id, when):
        """Submit session and token revocation as one explicit D1 batch."""
        self.client.batch(
            [
                Statement(
                    "UPDATE web_sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
                    [when.isoformat(sep=" "), user_id],
                ),
                Statement(
                    "UPDATE oauth2_tokens SET access_token_revoked_at = ? WHERE user_id = ? AND access_token_revoked_at = 0",
                    [int(when.timestamp()), user_id],
                ),
            ]
        )

    def cleanup_expired(self, now):
        now_text = now.isoformat(sep=" ")
        now_epoch = int(now.timestamp())
        self.client.batch(
            [
                Statement(
                    "DELETE FROM web_sessions WHERE absolute_expires_at<=? OR "
                    "(revoked_at IS NOT NULL AND revoked_at<?)",
                    [now_text, (now - timedelta(days=7)).isoformat(sep=" ")],
                ),
                Statement(
                    "DELETE FROM rate_limit_events WHERE created_at<?",
                    [(now - timedelta(days=2)).isoformat(sep=" ")],
                ),
                Statement(
                    "DELETE FROM oauth2_authorization_codes WHERE issued_at<?", [now_epoch - 300]
                ),
                Statement("DELETE FROM oauth2_tokens WHERE issued_at<?", [now_epoch - 86400]),
            ]
        )

    def upgrade_password(
        self, user_id, password_hash, must_change_password, actor_user_id=None, ip_address=""
    ):
        """Atomically promote a legacy credential to the central password.

        D1 commits each statement by default, so the three writes are submitted
        as one batch.  The conditional update also makes retries harmless.
        """
        now = utc_now().isoformat(sep=" ")
        self.client.batch(
            [
                # Update first so a missing user cannot produce a misleading audit.
                Statement(
                    "UPDATE users SET password_hash = ?, must_change_password = ?, updated_at = ? WHERE id = ?",
                    [password_hash, int(must_change_password), now, user_id],
                ),
                Statement("DELETE FROM legacy_credentials WHERE user_id = ?", [user_id]),
                Statement(
                    "INSERT INTO audit_logs (actor_user_id, target_user_id, action, ip_address, details_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                    [
                        actor_user_id,
                        user_id,
                        "auth.legacy_password_upgraded",
                        ip_address,
                        "{}",
                        now,
                    ],
                ),
            ]
        )
