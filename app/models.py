from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from datetime import UTC, datetime

from authlib.integrations.sqla_oauth2 import (
    OAuth2AuthorizationCodeMixin,
    OAuth2ClientMixin,
    OAuth2TokenMixin,
)
from sqlalchemy import Boolean, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .extensions import db


def utc_now() -> datetime:
    # SQLite drops timezone information. Store UTC as a consistently naive value.
    return datetime.now(UTC).replace(tzinfo=None)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(default=utc_now, onupdate=utc_now, nullable=False)


class User(TimestampMixin, db.Model):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    sub: Mapped[str] = mapped_column(
        String(36), unique=True, index=True, default=lambda: str(uuid.uuid4())
    )
    username: Mapped[str] = mapped_column(String(64), nullable=False)
    username_key: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(80), nullable=False)
    password_hash: Mapped[str | None] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_system_admin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    must_change_password: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    terms_accepted_at: Mapped[datetime | None]
    merged_into_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))

    aliases: Mapped[list[LoginAlias]] = relationship(
        back_populates="user", cascade="all, delete-orphan", foreign_keys="LoginAlias.user_id"
    )

    def get_user_id(self) -> str:
        return self.sub


class LoginAlias(TimestampMixin, db.Model):
    __tablename__ = "login_aliases"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    alias: Mapped[str] = mapped_column(String(64), nullable=False)
    alias_key: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="central")
    user: Mapped[User] = relationship(back_populates="aliases", foreign_keys=[user_id])


class LegacyCredential(TimestampMixin, db.Model):
    __tablename__ = "legacy_credentials"
    __table_args__ = (UniqueConstraint("source_app", "source_user_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    source_app: Mapped[str] = mapped_column(String(32), nullable=False)
    source_user_id: Mapped[str] = mapped_column(String(64), nullable=False)
    login_alias_key: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    algorithm: Mapped[str] = mapped_column(String(32), nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class WebSession(db.Model):
    __tablename__ = "web_sessions"

    sid: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    csrf_token: Mapped[str] = mapped_column(String(96), nullable=False)
    auth_time: Mapped[int] = mapped_column(
        Integer, nullable=False, default=lambda: int(time.time())
    )
    created_at: Mapped[datetime] = mapped_column(default=utc_now, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(default=utc_now, nullable=False)
    idle_expires_at: Mapped[datetime] = mapped_column(nullable=False)
    absolute_expires_at: Mapped[datetime] = mapped_column(nullable=False)
    revoked_at: Mapped[datetime | None]
    user: Mapped[User] = relationship()


class OAuth2Client(OAuth2ClientMixin, TimestampMixin, db.Model):
    __tablename__ = "oauth2_clients"
    __table_args__ = (UniqueConstraint("client_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    launch_uri: Mapped[str] = mapped_column(Text, nullable=False, default="")
    backchannel_logout_uri: Mapped[str] = mapped_column(Text, nullable=False, default="")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    def check_client_secret(self, client_secret: str) -> bool:
        expected = "sha256$" + hashlib.sha256(client_secret.encode("utf-8")).hexdigest()
        return hmac.compare_digest(self.client_secret or "", expected)

    def check_endpoint_auth_method(self, method: str, endpoint: str) -> bool:
        return self.is_active and super().check_endpoint_auth_method(method, endpoint)


class AuthorizationCode(OAuth2AuthorizationCodeMixin, db.Model):
    __tablename__ = "oauth2_authorization_codes"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    sid: Mapped[str] = mapped_column(String(36), nullable=False)
    user: Mapped[User] = relationship()


class OAuth2Token(OAuth2TokenMixin, db.Model):
    __tablename__ = "oauth2_tokens"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    sid: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    user: Mapped[User] = relationship()


class AppMembership(db.Model):
    __tablename__ = "user_app_memberships"
    __table_args__ = (UniqueConstraint("user_id", "client_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    client_id: Mapped[str] = mapped_column(String(48), index=True, nullable=False)
    first_authorized_at: Mapped[datetime] = mapped_column(default=utc_now, nullable=False)
    last_authorized_at: Mapped[datetime] = mapped_column(default=utc_now, nullable=False)
    user: Mapped[User] = relationship()


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    actor_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), index=True)
    target_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), index=True)
    action: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    ip_address: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    details_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    created_at: Mapped[datetime] = mapped_column(default=utc_now, index=True, nullable=False)

    @property
    def details(self) -> dict:
        try:
            return json.loads(self.details_json)
        except (TypeError, json.JSONDecodeError):
            return {}


class RateLimitEvent(db.Model):
    __tablename__ = "rate_limit_events"
    __table_args__ = (Index("idx_rate_limit_lookup", "action", "subject", "created_at"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    subject: Mapped[str] = mapped_column(String(192), nullable=False)
    succeeded: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(default=utc_now, nullable=False)


class BackchannelJob(db.Model):
    __tablename__ = "backchannel_jobs"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    client_id: Mapped[str] = mapped_column(String(48), index=True, nullable=False)
    sid: Mapped[str | None] = mapped_column(String(36))
    reason: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_error: Mapped[str] = mapped_column(Text, nullable=False, default="")
    next_attempt_at: Mapped[datetime] = mapped_column(default=utc_now, index=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(default=utc_now, nullable=False)
    delivered_at: Mapped[datetime | None]
