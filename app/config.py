from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")


def _bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int, minimum: int = 0) -> int:
    raw = os.getenv(name)
    value = default if raw is None else int(raw)
    if value < minimum:
        raise RuntimeError(f"{name} must be at least {minimum}")
    return value


def _database_uri(raw: str) -> str:
    if raw.startswith("sqlite:///"):
        database_path = Path(raw.removeprefix("sqlite:///"))
        if not database_path.is_absolute():
            database_path = PROJECT_ROOT / database_path
        database_path.parent.mkdir(parents=True, exist_ok=True)
        return f"sqlite:///{database_path.as_posix()}"
    return raw


@dataclass(frozen=True)
class Settings:
    host: str
    port: int
    issuer: str
    database_uri: str
    secret_key: str
    signing_key_path: Path
    registration_enabled: bool
    cookie_secure: bool
    trusted_proxy_count: int
    session_idle_seconds: int
    session_absolute_seconds: int
    token_expires_seconds: int
    login_limit_per_15_minutes: int
    register_limit_per_day: int

    @classmethod
    def from_env(cls, *, testing: bool = False) -> Settings:
        raw_database = os.getenv("DATABASE_URL", "sqlite:///data/accounts.sqlite3")
        key_path = Path(os.getenv("OIDC_SIGNING_KEY_PATH", "data/oidc-rs256.pem"))
        if not key_path.is_absolute():
            key_path = PROJECT_ROOT / key_path
        settings = cls(
            host=os.getenv("ACCOUNTS_HOST", "127.0.0.1").strip(),
            port=_int("ACCOUNTS_PORT", 3400, 1),
            issuer=os.getenv("ACCOUNTS_ISSUER", "https://auth.nethub.wiki").rstrip("/"),
            database_uri=_database_uri(raw_database),
            secret_key=os.getenv("ACCOUNTS_SECRET_KEY", "").strip(),
            signing_key_path=key_path,
            registration_enabled=_bool("REGISTRATION_ENABLED", False),
            cookie_secure=_bool("SESSION_COOKIE_SECURE", True),
            trusted_proxy_count=_int("TRUSTED_PROXY_COUNT", 1, 0),
            session_idle_seconds=_int("SESSION_IDLE_SECONDS", 7 * 86400, 300),
            session_absolute_seconds=_int("SESSION_ABSOLUTE_SECONDS", 30 * 86400, 3600),
            token_expires_seconds=_int("OAUTH_TOKEN_EXPIRES_SECONDS", 300, 60),
            login_limit_per_15_minutes=_int("LOGIN_LIMIT_PER_15_MINUTES", 20, 1),
            register_limit_per_day=_int("REGISTER_LIMIT_PER_DAY", 10, 1),
        )
        if testing:
            return settings
        if not settings.host:
            raise RuntimeError("ACCOUNTS_HOST cannot be empty")
        if not settings.issuer.startswith("https://"):
            raise RuntimeError("ACCOUNTS_ISSUER must use https://")
        if len(settings.secret_key.encode("utf-8")) < 32:
            raise RuntimeError("ACCOUNTS_SECRET_KEY must contain at least 32 bytes")
        if not settings.signing_key_path.is_file():
            raise RuntimeError(f"OIDC signing key does not exist: {settings.signing_key_path}")
        return settings
