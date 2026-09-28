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
    database_backend: str
    d1_gateway_url: str
    d1_gateway_secret: str
    d1_gateway_timeout: float
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
    avatar_upload_dir: Path
    avatar_upload_max_bytes: int
    avatar_size_px: int
    avatar_max_stored_bytes: int
    avatar_webp_quality: int
    avatar_storage_backend: str
    avatar_r2_gateway_url: str
    avatar_r2_hmac_secret: str
    avatar_r2_timeout: float
    turnstile_site_key: str
    turnstile_secret_key: str

    @classmethod
    def from_env(cls, *, testing: bool = False) -> Settings:
        database_backend = (
            os.getenv("ACCOUNTS_DATABASE_BACKEND", "sqlite" if testing else "d1").strip().casefold()
        )
        raw_database = os.getenv("DATABASE_URL", "sqlite:///data/accounts.sqlite3")
        key_path = Path(os.getenv("OIDC_SIGNING_KEY_PATH", "data/oidc-rs256.pem"))
        if not key_path.is_absolute():
            key_path = PROJECT_ROOT / key_path
        avatar_dir = Path(os.getenv("AVATAR_UPLOAD_DIR", "data/uploads/avatars"))
        if not avatar_dir.is_absolute():
            avatar_dir = PROJECT_ROOT / avatar_dir
        settings = cls(
            host=os.getenv("ACCOUNTS_HOST", "127.0.0.1").strip(),
            port=_int("ACCOUNTS_PORT", 3400, 1),
            issuer=os.getenv("ACCOUNTS_ISSUER", "https://auth.nethub.wiki").rstrip("/"),
            database_uri=(
                _database_uri(raw_database)
                if database_backend == "sqlite"
                else "sqlite:///:memory:"
            ),
            database_backend=database_backend,
            d1_gateway_url=os.getenv("ACCOUNTS_D1_GATEWAY_URL", "").strip(),
            d1_gateway_secret=os.getenv("ACCOUNTS_D1_GATEWAY_SECRET", "").strip(),
            d1_gateway_timeout=float(os.getenv("ACCOUNTS_D1_GATEWAY_TIMEOUT", "10")),
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
            avatar_upload_dir=avatar_dir,
            avatar_upload_max_bytes=_int("AVATAR_UPLOAD_MAX_MB", 5, 1) * 1024 * 1024,
            avatar_size_px=_int("AVATAR_SIZE_PX", 512, 64),
            avatar_max_stored_bytes=_int("AVATAR_MAX_STORED_KB", 256, 32) * 1024,
            avatar_webp_quality=_int("AVATAR_WEBP_QUALITY", 85, 40),
            avatar_storage_backend=(
                "local" if testing else os.getenv("AVATAR_STORAGE_BACKEND", "r2").strip().casefold()
            ),
            avatar_r2_gateway_url=os.getenv(
                "AVATAR_R2_GATEWAY_URL", "https://wiki-media.nethub.wiki"
            )
            .strip()
            .rstrip("/"),
            avatar_r2_hmac_secret=os.getenv("AVATAR_R2_HMAC_SECRET", "").strip(),
            avatar_r2_timeout=float(os.getenv("AVATAR_R2_TIMEOUT", "10")),
            turnstile_site_key=os.getenv("TURNSTILE_SITE_KEY", "").strip(),
            turnstile_secret_key=os.getenv("TURNSTILE_SECRET_KEY", "").strip(),
        )
        if testing:
            return settings
        if not settings.host:
            raise RuntimeError("ACCOUNTS_HOST cannot be empty")
        if not settings.issuer.startswith("https://"):
            raise RuntimeError("ACCOUNTS_ISSUER must use https://")
        if settings.database_backend not in {"sqlite", "d1"}:
            raise RuntimeError("ACCOUNTS_DATABASE_BACKEND must be sqlite or d1")
        if settings.database_backend == "d1" and (
            not settings.d1_gateway_url or not settings.d1_gateway_secret
        ):
            raise RuntimeError(
                "D1 backend requires ACCOUNTS_D1_GATEWAY_URL and ACCOUNTS_D1_GATEWAY_SECRET"
            )
        if settings.avatar_storage_backend not in {"local", "r2"}:
            raise RuntimeError("AVATAR_STORAGE_BACKEND must be local or r2")
        if settings.avatar_storage_backend == "r2" and (
            not settings.avatar_r2_gateway_url.startswith("https://")
            or len(settings.avatar_r2_hmac_secret.encode("utf-8")) < 32
        ):
            raise RuntimeError(
                "R2 avatar storage requires HTTPS AVATAR_R2_GATEWAY_URL "
                "and a 32-byte AVATAR_R2_HMAC_SECRET"
            )
        if settings.avatar_r2_timeout <= 0:
            raise RuntimeError("AVATAR_R2_TIMEOUT must be positive")
        if not settings.turnstile_site_key or not settings.turnstile_secret_key:
            raise RuntimeError("TURNSTILE_SITE_KEY and TURNSTILE_SECRET_KEY are required")
        if len(settings.secret_key.encode("utf-8")) < 32:
            raise RuntimeError("ACCOUNTS_SECRET_KEY must contain at least 32 bytes")
        if not settings.signing_key_path.is_file():
            raise RuntimeError(f"OIDC signing key does not exist: {settings.signing_key_path}")
        return settings
