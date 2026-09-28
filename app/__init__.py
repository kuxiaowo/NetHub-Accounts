from __future__ import annotations

from flask import Flask, g
from werkzeug.middleware.proxy_fix import ProxyFix

from .analytics import default_database_path
from .analytics_routes import traffic
from .avatar_gateway import AvatarGatewayClient
from .backchannel import start_worker
from .config import Settings
from .d1_gateway import D1GatewayClient
from .extensions import db
from .oauth_repository import init_oauth_repository
from .oidc import init_oauth, signing_key_id
from .routes import web
from .security import load_request_user


def create_app(test_config: dict | None = None) -> Flask:
    testing = bool(test_config and test_config.get("TESTING"))
    settings = Settings.from_env(testing=testing)
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.update(
        SECRET_KEY=settings.secret_key or "test-secret-key-that-is-at-least-thirty-two-bytes",
        SESSION_COOKIE_NAME="nethub_csrf",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=settings.cookie_secure,
        SQLALCHEMY_DATABASE_URI=settings.database_uri,
        ACCOUNTS_DATABASE_BACKEND=settings.database_backend,
        ACCOUNTS_D1_GATEWAY_URL=settings.d1_gateway_url,
        ACCOUNTS_D1_GATEWAY_SECRET=settings.d1_gateway_secret,
        ACCOUNTS_D1_GATEWAY_TIMEOUT=settings.d1_gateway_timeout,
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SQLALCHEMY_ENGINE_OPTIONS={
            "connect_args": {"timeout": 5, "check_same_thread": False}
            if settings.database_uri.startswith("sqlite")
            else {}
        },
        OIDC_ISSUER=settings.issuer,
        OIDC_SIGNING_KEY_PATH=settings.signing_key_path,
        OIDC_KEY_ID=signing_key_id(settings.signing_key_path),
        OAUTH2_SCOPES_SUPPORTED=["openid", "profile"],
        OAUTH2_REFRESH_TOKEN_GENERATOR=False,
        OAUTH2_TOKEN_EXPIRES_IN={"authorization_code": settings.token_expires_seconds},
        OAUTH_TOKEN_EXPIRES_SECONDS=settings.token_expires_seconds,
        REGISTRATION_ENABLED=settings.registration_enabled,
        SESSION_IDLE_SECONDS=settings.session_idle_seconds,
        SESSION_ABSOLUTE_SECONDS=settings.session_absolute_seconds,
        LOGIN_LIMIT_PER_15_MINUTES=settings.login_limit_per_15_minutes,
        REGISTER_LIMIT_PER_DAY=settings.register_limit_per_day,
        AVATAR_UPLOAD_DIR=settings.avatar_upload_dir,
        AVATAR_UPLOAD_MAX_BYTES=settings.avatar_upload_max_bytes,
        AVATAR_SIZE_PX=settings.avatar_size_px,
        AVATAR_MAX_STORED_BYTES=settings.avatar_max_stored_bytes,
        AVATAR_WEBP_QUALITY=settings.avatar_webp_quality,
        AVATAR_STORAGE_BACKEND=settings.avatar_storage_backend,
        AVATAR_R2_GATEWAY_URL=settings.avatar_r2_gateway_url,
        AVATAR_R2_HMAC_SECRET=settings.avatar_r2_hmac_secret,
        AVATAR_R2_TIMEOUT=settings.avatar_r2_timeout,
        BACKCHANNEL_TIMEOUT_SECONDS=3,
        BACKCHANNEL_POLL_SECONDS=30,
        BACKCHANNEL_WORKER_ENABLED=True,
        ACCOUNTS_HOST=settings.host,
        ACCOUNTS_PORT=settings.port,
        ACCOUNTS_ANALYTICS_DB=default_database_path(),
        TURNSTILE_SITE_KEY=settings.turnstile_site_key,
        TURNSTILE_SECRET_KEY=settings.turnstile_secret_key,
        TURNSTILE_HOSTNAME="auth.nethub.wiki",
    )
    if test_config:
        app.config.update(test_config)

    if app.config["AVATAR_STORAGE_BACKEND"] == "r2":
        app.extensions["avatar_gateway_client"] = AvatarGatewayClient(
            app.config["AVATAR_R2_GATEWAY_URL"],
            app.config["AVATAR_R2_HMAC_SECRET"],
            timeout=app.config["AVATAR_R2_TIMEOUT"],
        )

    if app.config.get("ACCOUNTS_DATABASE_BACKEND") == "d1":
        # Flask-SQLAlchemy remains registered because Authlib and the model
        # classes use its metadata.  Point it at a non-persistent placeholder
        # so an accidental ORM access cannot create or read a local database.
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
        app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
            "connect_args": {"check_same_thread": False}
        }
        app.extensions["d1_gateway_client"] = D1GatewayClient(
            app.config["ACCOUNTS_D1_GATEWAY_URL"],
            app.config["ACCOUNTS_D1_GATEWAY_SECRET"],
            timeout=app.config["ACCOUNTS_D1_GATEWAY_TIMEOUT"],
        )

    if settings.trusted_proxy_count:
        app.wsgi_app = ProxyFix(
            app.wsgi_app,
            x_for=settings.trusted_proxy_count,
            x_proto=settings.trusted_proxy_count,
            x_host=settings.trusted_proxy_count,
        )

    db.init_app(app)
    init_oauth_repository(app)
    init_oauth(app)
    app.register_blueprint(web)
    app.before_request(load_request_user)
    app.register_blueprint(traffic)

    @app.after_request
    def security_headers(response):
        user = getattr(g, "current_user", None)
        if user is not None and getattr(user, "sub", None):
            response.headers["X-Nethub-User-Sub"] = user.sub
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self'; "
            "script-src 'self' https://challenges.cloudflare.com; "
            "frame-src https://challenges.cloudflare.com; "
            "connect-src 'self' https://challenges.cloudflare.com; "
            "img-src 'self' data: https://wiki-media.nethub.wiki; form-action 'self'",
        )
        if response.content_type and "json" in response.content_type:
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    start_worker(app)
    return app
