from __future__ import annotations

from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix

from .backchannel import start_worker
from .config import Settings
from .extensions import db
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
        BACKCHANNEL_TIMEOUT_SECONDS=3,
        BACKCHANNEL_POLL_SECONDS=30,
        BACKCHANNEL_WORKER_ENABLED=True,
        ACCOUNTS_HOST=settings.host,
        ACCOUNTS_PORT=settings.port,
    )
    if test_config:
        app.config.update(test_config)

    if settings.trusted_proxy_count:
        app.wsgi_app = ProxyFix(
            app.wsgi_app,
            x_for=settings.trusted_proxy_count,
            x_proto=settings.trusted_proxy_count,
            x_host=settings.trusted_proxy_count,
        )

    db.init_app(app)
    init_oauth(app)
    app.register_blueprint(web)
    app.before_request(load_request_user)

    @app.after_request
    def security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self'; img-src 'self' data:; form-action 'self'",
        )
        if response.content_type and "json" in response.content_type:
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    start_worker(app)
    return app
