"""Run the real UI against disposable synthetic data on 127.0.0.1 only.

Usage: python scripts/preview_ui.py --port 8793
Open /preview/sign-in to inspect an unverified account, or add ?user=verified.
No production configuration, credentials, database or email provider is used.
"""

from __future__ import annotations

import argparse
import os
import secrets
import sys
import tempfile
from datetime import timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8793)
    args = parser.parse_args()
    temporary = tempfile.TemporaryDirectory(prefix="nethub-ui-")
    directory = Path(temporary.name)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_path = directory / "preview.pem"
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    os.environ.update(
        {
            "PYTHON_DOTENV_DISABLED": "1",
            "ACCOUNTS_SECRET_KEY": secrets.token_urlsafe(48),
            "DATABASE_URL": "sqlite:///" + (directory / "preview.sqlite3").as_posix(),
            "OIDC_SIGNING_KEY_PATH": str(key_path),
            "ACCOUNTS_DATABASE_BACKEND": "sqlite",
            "ACCOUNTS_ISSUER": f"http://127.0.0.1:{args.port}",
            "SESSION_COOKIE_SECURE": "false",
            "REGISTRATION_ENABLED": "true",
            "RESEND_API_KEY": "",
            "MAIL_FROM": "",
            "TURNSTILE_SITE_KEY": "",
            "TURNSTILE_SECRET_KEY": "",
            "TRUSTED_PROXY_COUNT": "0",
        }
    )
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from flask import abort, redirect, request

    import app.routes
    from app import create_app
    from app.extensions import db
    from app.models import LoginAlias, OAuth2Client, User, utc_now
    from app.security import create_web_session, hash_password, set_session_cookie

    application = create_app(
        {
            "TESTING": True,
            "BACKCHANNEL_WORKER_ENABLED": False,
            "TEMPLATES_AUTO_RELOAD": True,
            "SESSION_COOKIE_SECURE": False,
            "REGISTRATION_ENABLED": True,
            "AVATAR_UPLOAD_DIR": directory / "avatars",
            "ACCOUNTS_ANALYTICS_DB": directory / "analytics.sqlite3",
            "RESEND_API_KEY": "",
            "MAIL_FROM": "",
            "TURNSTILE_SITE_KEY": "",
            "TURNSTILE_SECRET_KEY": "",
        }
    )
    # The preview has no CAPTCHA service and only disposable sample accounts.
    app.routes.verify_turnstile = lambda action: True
    with application.app_context():
        db.create_all()
        for name, verified in (("demo", False), ("verified", True)):
            user = User(
                username=name,
                username_key=name,
                display_name="Alex Lin",
                password_hash=hash_password("preview-password"),
                is_active=True,
                email=f"{name}@example.test",
            )
            if verified:
                user.email_verified_at = user.first_email_verified_at = utc_now() - timedelta(
                    days=5
                )
            db.session.add(user)
            db.session.flush()
            db.session.add(
                LoginAlias(user_id=user.id, alias=name, alias_key=name, source="central")
            )
        for identifier, name in (
            ("todo", "TodoList"),
            ("techx", "TechX"),
            ("campus-wiki", "Campus Wiki"),
            ("cas", "Codex Notes"),
        ):
            client = OAuth2Client(
                client_id=identifier,
                client_secret="preview-only",
                client_id_issued_at=1,
                client_secret_expires_at=0,
                launch_uri="/account",
                is_active=True,
            )
            client.set_client_metadata(
                {
                    "client_name": name,
                    "redirect_uris": [f"http://127.0.0.1:{args.port}/"],
                    "scope": "openid profile",
                    "grant_types": ["authorization_code"],
                    "response_types": ["code"],
                    "token_endpoint_auth_method": "client_secret_basic",
                }
            )
            db.session.add(client)
        db.session.commit()

    @application.get("/preview/sign-in")
    def preview_sign_in():
        name = request.args.get("user", "demo")
        if name not in {"demo", "verified"}:
            abort(404)
        user = db.session.scalar(db.select(User).where(User.username == name))
        _, token = create_web_session(user)
        db.session.commit()
        response = redirect("/account/community")
        set_session_cookie(response, token)
        return response

    @application.get("/preview/phone")
    def phone():
        path = request.args.get("page", "/account/community")
        if path not in {"/", "/login", "/register", "/account", "/account/community"}:
            abort(404)
        return (
            '<!doctype html><title>390px preview</title>'
            '<link rel="stylesheet" href="/preview/phone.css">'
            '<iframe title="Phone preview" src="'
            + path
            + '"></iframe>'
        )

    @application.get("/preview/phone.css")
    def phone_css():
        return (
            "body{margin:0;padding:20px;background:#e3e7ed;display:flex;justify-content:center}"
            "iframe{width:390px;height:950px;border:1px solid #a0a8b5;background:#fff}",
            200,
            {"Content-Type": "text/css"},
        )

    @application.after_request
    def preview_headers(response):
        # SAMEORIGIN is scoped to this isolated preview executable, never the app.
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self'; "
            "script-src 'self' https://challenges.cloudflare.com; "
            "frame-src 'self' https://challenges.cloudflare.com; "
            "connect-src 'self' https://challenges.cloudflare.com; "
            "img-src 'self' data:; form-action 'self'; frame-ancestors 'self'"
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    print(f"Synthetic UI preview: http://127.0.0.1:{args.port}/preview/sign-in", flush=True)
    application.run(host="127.0.0.1", port=args.port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
