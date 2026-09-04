from __future__ import annotations

import hashlib
import re
import secrets

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app import create_app
from app.extensions import db
from app.models import LoginAlias, User
from app.security import hash_password, normalize_username


@pytest.fixture()
def app(tmp_path, monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_path = tmp_path / "oidc.pem"
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    monkeypatch.setenv("ACCOUNTS_SECRET_KEY", secrets.token_urlsafe(48))
    monkeypatch.setenv("OIDC_SIGNING_KEY_PATH", str(key_path))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'test.sqlite3').as_posix()}")
    monkeypatch.setenv("ACCOUNTS_ISSUER", "https://accounts.test")
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "false")
    monkeypatch.setenv("REGISTRATION_ENABLED", "true")
    application = create_app(
        {
            "TESTING": True,
            "BACKCHANNEL_WORKER_ENABLED": False,
            "SESSION_COOKIE_SECURE": False,
            "REGISTRATION_ENABLED": True,
        }
    )
    with application.app_context():
        db.create_all()
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


def csrf_from(response) -> str:
    match = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
    assert match
    return match.group(1).decode()


def create_user(username="alice", password="password-123", *, admin=False):
    normalized, key = normalize_username(username)
    user = User(
        username=normalized,
        username_key=key,
        display_name=normalized.title(),
        password_hash=hash_password(password),
        is_system_admin=admin,
        is_active=True,
    )
    db.session.add(user)
    db.session.flush()
    db.session.add(LoginAlias(user_id=user.id, alias=normalized, alias_key=key, source="central"))
    db.session.commit()
    return user


def client_secret_hash(secret: str) -> str:
    return "sha256$" + hashlib.sha256(secret.encode()).hexdigest()
