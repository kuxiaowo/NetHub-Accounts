from __future__ import annotations

import base64
import hashlib
import secrets
import time
from urllib.parse import parse_qs, urlsplit

import pytest
from authlib.oidc.core import CodeIDToken
from joserfc import jwt
from joserfc.jwk import import_key
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.models import AppMembership, AuthorizationCode, OAuth2Client, WebSession
from tests.conftest import client_secret_hash, create_user, csrf_from
from tests.test_accounts import login

CLIENT_ID = "test-client"
CLIENT_SECRET = "test-client-secret-with-sufficient-entropy"
REDIRECT_URI = "https://client.test/auth/callback"


def add_oauth_client(
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    redirect_uri=REDIRECT_URI,
):
    item = OAuth2Client(
        client_id=client_id,
        client_secret=client_secret_hash(client_secret),
        client_id_issued_at=1,
        client_secret_expires_at=0,
        launch_uri=redirect_uri.rsplit("/", 2)[0] + "/",
        backchannel_logout_uri="",
        is_active=True,
    )
    item.set_client_metadata(
        {
            "client_name": "Test Client",
            "redirect_uris": [redirect_uri],
            "scope": "openid profile",
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_basic",
            "id_token_signed_response_alg": "RS256",
        }
    )
    db.session.add(item)
    db.session.commit()


def test_client_id_is_unique(app):
    with app.app_context():
        add_oauth_client()
        duplicate = OAuth2Client(
            client_id=CLIENT_ID,
            client_secret=client_secret_hash("different-client-secret-with-enough-entropy"),
            client_id_issued_at=2,
            client_secret_expires_at=0,
            launch_uri="https://other.test/",
            backchannel_logout_uri="",
            is_active=True,
        )
        duplicate.set_client_metadata(
            {
                "client_name": "Duplicate",
                "redirect_uris": ["https://other.test/auth/callback"],
                "scope": "openid profile",
                "response_types": ["code"],
                "grant_types": ["authorization_code"],
                "token_endpoint_auth_method": "client_secret_basic",
            }
        )
        db.session.add(duplicate)
        with pytest.raises(IntegrityError):
            db.session.commit()
        db.session.rollback()


def pkce_pair():
    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    return verifier, challenge


def authorize(client, challenge: str, *, redirect_uri=REDIRECT_URI, client_id=CLIENT_ID):
    return client.get(
        "/oauth/authorize",
        query_string={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": "openid profile",
            "state": "state-123",
            "nonce": "nonce-123",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
    )


def exchange(
    client,
    code: str,
    verifier: str,
    *,
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    redirect_uri=REDIRECT_URI,
):
    basic = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    return client.post(
        "/oauth/token",
        headers={"Authorization": f"Basic {basic}"},
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
        },
    )


def test_silent_authorization_returns_login_required_without_central_session(app, client):
    with app.app_context():
        add_oauth_client()
    _, challenge = pkce_pair()

    response = client.get(
        "/oauth/authorize",
        query_string={
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "scope": "openid profile",
            "state": "silent-state",
            "nonce": "silent-nonce",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "prompt": "none",
        },
    )

    query = parse_qs(urlsplit(response.location).query)
    assert response.status_code == 302
    assert response.location.startswith(REDIRECT_URI)
    assert query["error"] == ["login_required"]
    assert query["state"] == ["silent-state"]


def test_signup_hint_opens_registration_and_preserves_authorization(app, client):
    with app.app_context():
        add_oauth_client()
    _, challenge = pkce_pair()

    response = client.get(
        "/oauth/authorize",
        query_string={
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "scope": "openid profile",
            "state": "signup-state",
            "nonce": "signup-nonce",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "screen_hint": "signup",
        },
    )

    assert response.status_code == 302
    assert urlsplit(response.location).path == "/register"
    assert parse_qs(urlsplit(response.location).query)["next"][0].startswith("/oauth/authorize?")


def test_discovery_and_jwks(client):
    discovery = client.get("/.well-known/openid-configuration").get_json()
    assert discovery["issuer"] == "https://accounts.test"
    assert discovery["code_challenge_methods_supported"] == ["S256"]
    assert "picture" in discovery["claims_supported"]
    keys = client.get("/.well-known/jwks.json").get_json()["keys"]
    assert keys[0]["alg"] == "RS256"
    assert "d" not in keys[0]


def test_authorization_code_pkce_and_userinfo(app, client):
    with app.app_context():
        user = create_user()
        add_oauth_client()
        user_id = user.id
    login(client)
    verifier, challenge = pkce_pair()
    response = authorize(client, challenge)
    assert response.status_code == 302
    query = parse_qs(urlsplit(response.location).query)
    assert query["state"] == ["state-123"]
    token_response = exchange(client, query["code"][0], verifier)
    assert token_response.status_code == 200, token_response.get_data(as_text=True)
    token = token_response.get_json()
    assert token["expires_in"] == 300
    with app.app_context():
        key = import_key(app.config["OIDC_SIGNING_KEY_PATH"].read_bytes(), "RSA")
        decoded = jwt.decode(token["id_token"], key)
        claims = CodeIDToken(decoded.claims, decoded.header)
        claims.validate()
        assert claims["iss"] == "https://accounts.test"
        assert CLIENT_ID in claims["aud"]
        assert claims["sub"]
        assert claims["preferred_username"] == "alice"
        assert claims["picture"] == f"https://accounts.test/avatars/{claims['sub']}"
        assert claims["nonce"] == "nonce-123"
        assert claims["sid"]
        assert db.session.scalar(
            select(AppMembership).where(
                AppMembership.user_id == user_id, AppMembership.client_id == CLIENT_ID
            )
        )
    userinfo = client.get(
        "/oauth/userinfo", headers={"Authorization": f"Bearer {token['access_token']}"}
    )
    assert userinfo.status_code == 200
    assert userinfo.get_json()["preferred_username"] == "alice"
    assert userinfo.get_json()["picture"] == f"https://accounts.test/avatars/{userinfo.get_json()['sub']}"
    assert exchange(client, query["code"][0], verifier).status_code == 400


def test_new_code_remains_valid_when_central_login_is_older_than_five_minutes(app, client):
    with app.app_context():
        create_user()
        add_oauth_client()
    login(client)
    original_auth_time = int(time.time()) - 3600
    with app.app_context():
        session = db.session.scalar(select(WebSession))
        session.auth_time = original_auth_time
        db.session.commit()

    verifier, challenge = pkce_pair()
    response = authorize(client, challenge)
    code = parse_qs(urlsplit(response.location).query)["code"][0]
    token_response = exchange(client, code, verifier)

    assert token_response.status_code == 200, token_response.get_data(as_text=True)
    with app.app_context():
        key = import_key(app.config["OIDC_SIGNING_KEY_PATH"].read_bytes(), "RSA")
        decoded = jwt.decode(token_response.get_json()["id_token"], key)
        assert decoded.claims["auth_time"] == original_auth_time


def test_authorization_code_expires_from_its_own_issuance_time(app, client):
    with app.app_context():
        create_user()
        add_oauth_client()
    login(client)
    verifier, challenge = pkce_pair()
    response = authorize(client, challenge)
    code = parse_qs(urlsplit(response.location).query)["code"][0]
    with app.app_context():
        authorization_code = db.session.scalar(select(AuthorizationCode))
        authorization_code.issued_at = int(time.time()) - 301
        db.session.commit()

    assert exchange(client, code, verifier).status_code == 400


def test_pkce_is_required_for_confidential_client(app, client):
    with app.app_context():
        create_user()
        add_oauth_client()
    login(client)
    response = client.get(
        "/oauth/authorize",
        query_string={
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "scope": "openid profile",
            "state": "state",
            "nonce": "nonce",
        },
    )
    assert response.status_code == 302
    assert "error=invalid_request" in response.location


def test_redirect_uri_must_match_exactly(app, client):
    with app.app_context():
        create_user()
        add_oauth_client()
    login(client)
    _, challenge = pkce_pair()
    response = authorize(client, challenge, redirect_uri="https://evil.test/callback")
    assert response.status_code == 400


def test_one_central_session_authorizes_two_apps(app, client):
    second_id = "second-client"
    second_secret = "second-client-secret-with-sufficient-entropy"
    second_redirect = "https://second.test/auth/callback"
    with app.app_context():
        create_user()
        add_oauth_client()
        add_oauth_client(second_id, second_secret, second_redirect)
    assert login(client).status_code == 302
    verifier_one, challenge_one = pkce_pair()
    first_response = authorize(client, challenge_one)
    first_code = parse_qs(urlsplit(first_response.location).query)["code"][0]
    assert exchange(client, first_code, verifier_one).status_code == 200

    verifier_two, challenge_two = pkce_pair()
    second_response = authorize(
        client,
        challenge_two,
        redirect_uri=second_redirect,
        client_id=second_id,
    )
    assert second_response.status_code == 302
    second_code = parse_qs(urlsplit(second_response.location).query)["code"][0]
    assert (
        exchange(
            client,
            second_code,
            verifier_two,
            client_id=second_id,
            client_secret=second_secret,
            redirect_uri=second_redirect,
        ).status_code
        == 200
    )
    with app.app_context():
        assert set(db.session.scalars(select(AppMembership.client_id)).all()) == {
            CLIENT_ID,
            second_id,
        }


def test_revocation_invalidates_access_token(app, client):
    with app.app_context():
        create_user()
        add_oauth_client()
    login(client)
    verifier, challenge = pkce_pair()
    response = authorize(client, challenge)
    code = parse_qs(urlsplit(response.location).query)["code"][0]
    token = exchange(client, code, verifier).get_json()
    basic = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
    revoked = client.post(
        "/oauth/revoke",
        headers={"Authorization": f"Basic {basic}"},
        data={"token": token["access_token"], "token_type_hint": "access_token"},
    )
    assert revoked.status_code == 200
    assert (
        client.get(
            "/oauth/userinfo",
            headers={"Authorization": f"Bearer {token['access_token']}"},
        ).status_code
        == 401
    )


def test_admin_disable_immediately_revokes_user_access_tokens(app, client):
    with app.app_context():
        target = create_user()
        target_id = target.id
        create_user("admin", admin=True)
        add_oauth_client()
    target_browser = app.test_client()
    login(target_browser)
    verifier, challenge = pkce_pair()
    response = authorize(target_browser, challenge)
    code = parse_qs(urlsplit(response.location).query)["code"][0]
    token = exchange(target_browser, code, verifier).get_json()

    login(client, "admin")
    admin_page = client.get("/admin")
    response = client.post(
        f"/admin/users/{target_id}/toggle",
        data={"csrf_token": csrf_from(admin_page)},
    )
    assert response.status_code == 302
    assert (
        target_browser.get(
            "/oauth/userinfo",
            headers={"Authorization": f"Bearer {token['access_token']}"},
        ).status_code
        == 401
    )
