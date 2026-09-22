from __future__ import annotations

import hashlib
import threading
import time
from collections import OrderedDict
from pathlib import Path

from authlib.integrations.flask_oauth2 import ResourceProtector, current_token
from authlib.oauth2.rfc6749.grants import AuthorizationCodeGrant
from authlib.oauth2.rfc7009 import RevocationEndpoint
from authlib.oauth2.rfc7636 import CodeChallenge
from authlib.oidc.core import UserInfo
from authlib.oidc.core.grants import OpenIDCode
from flask import current_app
from joserfc.jwk import import_key
from sqlalchemy import select

from .avatars import avatar_url
from .extensions import authorization, db
from .models import AppMembership, AuthorizationCode, OAuth2Client, OAuth2Token, User, utc_now
from .security import token_digest

_SIGNING_KEY_CACHE_MAX_ENTRIES = 8
_SIGNING_KEY_CACHE: OrderedDict[Path, tuple[tuple[int, int, int, int, int], object, str]] = (
    OrderedDict()
)
_SIGNING_KEY_CACHE_LOCK = threading.Lock()


def _key_file_fingerprint(path: Path) -> tuple[int, int, int, int, int]:
    stat = path.stat()
    return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)


def _read_stable_key_file(path: Path) -> tuple[bytes, tuple[int, int, int, int, int]]:
    """Read a key whose metadata stays unchanged for the duration of the read."""
    for _attempt in range(3):
        before = _key_file_fingerprint(path)
        pem = path.read_bytes()
        after = _key_file_fingerprint(path)
        if before == after:
            return pem, after
    raise RuntimeError(f"OIDC signing key changed repeatedly while being read: {path}")


def get_signing_key(path: Path | None = None):
    """Return a parsed signing key, reloading it after an atomic key rotation."""
    key_path = Path(path or current_app.config["OIDC_SIGNING_KEY_PATH"]).resolve()
    with _SIGNING_KEY_CACHE_LOCK:
        fingerprint = _key_file_fingerprint(key_path)
        cached = _SIGNING_KEY_CACHE.get(key_path)
        if cached and cached[0] == fingerprint:
            _SIGNING_KEY_CACHE.move_to_end(key_path)
            return cached[1], cached[2]

        pem, current_fingerprint = _read_stable_key_file(key_path)
        parsed_key = import_key(pem, "RSA")
        key_id = hashlib.sha256(parsed_key.thumbprint().encode("ascii")).hexdigest()[:16]
        key = import_key(pem, "RSA", {"kid": key_id})
        _SIGNING_KEY_CACHE[key_path] = (current_fingerprint, key, key_id)
        _SIGNING_KEY_CACHE.move_to_end(key_path)
        while len(_SIGNING_KEY_CACHE) > _SIGNING_KEY_CACHE_MAX_ENTRIES:
            _SIGNING_KEY_CACHE.popitem(last=False)
        return key, key_id


class RequiredS256CodeChallenge(CodeChallenge):
    def validate_code_challenge(self, grant, redirect_uri):
        super().validate_code_challenge(grant, redirect_uri)
        challenge = grant.request.payload.data.get("code_challenge")
        method = grant.request.payload.data.get("code_challenge_method")
        if not challenge:
            from authlib.oauth2 import OAuth2Error

            raise OAuth2Error(error="invalid_request", description="PKCE is required")
        if method != "S256":
            from authlib.oauth2 import OAuth2Error

            raise OAuth2Error(error="invalid_request", description="Only PKCE S256 is supported")


class AuthorizationCodeGrantImpl(AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic"]

    def save_authorization_code(self, code, request):
        item = AuthorizationCode(
            code=token_digest(code),
            client_id=request.client.client_id,
            redirect_uri=request.payload.redirect_uri or "",
            response_type=request.payload.response_type or "code",
            scope=request.scope,
            user_id=request.user.id,
            nonce=request.payload.data.get("nonce"),
            auth_time=getattr(request.user, "_auth_time", int(time.time())),
            issued_at=int(time.time()),
            code_challenge=request.payload.data.get("code_challenge"),
            code_challenge_method=request.payload.data.get("code_challenge_method"),
            sid=getattr(request.user, "_sid", ""),
        )
        db.session.add(item)
        db.session.commit()

    def query_authorization_code(self, code, client):
        return db.session.scalar(
            select(AuthorizationCode).where(
                AuthorizationCode.code == token_digest(code),
                AuthorizationCode.client_id == client.client_id,
                AuthorizationCode.issued_at >= int(time.time()) - 300,
            )
        )

    def delete_authorization_code(self, authorization_code):
        db.session.delete(authorization_code)
        db.session.commit()

    def authenticate_user(self, authorization_code):
        return db.session.get(User, authorization_code.user_id)


class OpenIDCodeImpl(OpenIDCode):
    DEFAULT_EXPIRES_IN = 300

    def resolve_client_private_key(self, client):
        key, _key_id = get_signing_key()
        return key

    def get_client_claims(self, client):
        return {
            "iss": current_app.config["OIDC_ISSUER"],
            "aud": [client.get_client_id()],
        }

    def get_authorization_code_claims(self, authorization_code):
        claims = super().get_authorization_code_claims(authorization_code)
        claims["sid"] = authorization_code.sid
        return claims

    def exists_nonce(self, nonce, request):
        return (
            db.session.scalar(
                select(AuthorizationCode.id).where(
                    AuthorizationCode.client_id == request.payload.client_id,
                    AuthorizationCode.nonce == nonce,
                )
            )
            is not None
        )

    def generate_user_info(self, user, scope):
        return UserInfo(
            sub=user.sub,
            preferred_username=user.username,
            name=user.display_name,
            picture=avatar_url(user),
        )


class RevocationEndpointImpl(RevocationEndpoint):
    CLIENT_AUTH_METHODS = ["client_secret_basic"]

    def query_token(self, token_string, token_type_hint):
        return db.session.scalar(
            select(OAuth2Token).where(OAuth2Token.access_token == token_digest(token_string))
        )

    def revoke_token(self, token, request):
        token.access_token_revoked_at = int(time.time())
        db.session.commit()


from authlib.oauth2.rfc6750 import BearerTokenValidator  # noqa: E402


class DatabaseBearerTokenValidator(BearerTokenValidator):
    def authenticate_token(self, token_string):
        return db.session.scalar(
            select(OAuth2Token).where(OAuth2Token.access_token == token_digest(token_string))
        )


require_oauth = ResourceProtector()
require_oauth.register_token_validator(DatabaseBearerTokenValidator())


def query_client(client_id: str):
    return db.session.scalar(
        select(OAuth2Client).where(
            OAuth2Client.client_id == client_id,
            OAuth2Client.is_active.is_(True),
        )
    )


def save_token(token: dict, request) -> None:
    access_token = token["access_token"]
    item = OAuth2Token(
        client_id=request.client.client_id,
        user_id=request.user.id,
        sid=getattr(request.authorization_code, "sid", ""),
        token_type=token.get("token_type", "Bearer"),
        access_token=token_digest(access_token),
        refresh_token=None,
        scope=token.get("scope", ""),
        issued_at=token.get("issued_at", int(time.time())),
        expires_in=token.get("expires_in", current_app.config["OAUTH_TOKEN_EXPIRES_SECONDS"]),
    )
    db.session.add(item)
    membership = db.session.scalar(
        select(AppMembership).where(
            AppMembership.user_id == request.user.id,
            AppMembership.client_id == request.client.client_id,
        )
    )
    if membership:
        membership.last_authorized_at = utc_now()
    else:
        db.session.add(AppMembership(user_id=request.user.id, client_id=request.client.client_id))
    # AuthorizationCodeGrant deletes the code immediately afterwards. Keep the
    # token, membership update and code deletion in that single transaction.
    db.session.flush()


def init_oauth(app) -> None:
    authorization.init_app(app, query_client=query_client, save_token=save_token)
    authorization.register_grant(
        AuthorizationCodeGrantImpl,
        extensions=[RequiredS256CodeChallenge(required=True), OpenIDCodeImpl(require_nonce=True)],
    )
    authorization.register_endpoint(RevocationEndpointImpl)


def public_jwks() -> dict:
    key, key_id = get_signing_key()
    return {
        "keys": [
            key.as_dict(private=False, use="sig", alg="RS256", kid=key_id)
        ]
    }


def userinfo_payload() -> dict:
    token = current_token
    return {
        "sub": token.user.sub,
        "preferred_username": token.user.username,
        "name": token.user.display_name,
        "picture": avatar_url(token.user),
    }


def signing_key_id(path) -> str:
    if not path.is_file():
        return "missing"
    return get_signing_key(Path(path))[1]
