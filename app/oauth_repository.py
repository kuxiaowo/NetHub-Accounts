from __future__ import annotations

import json
import time
from abc import ABC, abstractmethod
from typing import Any

from flask import current_app
from sqlalchemy import select

from .d1_gateway import D1GatewayClient, Statement
from .extensions import db
from .models import AppMembership, AuthorizationCode, OAuth2Client, OAuth2Token, User, utc_now


def _as_bool(value: Any) -> bool:
    return bool(value)


def _model(model_type, row: dict[str, Any] | None):
    if row is None:
        return None
    item = model_type()
    for key, value in row.items():
        if model_type is OAuth2Client and key == "client_metadata":
            item.set_client_metadata(json.loads(value or "{}"))
            continue
        if hasattr(model_type, key):
            if key in {"is_active", "is_system_admin", "must_change_password"}:
                value = _as_bool(value)
            setattr(item, key, value)
    return item


class OAuthRepository(ABC):
    @abstractmethod
    def query_client(self, client_id: str): ...

    @abstractmethod
    def save_authorization_code(self, values: dict[str, Any]) -> None: ...

    @abstractmethod
    def query_authorization_code(self, code_digest: str, client_id: str): ...

    @abstractmethod
    def delete_authorization_code(self, authorization_code) -> None: ...

    @abstractmethod
    def get_user(self, user_id: int): ...

    @abstractmethod
    def nonce_exists(self, client_id: str, nonce: str) -> bool: ...

    @abstractmethod
    def query_token(self, token_digest: str): ...

    @abstractmethod
    def revoke_token(self, token) -> None: ...

    @abstractmethod
    def save_token_and_consume_code(
        self, token_values: dict[str, Any], authorization_code
    ) -> None: ...


class SQLiteOAuthRepository(OAuthRepository):
    def query_client(self, client_id: str):
        return db.session.scalar(
            select(OAuth2Client).where(
                OAuth2Client.client_id == client_id,
                OAuth2Client.is_active.is_(True),
            )
        )

    def save_authorization_code(self, values: dict[str, Any]) -> None:
        db.session.add(AuthorizationCode(**values))
        db.session.commit()

    def query_authorization_code(self, code_digest: str, client_id: str):
        return db.session.scalar(
            select(AuthorizationCode).where(
                AuthorizationCode.code == code_digest,
                AuthorizationCode.client_id == client_id,
                AuthorizationCode.issued_at >= int(time.time()) - 300,
            )
        )

    def delete_authorization_code(self, authorization_code) -> None:
        db.session.delete(authorization_code)
        db.session.commit()

    def get_user(self, user_id: int):
        return db.session.get(User, user_id)

    def nonce_exists(self, client_id: str, nonce: str) -> bool:
        return (
            db.session.scalar(
                select(AuthorizationCode.id).where(
                    AuthorizationCode.client_id == client_id,
                    AuthorizationCode.nonce == nonce,
                )
            )
            is not None
        )

    def query_token(self, token_digest: str):
        return db.session.scalar(
            select(OAuth2Token).where(OAuth2Token.access_token == token_digest)
        )

    def revoke_token(self, token) -> None:
        token.access_token_revoked_at = int(time.time())
        db.session.commit()

    def save_token_and_consume_code(
        self, token_values: dict[str, Any], authorization_code
    ) -> None:
        db.session.add(OAuth2Token(**token_values))
        membership = db.session.scalar(
            select(AppMembership).where(
                AppMembership.user_id == token_values["user_id"],
                AppMembership.client_id == token_values["client_id"],
            )
        )
        if membership:
            membership.last_authorized_at = utc_now()
        else:
            db.session.add(
                AppMembership(
                    user_id=token_values["user_id"], client_id=token_values["client_id"]
                )
            )
        # Authlib invokes delete_authorization_code immediately after save_token.
        # Keeping the transaction open makes all three writes commit together there.
        db.session.flush()


class D1OAuthRepository(OAuthRepository):
    _AUTH_CODE_COLUMNS = (
        "id, user_id, sid, code, client_id, redirect_uri, response_type, scope, "
        "nonce, auth_time, acr, amr, code_challenge, code_challenge_method, issued_at"
    )
    _TOKEN_COLUMNS = (
        "id, user_id, sid, client_id, token_type, access_token, refresh_token, scope, "
        "issued_at, access_token_revoked_at, refresh_token_revoked_at, expires_in"
    )

    def __init__(self, client: D1GatewayClient) -> None:
        self.client = client

    @staticmethod
    def _first(result: dict[str, Any]) -> dict[str, Any] | None:
        rows = result.get("rows") or []
        return rows[0] if rows else None

    def query_client(self, client_id: str):
        result = self.client.execute(
            "SELECT id, launch_uri, backchannel_logout_uri, is_active, client_id, "
            "client_secret, client_id_issued_at, client_secret_expires_at, client_metadata, "
            "created_at, updated_at FROM oauth2_clients "
            "WHERE client_id = ? AND is_active = 1 LIMIT 1",
            [client_id],
        )
        return _model(OAuth2Client, self._first(result))

    def save_authorization_code(self, values: dict[str, Any]) -> None:
        columns = [
            "code", "client_id", "redirect_uri", "response_type", "scope", "user_id",
            "nonce", "auth_time", "issued_at", "code_challenge", "code_challenge_method", "sid",
        ]
        self.client.execute(
            f"INSERT INTO oauth2_authorization_codes ({', '.join(columns)}) "
            f"VALUES ({', '.join('?' for _ in columns)})",
            [values.get(column) for column in columns],
        )

    def query_authorization_code(self, code_digest: str, client_id: str):
        result = self.client.execute(
            f"SELECT {self._AUTH_CODE_COLUMNS} FROM oauth2_authorization_codes "
            "WHERE code = ? AND client_id = ? AND issued_at >= ? LIMIT 1",
            [code_digest, client_id, int(time.time()) - 300],
        )
        return _model(AuthorizationCode, self._first(result))

    def delete_authorization_code(self, authorization_code) -> None:
        if getattr(authorization_code, "_d1_consumed", False):
            return
        self.client.execute(
            "DELETE FROM oauth2_authorization_codes WHERE id = ? AND code = ?",
            [authorization_code.id, authorization_code.code],
        )

    def get_user(self, user_id: int):
        result = self.client.execute(
            "SELECT id, sub, username, username_key, display_name, avatar_file, "
            "avatar_updated_at, avatar_color, password_hash, is_active, is_system_admin, "
            "must_change_password, terms_accepted_at, merged_into_user_id, created_at, updated_at "
            "FROM users WHERE id = ? LIMIT 1",
            [user_id],
        )
        return _model(User, self._first(result))

    def nonce_exists(self, client_id: str, nonce: str) -> bool:
        result = self.client.execute(
            "SELECT 1 AS present FROM oauth2_authorization_codes "
            "WHERE client_id = ? AND nonce = ? LIMIT 1",
            [client_id, nonce],
        )
        return self._first(result) is not None

    def query_token(self, token_digest: str):
        result = self.client.execute(
            f"SELECT {self._TOKEN_COLUMNS} FROM oauth2_tokens WHERE access_token = ? LIMIT 1",
            [token_digest],
        )
        token = _model(OAuth2Token, self._first(result))
        if token is not None:
            token.user = self.get_user(token.user_id)
        return token

    def revoke_token(self, token) -> None:
        result = self.client.execute(
            "UPDATE oauth2_tokens SET access_token_revoked_at = ? "
            "WHERE id = ? AND access_token_revoked_at = 0",
            [int(time.time()), token.id],
        )
        token.access_token_revoked_at = int(time.time())
        if result.get("meta", {}).get("changes", 0) not in {0, 1}:
            raise RuntimeError("unexpected token revoke result")

    def save_token_and_consume_code(
        self, token_values: dict[str, Any], authorization_code
    ) -> None:
        now = utc_now().isoformat(sep=" ")
        code_id = authorization_code.id
        code_digest = authorization_code.code
        token_columns = [
            "client_id", "user_id", "sid", "token_type", "access_token", "refresh_token",
            "scope", "issued_at", "access_token_revoked_at", "refresh_token_revoked_at", "expires_in",
        ]
        token_params = [token_values.get(column) for column in token_columns]
        token_sql = (
            f"INSERT INTO oauth2_tokens ({', '.join(token_columns)}) "
            f"SELECT {', '.join('?' for _ in token_columns)} "
            "WHERE EXISTS (SELECT 1 FROM oauth2_authorization_codes WHERE id = ? AND code = ?)"
        )
        membership_sql = (
            "INSERT INTO user_app_memberships "
            "(user_id, client_id, first_authorized_at, last_authorized_at) "
            "SELECT ?, ?, ?, ? WHERE EXISTS "
            "(SELECT 1 FROM oauth2_authorization_codes WHERE id = ? AND code = ?) "
            "ON CONFLICT(user_id, client_id) DO UPDATE SET last_authorized_at = excluded.last_authorized_at"
        )
        results = self.client.batch(
            [
                Statement(token_sql, [*token_params, code_id, code_digest]),
                Statement(
                    membership_sql,
                    [token_values["user_id"], token_values["client_id"], now, now, code_id, code_digest],
                ),
                Statement(
                    "DELETE FROM oauth2_authorization_codes WHERE id = ? AND code = ?",
                    [code_id, code_digest],
                ),
            ]
        )
        changes = [item.get("meta", {}).get("changes", 0) for item in results]
        if len(changes) != 3 or changes[0] != 1 or changes[2] != 1:
            raise RuntimeError("authorization code was already consumed")
        authorization_code._d1_consumed = True


def init_oauth_repository(app) -> None:
    if app.config["ACCOUNTS_DATABASE_BACKEND"] == "d1":
        client = app.extensions.get("d1_gateway_client")
        if client is None:
            client = D1GatewayClient(
                app.config["ACCOUNTS_D1_GATEWAY_URL"],
                app.config["ACCOUNTS_D1_GATEWAY_SECRET"],
                timeout=app.config["ACCOUNTS_D1_GATEWAY_TIMEOUT"],
            )
        repository: OAuthRepository = D1OAuthRepository(client)
    else:
        repository = SQLiteOAuthRepository()
    app.extensions["accounts_oauth_repository"] = repository


def oauth_repository() -> OAuthRepository:
    return current_app.extensions["accounts_oauth_repository"]
