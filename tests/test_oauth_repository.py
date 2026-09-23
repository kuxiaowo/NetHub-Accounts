from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.oauth_repository import D1OAuthRepository


class FakeGateway:
    def __init__(self, *, batch_results=None):
        self.batch_results = batch_results or [
            {"rows": [], "meta": {"changes": 1}},
            {"rows": [], "meta": {"changes": 1}},
            {"rows": [], "meta": {"changes": 1}},
        ]
        self.statements = None

    def batch(self, statements):
        self.statements = statements
        return self.batch_results


def token_values():
    return {
        "client_id": "todo",
        "user_id": 7,
        "sid": "session-id",
        "token_type": "Bearer",
        "access_token": "hashed-token",
        "refresh_token": None,
        "scope": "openid profile",
        "issued_at": 123,
        "access_token_revoked_at": 0,
        "refresh_token_revoked_at": 0,
        "expires_in": 300,
    }


def test_token_membership_and_code_consumption_use_one_batch():
    gateway = FakeGateway()
    repository = D1OAuthRepository(gateway)
    code = SimpleNamespace(id=11, code="hashed-code")

    repository.save_token_and_consume_code(token_values(), code)

    assert len(gateway.statements) == 3
    assert "INSERT INTO oauth2_tokens" in gateway.statements[0].sql
    assert "WHERE EXISTS" in gateway.statements[0].sql
    assert "ON CONFLICT(user_id, client_id)" in gateway.statements[1].sql
    assert gateway.statements[2].sql.startswith("DELETE FROM oauth2_authorization_codes")
    assert gateway.statements[2].params == [11, "hashed-code"]
    assert code._d1_consumed is True


def test_already_consumed_code_is_rejected_without_false_success():
    gateway = FakeGateway(
        batch_results=[
            {"rows": [], "meta": {"changes": 0}},
            {"rows": [], "meta": {"changes": 0}},
            {"rows": [], "meta": {"changes": 0}},
        ]
    )
    repository = D1OAuthRepository(gateway)

    with pytest.raises(RuntimeError, match="already consumed"):
        repository.save_token_and_consume_code(
            token_values(), SimpleNamespace(id=11, code="hashed-code")
        )
