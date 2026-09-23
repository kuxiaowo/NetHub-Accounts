from __future__ import annotations

import hashlib
import hmac
import json

from app.d1_gateway import D1GatewayClient
from app.security_repository import D1SecurityRepository


class _Response:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return json.dumps({"ok": True, "results": [{"rows": [], "meta": {"changes": 1}}]}).encode()


def test_gateway_request_is_signed_with_shared_canonical_format(monkeypatch):
    captured = {}

    def fake_urlopen(request, timeout):
        captured["headers"] = dict(request.headers)
        captured["body"] = json.loads(request.data)
        captured["timeout"] = timeout
        return _Response()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    monkeypatch.setattr("app.d1_gateway.uuid.uuid4", lambda: "request-id")
    monkeypatch.setattr("app.d1_gateway.time.time", lambda: 1_700_000_000)
    result = D1GatewayClient("https://gateway.example", "secret", timeout=3).execute(
        "UPDATE users SET is_active = ? WHERE id = ?", (0, 7)
    )
    assert result["meta"]["changes"] == 1
    assert captured["body"]["mode"] == "single"
    raw = json.dumps(captured["body"], separators=(",", ":"), ensure_ascii=False).encode()
    digest = hashlib.sha256(raw).hexdigest()
    canonical = f"v1\nPOST\n/internal/db\nrequest-id\n1700000000\n{digest}".encode()
    expected = hmac.new(b"secret", canonical, hashlib.sha256).hexdigest()
    assert captured["headers"]["X-db-request-id"] == "request-id"
    assert captured["headers"]["X-db-timestamp"] == "1700000000"
    assert captured["headers"]["X-db-signature"] == expected
    assert captured["timeout"] == 3


def test_gateway_url_is_not_duplicated():
    client = D1GatewayClient("https://gateway.example/internal/db", "secret")
    assert client.url == "https://gateway.example/internal/db"


def test_legacy_upgrade_is_one_explicit_batch():
    class FakeClient:
        def batch(self, statements):
            self.statements = list(statements)
            return []

    client = FakeClient()
    D1SecurityRepository(client).upgrade_password(7, "scrypt:hash", False, 7, "127.0.0.1")
    assert len(client.statements) == 3
    assert client.statements[0].sql.startswith("UPDATE users SET password_hash")
    assert client.statements[1].sql.startswith("DELETE FROM legacy_credentials")
    assert client.statements[2].sql.startswith("INSERT INTO audit_logs")
    assert client.statements[0].params[-1] == 7
