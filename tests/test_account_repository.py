import sqlite3
from datetime import datetime, timedelta

from app.account_repository import D1AccountRepository


class FakeClient:
    def __init__(self):
        self.statements = []

    def batch(self, statements):
        self.statements = list(statements)
        return [
            {"rows": [], "meta": {"changes": 1}},
            *({"rows": [], "meta": {"changes": 1}} for _ in range(4)),
        ]

    def execute(self, sql, params=()):
        self.statements.append(type("Captured", (), {"sql": sql, "params": params})())
        return {"rows": [], "meta": {"changes": 0}}


def test_d1_registration_is_one_atomic_batch():
    now = datetime(2026, 1, 1, 12, 0, 0)
    client = FakeClient()
    repository = D1AccountRepository(client)

    user, _session = repository.register(
        {
            "username": "alice",
            "username_key": "alice",
            "display_name": "Alice",
            "password_hash": "hash",
            "terms_accepted_at": now,
        },
        {
            "sid": "sid",
            "token_hash": "token",
            "csrf_token": "csrf",
            "auth_time": 1,
            "created_at": now,
            "last_seen_at": now,
            "idle_expires_at": now + timedelta(hours=1),
            "absolute_expires_at": now + timedelta(days=1),
        },
        ip="127.0.0.1",
    )

    assert user.id
    assert len(client.statements) == 5
    assert client.statements[0].sql.startswith("INSERT INTO users")
    assert client.statements[-1].sql.startswith("INSERT INTO web_sessions")
    assert all(not isinstance(value, datetime) for item in client.statements for value in item.params)


def test_d1_password_change_revokes_access_and_creates_replacement_session_in_one_batch():
    now = datetime(2026, 1, 1, 12, 0, 0)
    client = FakeClient()
    repository = D1AccountRepository(client)

    changed = repository.change_password(
        42,
        "new-hash",
        {
            "sid": "replacement",
            "token_hash": "token",
            "user_id": 42,
            "csrf_token": "csrf",
            "auth_time": 1,
            "created_at": now,
            "last_seen_at": now,
            "idle_expires_at": now + timedelta(hours=1),
            "absolute_expires_at": now + timedelta(days=1),
        },
        ip="127.0.0.1",
    )

    assert changed is True
    assert len(client.statements) == 6
    assert client.statements[0].sql.startswith("UPDATE users SET password_hash")
    assert client.statements[1].sql.startswith("DELETE FROM legacy_credentials")
    assert client.statements[2].sql.startswith("UPDATE web_sessions SET revoked_at")
    assert client.statements[3].sql.startswith("UPDATE oauth2_tokens")
    assert client.statements[-1].sql.startswith("INSERT INTO web_sessions")


def test_d1_logout_all_is_one_batch_with_audit():
    client = FakeClient()
    D1AccountRepository(client).logout_all(42, ip="127.0.0.1")

    assert len(client.statements) == 3
    assert client.statements[0].sql.startswith("UPDATE web_sessions SET revoked_at")
    assert client.statements[1].sql.startswith("UPDATE oauth2_tokens")
    assert "auth.logout_all" in client.statements[2].params


def test_d1_account_details_reads_client_name_from_metadata():
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.executescript(
        """
        CREATE TABLE oauth2_clients (
            id INTEGER, client_id TEXT, client_metadata TEXT, is_active INTEGER
        );
        CREATE TABLE user_app_memberships (
            id INTEGER, user_id INTEGER, client_id TEXT,
            first_authorized_at TEXT, last_authorized_at TEXT
        );
        CREATE TABLE login_aliases (
            id INTEGER, user_id INTEGER, alias TEXT, alias_key TEXT,
            source TEXT, created_at TEXT, updated_at TEXT
        );
        INSERT INTO oauth2_clients VALUES (1, 'todo', '{"client_name":"Todo List"}', 1);
        INSERT INTO user_app_memberships VALUES (1, 7, 'todo', '2026-01-01', '2026-01-02');
        """
    )

    class SQLiteGateway:
        def execute(self, sql, params=()):
            return {"rows": [dict(row) for row in connection.execute(sql, params).fetchall()]}

    memberships, aliases = D1AccountRepository(SQLiteGateway()).account_details(7)
    assert len(memberships) == 1
    assert memberships[0][1].client_name == "Todo List"
    assert aliases == []
    clients, linked = D1AccountRepository(SQLiteGateway()).home_data(7)
    assert clients[0].client_name == "Todo List"
    assert linked == {"todo"}
