from app.admin_repository import D1AdminRepository


class FakeClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.statements = []

    def execute(self, sql, params=()):
        self.statements.append(("single", sql, list(params)))
        return self.responses.pop(0)

    def batch(self, statements):
        captured = list(statements)
        self.statements.append(("batch", captured))
        return [{"rows": [], "meta": {"changes": 1}} for _ in captured]


def user_row(user_id, *, active=0):
    return {
        "id": user_id,
        "sub": f"sub-{user_id}",
        "username": f"user-{user_id}",
        "username_key": f"user-{user_id}",
        "display_name": f"User {user_id}",
        "is_active": active,
        "is_system_admin": 0,
        "must_change_password": 0,
        "merged_into_user_id": None,
        "avatar_file": None,
    }


def test_d1_delete_user_is_one_guarded_batch():
    client = FakeClient([
        {"rows": [user_row(7)]},
        {"rows": []},
        {"rows": [{"count": 0}]},
    ])

    target, error = D1AdminRepository(client).delete_user(7, actor_id=1, ip="127.0.0.1")

    assert error is None
    assert target.id == 7
    mode, statements = client.statements[-1]
    assert mode == "batch"
    assert statements[0].sql.startswith("UPDATE users SET updated_at=updated_at")
    assert statements[-1].sql.startswith("DELETE FROM users")
    assert any("admin.user_deleted" in item.params for item in statements)


def test_d1_merge_queues_logout_and_transfers_memberships_in_one_batch():
    client = FakeClient([
        {"rows": [user_row(2), user_row(3, active=1)]},
    ])

    source, target, error = D1AdminRepository(client).merge_users(
        2, 3, actor_id=1, ip="127.0.0.1"
    )

    assert error is None
    assert source.id == 2
    assert target.id == 3
    mode, statements = client.statements[-1]
    assert mode == "batch"
    assert any(item.sql.startswith("INSERT INTO backchannel_jobs") for item in statements)
    assert any(item.sql.startswith("INSERT INTO user_app_memberships") for item in statements)
    assert statements[-1].sql.startswith("UPDATE users SET is_system_admin=0")


def test_d1_oauth_client_upsert_is_one_statement():
    client = FakeClient([{"rows": [], "meta": {"changes": 1}}])

    D1AdminRepository(client).upsert_oauth_client(
        client_id="todo",
        client_secret_hash="sha256$hash",
        issued_at=1,
        launch_uri="https://todo.example/",
        backchannel_logout_uri="https://todo.example/auth/backchannel-logout",
        metadata={"client_name": "Todo", "redirect_uris": ["https://todo.example/callback"]},
    )

    mode, sql, params = client.statements[-1]
    assert mode == "single"
    assert "ON CONFLICT(client_id) DO UPDATE" in sql
    assert "todo" in params


def test_d1_dashboard_reads_client_metadata():
    client = FakeClient([
        {"rows": [{"count": 0}]},
        {"rows": []},
        {"rows": [{
            "id": 1,
            "client_id": "todo",
            "client_metadata": '{"client_name":"Todo List"}',
            "is_active": 1,
        }]},
        {"rows": [{"count": 0}]},
    ])
    _users, clients, _memberships, *_rest = D1AdminRepository(client).dashboard(1, 50)
    assert clients[0].client_name == "Todo List"
