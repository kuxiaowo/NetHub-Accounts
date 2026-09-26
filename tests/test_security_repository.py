from datetime import UTC, datetime

from app.security_repository import D1SecurityRepository


class FakeClient:
    def __init__(self):
        self.calls = []

    def execute(self, sql, params=()):
        self.calls.append((sql, list(params)))
        if sql.startswith("SELECT COUNT"):
            return {"rows": [{"count": 2}], "meta": {"changes": 0}}
        return {"rows": [], "meta": {"changes": 1}}

    def batch(self, statements):
        self.batch_statements = list(statements)
        return []


def test_d1_security_repository_uses_bound_parameters():
    fake = FakeClient()
    repo = D1SecurityRepository(fake)
    cutoff = datetime(2026, 1, 1, tzinfo=UTC)
    assert repo.rate_count("login", "ip", cutoff, failures_only=True) == 2
    repo.add_rate_event("login", "ip", False)
    repo.add_audit(None, 4, "auth.login_failed", "127.0.0.1", {"x": 1})
    repo.revoke_sessions(4, cutoff)
    assert len(fake.calls) == 4
    assert all("?" in sql for sql, _ in fake.calls)
    assert all("'ip'" not in sql for sql, _ in fake.calls)


def test_d1_revoke_access_is_single_explicit_batch():
    fake = FakeClient()
    D1SecurityRepository(fake).revoke_access(4, datetime(2026, 1, 1, tzinfo=UTC))
    assert len(fake.batch_statements) == 2
    assert fake.batch_statements[0].sql.startswith("UPDATE web_sessions SET revoked_at")
    assert fake.batch_statements[1].sql.startswith(
        "UPDATE oauth2_tokens SET access_token_revoked_at"
    )
