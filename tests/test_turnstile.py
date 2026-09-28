from __future__ import annotations

import io
import json
from urllib.error import URLError
from urllib.parse import parse_qs

import pytest

from app import turnstile
from tests.conftest import csrf_from


class SiteverifyResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


def test_siteverify_checks_action_hostname_and_secret(app, monkeypatch):
    app.config.update(TURNSTILE_SECRET_KEY="test-secret", TURNSTILE_HOSTNAME="auth.nethub.wiki")

    def response_for(action="login", hostname="auth.nethub.wiki"):
        def fake_open(submission, timeout):
            assert timeout == 4
            sent = parse_qs(submission.data.decode("ascii"))
            assert sent["secret"] == ["test-secret"]
            assert sent["response"] == ["single-use-token"]
            return SiteverifyResponse(
                json.dumps({"success": True, "action": action, "hostname": hostname}).encode()
            )

        return fake_open

    with app.test_request_context(
        "/login", method="POST", data={"cf-turnstile-response": "single-use-token"}
    ):
        monkeypatch.setattr(turnstile, "urlopen", response_for())
        assert turnstile.verify_turnstile("login")
        monkeypatch.setattr(turnstile, "urlopen", response_for(action="register"))
        assert not turnstile.verify_turnstile("login")
        monkeypatch.setattr(turnstile, "urlopen", response_for(hostname="other.example"))
        assert not turnstile.verify_turnstile("login")


def test_missing_token_does_not_call_siteverify(app, monkeypatch):
    monkeypatch.setattr(turnstile, "urlopen", lambda *_args, **_kwargs: pytest.fail("network call"))
    with app.test_request_context("/login", method="POST"):
        assert not turnstile.verify_turnstile("login")


def test_siteverify_outage_fails_closed(app, monkeypatch):
    monkeypatch.setattr(turnstile, "urlopen", lambda *_args, **_kwargs: (_ for _ in ()).throw(URLError("offline")))
    with app.test_request_context(
        "/login", method="POST", data={"cf-turnstile-response": "token"}
    ):
        with pytest.raises(turnstile.TurnstileUnavailable):
            turnstile.verify_turnstile("login")


def test_login_rejects_failed_turnstile_before_password_check(client, monkeypatch):
    monkeypatch.setattr("app.routes.verify_turnstile", lambda action: False)
    page = client.get("/login")
    response = client.post(
        "/login",
        data={"csrf_token": csrf_from(page), "username": "alice", "password": "wrong"},
    )
    assert response.status_code == 400
    assert "请完成人机验证" in response.text
