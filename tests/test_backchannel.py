from __future__ import annotations

import pytest
from sqlalchemy import select

from app.backchannel import deliver_pending_jobs
from app.extensions import db
from app.models import AppMembership, BackchannelJob, OAuth2Client, WebSession
from tests.conftest import client_secret_hash, create_user, csrf_from
from tests.test_accounts import login


class SuccessfulResponse:
    def raise_for_status(self):
        return None


@pytest.mark.parametrize("reason", ["logout_all", "password_changed"])
def test_user_action_queues_and_delivers_backchannel(app, client, monkeypatch, reason):
    with app.app_context():
        user = create_user()
        oauth_client = OAuth2Client(
            client_id="todo",
            client_secret=client_secret_hash("secret"),
            client_id_issued_at=1,
            client_secret_expires_at=0,
            launch_uri="https://todo.test/",
            backchannel_logout_uri="https://todo.test/auth/backchannel-logout",
            is_active=True,
        )
        oauth_client.set_client_metadata(
            {
                "client_name": "Todo",
                "redirect_uris": ["https://todo.test/auth/callback"],
                "scope": "openid profile",
                "grant_types": ["authorization_code"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "client_secret_basic",
            }
        )
        db.session.add(oauth_client)
        db.session.add(AppMembership(user_id=user.id, client_id="todo"))
        db.session.commit()
        user_id = user.id

    login(client)
    if reason == "logout_all":
        page = client.get("/oauth/logout")
        assert 'href="/account"' in page.text and ">取消</a>" in page.text
        response = client.post("/oauth/logout", data={"csrf_token": csrf_from(page)})
    else:
        response = client.post(
            "/account",
            data={
                "csrf_token": csrf_from(client.get("/account")),
                "action": "password",
                "current_password": "password-123",
                "new_password": "new-password-456",
                "confirm_password": "new-password-456",
            },
        )
    assert response.status_code == 302
    with app.app_context():
        sessions = db.session.scalars(select(WebSession).where(WebSession.user_id == user_id)).all()
        assert any(item.revoked_at is not None for item in sessions)
        active_count = sum(item.revoked_at is None for item in sessions)
        assert active_count == int(reason == "password_changed")
        job = db.session.scalar(select(BackchannelJob))
        assert job.status == "pending" and job.reason == reason

    sent = {}

    def fake_post(url, data, **kwargs):
        sent["url"] = url
        sent["logout_token"] = data["logout_token"]
        return SuccessfulResponse()

    monkeypatch.setattr("app.backchannel.requests.post", fake_post)
    with app.app_context():
        assert deliver_pending_jobs() == {"delivered": 1, "failed": 0}
        assert db.session.scalar(select(BackchannelJob)).status == "delivered"
    assert sent["url"] == "https://todo.test/auth/backchannel-logout"
    assert sent["logout_token"]
