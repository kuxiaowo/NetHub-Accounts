from datetime import timedelta
from urllib.parse import urlsplit

import pytest
from sqlalchemy import select

from app.extensions import db
from app.governance import cipher, create_invitation, request_verification
from app.models import EmailJob, EmailVerification, Invitation, User, utc_now
from tests.conftest import create_user, csrf_from


def eligible():
    user = create_user()
    user.email = "alice@example.test"
    user.email_verified_at = utc_now() - timedelta(hours=72, seconds=1)
    user.first_email_verified_at = user.email_verified_at
    db.session.commit()
    return user


def test_daily_invite_is_single_use_and_revocation_does_not_refund(app):
    with app.test_request_context():
        user = eligible()
        item, token = create_invitation(user.id)
        assert item.expires_at - item.created_at <= timedelta(days=7)
        assert item.token_hash != token
        item.revoked_at = utc_now()
        db.session.commit()
        with pytest.raises(ValueError, match="今日邀请额度"):
            create_invitation(user.id)
        assert len(db.session.scalars(select(Invitation)).all()) == 1


def test_email_unverified_and_72_hours_block_invites(app):
    with app.test_request_context():
        user = create_user()
        with pytest.raises(ValueError, match="验证邮箱"):
            create_invitation(user.id)
        user.email_verified_at = user.first_email_verified_at = utc_now()
        db.session.commit()
        with pytest.raises(ValueError, match="72"):
            create_invitation(user.id)


def test_verification_get_does_not_consume_and_post_is_one_time(app, client):
    with app.test_request_context():
        user_id = create_user().id
        request_verification(user_id, "alice@example.test")
        job = db.session.scalar(select(EmailJob))
        link = cipher().decrypt(job.payload_encrypted.encode()).decode()
        assert "alice@example.test" not in job.payload_encrypted
    path = urlsplit(link).path + "?" + urlsplit(link).query
    page = client.get(path)
    assert page.status_code == 200
    with app.app_context():
        assert db.session.scalar(select(EmailVerification)).consumed_at is None
    assert client.post(path, data={"csrf_token": csrf_from(page)}).status_code == 302
    with app.app_context():
        assert db.session.get(User, user_id).email_verified_at is not None
    assert client.post(path, data={"csrf_token": csrf_from(page)}).status_code == 400


@pytest.mark.parametrize("mode", ["invite", "open"])
def test_registration_without_invite(app, client, mode):
    if mode == "open":
        app.config["REGISTRATION_MODE"] = "open"
    page = client.get("/register")
    assert ('name="invite"' in page.text) == (mode == "invite")
    response = client.post(
        "/register",
        data={
            "csrf_token": csrf_from(page),
            "username": "uninvited",
            "display_name": "Test",
            "email": "test@example.test",
            "password": "password-123",
            "confirm_password": "password-123",
            "accept_terms": "yes",
        },
    )
    with app.app_context():
        user = db.session.scalar(select(User))
        job = db.session.scalar(select(EmailJob))
        if mode == "open":
            assert response.status_code == 302
            assert user.email == "test@example.test" and user.email_verified_at is None
            assert job.status == "pending"
            assert db.session.scalar(select(Invitation)) is None
        else:
            assert response.status_code == 400
            assert user is None and job is None


def test_old_link_does_not_consume_invitation_during_open_registration(app, client):
    with app.test_request_context():
        owner = eligible()
        item, token = create_invitation(owner.id)
        invitation_id = item.id

    app.config["REGISTRATION_MODE"] = "open"
    path = "/register?invite=" + token
    form = {
        "csrf_token": csrf_from(client.get(path)),
        "username": "newcomer",
        "display_name": "Newcomer",
        "email": "newcomer@example.test",
        "password": "password-123",
        "confirm_password": "password-123",
        "accept_terms": "yes",
        "invite": token,
    }
    assert client.post(path, data=form).status_code == 302
    with app.app_context():
        item = db.session.get(Invitation, invitation_id)
        assert item.redeemed_at is None and item.invitee_id is None

    app.config["REGISTRATION_MODE"] = "invite"
    other = app.test_client()
    form.update(
        csrf_token=csrf_from(other.get(path)), username="invitee", email="other@example.test"
    )
    assert other.post(path, data=form).status_code == 302
    with app.app_context():
        item = db.session.get(Invitation, invitation_id)
        assert db.session.get(User, item.invitee_id).username == "invitee"


def test_open_mode_pauses_invitation_issuance_until_restored(app, client):
    from tests.test_accounts import login

    with app.test_request_context():
        eligible()
    assert login(client).status_code == 302
    app.config["REGISTRATION_MODE"] = "open"
    page = client.get("/account/community")
    assert "邀请功能已暂停" in page.text and "生成今日邀请" not in page.text
    form = {"csrf_token": csrf_from(page)}
    client.post("/account/invitations", data=form)
    with app.app_context():
        assert db.session.scalar(select(Invitation)) is None

    app.config["REGISTRATION_MODE"] = "invite"
    assert "邀请已生成" in client.post("/account/invitations", data=form).text


def test_failed_invitation_registration_counts_toward_rate_limit(app, client):
    app.config["REGISTER_LIMIT_PER_DAY"] = 2
    responses = []
    for _ in range(3):
        page = client.get("/register")
        response = client.post(
            "/register",
            data={
                "csrf_token": csrf_from(page),
                "username": "invalid-invite",
                "display_name": "Test",
                "email": "test@example.test",
                "password": "password-123",
                "confirm_password": "password-123",
                "accept_terms": "yes",
                "invite": "invalid",
            },
        )
        responses.append(response.status_code)
    assert responses == [400, 400, 429]
    with app.app_context():
        assert db.session.scalar(select(User)) is None
        assert db.session.scalar(select(EmailJob)) is None


@pytest.mark.parametrize("expired", [False, True])
def test_invitation_cannot_be_redeemed_twice_or_after_expiry(app, expired):
    from app.governance import redeem_invitation, write_lock

    with app.test_request_context():
        owner = eligible()
        item, token = create_invitation(owner.id)
        first = create_user("first-invitee")
        second = create_user("second-invitee")
        if expired:
            item.expires_at = utc_now() - timedelta(seconds=1)
        db.session.commit()
        if not expired:
            with write_lock():
                redeem_invitation(token, first)
        with pytest.raises(ValueError, match="邀请凭证无效"):
            with write_lock():
                redeem_invitation(token, second)
        db.session.refresh(item)
        assert item.invitee_id == (None if expired else first.id)


def test_concurrent_generation_has_one_daily_winner(app):
    from concurrent.futures import ThreadPoolExecutor

    with app.test_request_context():
        user_id = eligible().id

    def generate():
        with app.test_request_context():
            try:
                create_invitation(user_id)
                return True
            except ValueError:
                return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(lambda _: generate(), range(2))) == [False, True]
    with app.app_context():
        assert len(db.session.scalars(select(Invitation)).all()) == 1


def test_client_status_requires_credentials_and_app_membership(app, client):
    from app.models import AppMembership
    from tests.test_accounts import oauth_client

    with app.app_context():
        user = create_user()
        subject = user.sub
        db.session.add(oauth_client("wiki"))
        user_id = user.id
        db.session.commit()
    path = "/api/client/account-status?sub=" + subject
    assert client.get(path).status_code == 401
    assert client.get(path, auth=("wiki", "wrong")).status_code == 401
    assert client.get(path, auth=("wiki", "wiki-client-secret")).status_code == 404
    with app.app_context():
        db.session.add(AppMembership(user_id=user_id, client_id="wiki"))
        db.session.commit()
    response = client.get(path, auth=("wiki", "wiki-client-secret"))
    assert response.status_code == 200
    assert response.json["active"] is True
    assert response.json["emailVerified"] is False
