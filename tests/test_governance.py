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


def test_registration_without_invite_never_creates_account(app, client):
    page = client.get("/register")
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
    assert response.status_code == 400
    with app.app_context():
        assert db.session.scalar(select(User)) is None
        assert db.session.scalar(select(EmailJob)) is None


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
