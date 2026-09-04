from __future__ import annotations

import threading
import time
import uuid
from datetime import timedelta

import requests
from flask import current_app
from joserfc import jwt
from joserfc.jwk import import_key
from sqlalchemy import select

from .extensions import db
from .models import AppMembership, BackchannelJob, OAuth2Client, User, utc_now

LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"


def queue_logout(user: User, reason: str, sid: str | None = None) -> int:
    created = 0
    client_ids = db.session.scalars(
        select(AppMembership.client_id).where(AppMembership.user_id == user.id)
    ).all()
    for client_id in client_ids:
        client = db.session.scalar(select(OAuth2Client).where(OAuth2Client.client_id == client_id))
        if client and client.backchannel_logout_uri:
            db.session.add(
                BackchannelJob(
                    user_id=user.id,
                    client_id=client_id,
                    sid=sid,
                    reason=reason,
                )
            )
            created += 1
    return created


def _logout_token(job: BackchannelJob, user: User) -> str:
    now = int(time.time())
    claims = {
        "iss": current_app.config["OIDC_ISSUER"],
        "aud": [job.client_id],
        "iat": now,
        "jti": str(uuid.uuid4()),
        "sub": user.sub,
        "events": {LOGOUT_EVENT: {}},
    }
    if job.sid:
        claims["sid"] = job.sid
    key = import_key(
        current_app.config["OIDC_SIGNING_KEY_PATH"].read_bytes(),
        "RSA",
        {"kid": current_app.config["OIDC_KEY_ID"]},
    )
    return jwt.encode({"alg": "RS256", "kid": current_app.config["OIDC_KEY_ID"]}, claims, key)


def deliver_pending_jobs(limit: int = 10) -> dict[str, int]:
    now = utc_now()
    jobs = db.session.scalars(
        select(BackchannelJob)
        .where(
            BackchannelJob.status.in_(["pending", "failed"]),
            BackchannelJob.next_attempt_at <= now,
        )
        .order_by(BackchannelJob.id)
        .limit(limit)
    ).all()
    delivered = failed = 0
    for job in jobs:
        client = db.session.scalar(
            select(OAuth2Client).where(OAuth2Client.client_id == job.client_id)
        )
        user = db.session.get(User, job.user_id)
        if client is None or user is None or not client.backchannel_logout_uri:
            job.status = "failed"
            job.last_error = "client or user no longer exists"
            job.attempts += 1
            failed += 1
            continue
        job.status = "processing"
        db.session.commit()
        try:
            response = requests.post(
                client.backchannel_logout_uri,
                data={"logout_token": _logout_token(job, user)},
                timeout=current_app.config["BACKCHANNEL_TIMEOUT_SECONDS"],
                headers={"User-Agent": "NetHub-Accounts/1.0"},
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            job.status = "failed"
            job.attempts += 1
            job.last_error = str(exc)[:500]
            delay = min(3600, 30 * (2 ** min(job.attempts, 7)))
            job.next_attempt_at = utc_now() + timedelta(seconds=delay)
            failed += 1
        else:
            job.status = "delivered"
            job.attempts += 1
            job.last_error = ""
            job.delivered_at = utc_now()
            delivered += 1
        db.session.commit()
    return {"delivered": delivered, "failed": failed}


def start_worker(app) -> None:
    if not app.config.get("BACKCHANNEL_WORKER_ENABLED") or app.testing:
        return

    def run() -> None:
        while True:
            time.sleep(app.config["BACKCHANNEL_POLL_SECONDS"])
            try:
                with app.app_context():
                    from .security import cleanup_expired

                    cleanup_expired()
                    deliver_pending_jobs()
            except Exception:
                app.logger.exception("back-channel logout worker failed")

    threading.Thread(target=run, name="backchannel-worker", daemon=True).start()
