from __future__ import annotations

import threading
import time
import uuid
from datetime import timedelta

import requests
from flask import current_app
from joserfc import jwt

from .backchannel_repository import get_backchannel_repository
from .models import BackchannelJob, User, utc_now
from .oidc import get_signing_key

LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"


def queue_logout(user: User, reason: str, sid: str | None = None) -> int:
    return get_backchannel_repository().queue(user.id, reason, sid)


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
    key, key_id = get_signing_key()
    return jwt.encode({"alg": "RS256", "kid": key_id}, claims, key)


def deliver_pending_jobs(limit: int = 10) -> dict[str, int]:
    now = utc_now()
    repository = get_backchannel_repository()
    jobs = repository.pending(now, limit)
    delivered = failed = 0
    for job, client, user in jobs:
        if client is None or user is None or not client.backchannel_logout_uri:
            if repository.mark_processing(job):
                repository.mark_failed(job, "client or user no longer exists", now)
            failed += 1
            continue
        if not repository.mark_processing(job):
            continue
        try:
            response = requests.post(
                client.backchannel_logout_uri,
                data={"logout_token": _logout_token(job, user)},
                timeout=current_app.config["BACKCHANNEL_TIMEOUT_SECONDS"],
                headers={"User-Agent": "NetHub-Accounts/1.0"},
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            delay = min(3600, 30 * (2 ** min(job.attempts + 1, 7)))
            repository.mark_failed(job, str(exc), utc_now() + timedelta(seconds=delay))
            failed += 1
        else:
            repository.mark_delivered(job, utc_now())
            delivered += 1
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
