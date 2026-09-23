from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import select

from .d1_gateway import D1GatewayClient, Statement
from .extensions import db
from .models import AppMembership, BackchannelJob, OAuth2Client, User, utc_now


@dataclass
class Job:
    id: int
    user_id: int
    client_id: str
    sid: str | None
    reason: str
    status: str
    attempts: int
    last_error: str
    next_attempt_at: datetime | str
    delivered_at: datetime | str | None = None


@dataclass
class Client:
    client_id: str
    backchannel_logout_uri: str


@dataclass
class Subject:
    id: int
    sub: str


class BackchannelRepository:
    def queue(self, user_id: int, reason: str, sid: str | None = None) -> int:
        raise NotImplementedError

    def pending(self, now: datetime, limit: int) -> list[tuple[Job, Client | None, Subject | None]]:
        raise NotImplementedError

    def mark_processing(self, job: Job) -> bool:
        raise NotImplementedError

    def mark_failed(self, job: Job, error: str, next_attempt: datetime) -> bool:
        raise NotImplementedError

    def mark_delivered(self, job: Job, delivered_at: datetime) -> bool:
        raise NotImplementedError


class SQLiteBackchannelRepository(BackchannelRepository):
    def queue(self, user_id, reason, sid=None):
        client_ids = db.session.scalars(
            select(AppMembership.client_id).where(AppMembership.user_id == user_id)
        ).all()
        created = 0
        for client_id in client_ids:
            client = db.session.scalar(
                select(OAuth2Client).where(OAuth2Client.client_id == client_id)
            )
            if client and client.backchannel_logout_uri:
                db.session.add(
                    BackchannelJob(
                        user_id=user_id, client_id=client_id, sid=sid, reason=reason
                    )
                )
                created += 1
        return created

    def pending(self, now, limit):
        jobs = db.session.scalars(select(BackchannelJob).where(
            BackchannelJob.status.in_(["pending", "failed"]),
            BackchannelJob.next_attempt_at <= now,
        ).order_by(BackchannelJob.id).limit(limit)).all()
        result = []
        for item in jobs:
            client = db.session.scalar(select(OAuth2Client).where(OAuth2Client.client_id == item.client_id))
            user = db.session.get(User, item.user_id)
            result.append((item, client, user))
        return result

    def mark_processing(self, job):
        changed = db.session.query(BackchannelJob).filter(
            BackchannelJob.id == job.id,
            BackchannelJob.status.in_(["pending", "failed"]),
        ).update({BackchannelJob.status: "processing"}, synchronize_session=False)
        db.session.commit()
        return bool(changed)

    def mark_failed(self, job, error, next_attempt):
        changed = db.session.query(BackchannelJob).filter(
            BackchannelJob.id == job.id, BackchannelJob.status == "processing"
        ).update({BackchannelJob.status: "failed", BackchannelJob.attempts: BackchannelJob.attempts + 1,
                  BackchannelJob.last_error: error[:500], BackchannelJob.next_attempt_at: next_attempt}, synchronize_session=False)
        db.session.commit()
        return bool(changed)

    def mark_delivered(self, job, delivered_at):
        changed = db.session.query(BackchannelJob).filter(
            BackchannelJob.id == job.id, BackchannelJob.status == "processing"
        ).update({BackchannelJob.status: "delivered", BackchannelJob.attempts: BackchannelJob.attempts + 1,
                  BackchannelJob.last_error: "", BackchannelJob.delivered_at: delivered_at}, synchronize_session=False)
        db.session.commit()
        return bool(changed)


class D1BackchannelRepository(BackchannelRepository):
    def __init__(self, client: D1GatewayClient):
        self.client = client

    def queue(self, user_id, reason, sid=None):
        clients = self.client.execute(
            "SELECT m.client_id FROM user_app_memberships m "
            "JOIN oauth2_clients c ON c.client_id = m.client_id "
            "WHERE m.user_id = ? AND c.is_active = 1 "
            "AND c.backchannel_logout_uri <> ''",
            [user_id],
        ).get("rows", [])
        if not clients:
            return 0
        now = utc_now().isoformat(sep=" ")
        self.client.batch(
            [
                Statement(
                    "INSERT INTO backchannel_jobs "
                    "(user_id, client_id, sid, reason, status, attempts, last_error, "
                    "next_attempt_at, created_at, delivered_at) "
                    "VALUES (?, ?, ?, ?, 'pending', 0, '', ?, ?, NULL)",
                    [user_id, item["client_id"], sid, reason, now, now],
                )
                for item in clients
            ]
        )
        return len(clients)

    @staticmethod
    def _job(row: dict[str, Any]) -> Job:
        return Job(**{k: row.get(k) for k in Job.__dataclass_fields__})

    def pending(self, now, limit):
        rows = self.client.execute(
            "SELECT id,user_id,client_id,sid,reason,status,attempts,last_error,next_attempt_at,delivered_at "
            "FROM backchannel_jobs WHERE status IN (?,?) AND next_attempt_at <= ? ORDER BY id LIMIT ?",
            ("pending", "failed", now.isoformat(sep=" "), limit),
        ).get("rows", [])
        out = []
        for row in rows:
            job = self._job(row)
            c = self.client.execute("SELECT client_id,backchannel_logout_uri FROM oauth2_clients WHERE client_id = ?", (job.client_id,)).get("rows", [])
            u = self.client.execute("SELECT id,sub FROM users WHERE id = ?", (job.user_id,)).get("rows", [])
            client = Client(**c[0]) if c else None
            user = Subject(**u[0]) if u else None
            out.append((job, client, user))
        return out

    def _update(self, sql, params):
        return int(self.client.execute(sql, params).get("meta", {}).get("changes", 0)) > 0

    def mark_processing(self, job):
        return self._update("UPDATE backchannel_jobs SET status=? WHERE id=? AND status IN (?,?)", ("processing", job.id, "pending", "failed"))

    def mark_failed(self, job, error, next_attempt):
        return self._update("UPDATE backchannel_jobs SET status=?,attempts=attempts+1,last_error=?,next_attempt_at=? WHERE id=? AND status=?", ("failed", error[:500], next_attempt.isoformat(sep=" "), job.id, "processing"))

    def mark_delivered(self, job, delivered_at):
        return self._update("UPDATE backchannel_jobs SET status=?,attempts=attempts+1,last_error=?,delivered_at=? WHERE id=? AND status=?", ("delivered", "", delivered_at.isoformat(sep=" "), job.id, "processing"))


def get_backchannel_repository() -> BackchannelRepository:
    from flask import current_app
    if current_app.config.get("ACCOUNTS_DATABASE_BACKEND") == "d1":
        return D1BackchannelRepository(current_app.extensions["d1_gateway_client"])
    return SQLiteBackchannelRepository()
