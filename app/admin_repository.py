"""Administrator reads and small writes for the D1 runtime path."""

from __future__ import annotations

import json
import secrets
import uuid
from datetime import datetime

from .account_repository import AccountConflictError, D1AccountRepository
from .d1_gateway import D1GatewayClient, Statement
from .models import AuditLog, BackchannelJob, OAuth2Client


class D1AdminRepository:
    def __init__(self, client: D1GatewayClient):
        self.client = client

    @staticmethod
    def _client(row):
        item = OAuth2Client()
        for key, value in row.items():
            if key == "client_metadata":
                item.set_client_metadata(json.loads(value or "{}"))
                continue
            if key in {"is_active"} and value is not None:
                value = bool(value)
            if hasattr(OAuth2Client, key):
                setattr(item, key, value)
        return item

    def dashboard(self, page: int, per_page: int):
        count_rows = self.client.execute("SELECT COUNT(*) AS count FROM users").get("rows") or []
        total_users = int(count_rows[0]["count"]) if count_rows else 0
        total_pages = max(1, (total_users + per_page - 1) // per_page)
        page = min(page, total_pages)
        user_rows = (
            self.client.execute(
                "SELECT * FROM users ORDER BY id LIMIT ? OFFSET ?",
                [per_page, (page - 1) * per_page],
            ).get("rows")
            or []
        )
        users = [D1AccountRepository._user(row) for row in user_rows]
        clients = [
            self._client(row)
            for row in (
                self.client.execute("SELECT * FROM oauth2_clients ORDER BY id").get("rows") or []
            )
        ]
        client_names = {
            client.client_id: client.client_name or client.client_id for client in clients
        }
        membership_map: dict[int, list[str]] = {}
        if users:
            placeholders = ",".join("?" for _ in users)
            rows = (
                self.client.execute(
                    f"SELECT user_id,client_id FROM user_app_memberships WHERE user_id IN ({placeholders}) "
                    "ORDER BY user_id,client_id",
                    [user.id for user in users],
                ).get("rows")
                or []
            )
            for row in rows:
                membership_map.setdefault(int(row["user_id"]), []).append(
                    client_names.get(row["client_id"], row["client_id"])
                )
        failed_rows = (
            self.client.execute(
                "SELECT COUNT(*) AS count FROM backchannel_jobs WHERE status='failed'"
            ).get("rows")
            or []
        )
        failed_jobs = int(failed_rows[0]["count"]) if failed_rows else 0
        return users, clients, membership_map, failed_jobs, total_users, total_pages, page

    def create_user(
        self,
        values,
        *,
        actor_id: int | None,
        ip: str,
        must_change_password: bool = True,
        audit_action: str = "admin.user_created",
    ):
        now = datetime.now().isoformat(sep=" ")
        user_id = secrets.randbelow(2**62 - 1) + 1
        columns = [
            "id",
            "sub",
            "username",
            "username_key",
            "display_name",
            "password_hash",
            "avatar_color",
            "is_active",
            "is_system_admin",
            "must_change_password",
            "terms_accepted_at",
            "created_at",
            "updated_at",
        ]
        params = [
            user_id,
            str(uuid.uuid4()),
            values["username"],
            values["username_key"],
            values["display_name"],
            values["password_hash"],
            "#6366f1",
            1,
            int(values.get("is_system_admin", False)),
            int(must_change_password),
            now,
            now,
            now,
        ]
        results = self.client.batch(
            [
                Statement(
                    f"INSERT INTO users ({','.join(columns)}) VALUES ({','.join('?' for _ in columns)}) "
                    "ON CONFLICT(username_key) DO NOTHING",
                    params,
                ),
                Statement(
                    "INSERT INTO login_aliases (user_id,alias,alias_key,source,created_at,updated_at) "
                    "SELECT ?,?,?,?,?,? WHERE EXISTS (SELECT 1 FROM users WHERE id=?)",
                    [
                        user_id,
                        values["username"],
                        values["username_key"],
                        "central",
                        now,
                        now,
                        user_id,
                    ],
                ),
                Statement(
                    "INSERT INTO audit_logs (actor_user_id,target_user_id,action,ip_address,details_json,created_at) "
                    "SELECT ?,?,?,?,?,? WHERE EXISTS (SELECT 1 FROM users WHERE id=?)",
                    [actor_id, user_id, audit_action, ip, "{}", now, user_id],
                ),
            ]
        )
        if not results or int(results[0].get("meta", {}).get("changes", 0)) != 1:
            raise AccountConflictError("用户名已存在")
        return D1AccountRepository._user(dict(zip(columns, params, strict=True)))

    def upsert_oauth_client(
        self,
        *,
        client_id: str,
        client_secret_hash: str,
        issued_at: int,
        launch_uri: str,
        backchannel_logout_uri: str,
        metadata: dict,
    ) -> None:
        now = datetime.now().isoformat(sep=" ")
        client_pk = secrets.randbelow(2**62 - 1) + 1
        self.client.execute(
            "INSERT INTO oauth2_clients "
            "(id,launch_uri,backchannel_logout_uri,is_active,client_id,client_secret,"
            "client_id_issued_at,client_secret_expires_at,client_metadata,created_at,updated_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(client_id) DO UPDATE SET "
            "launch_uri=excluded.launch_uri,backchannel_logout_uri=excluded.backchannel_logout_uri,"
            "is_active=1,client_secret=excluded.client_secret,client_secret_expires_at=0,"
            "client_metadata=excluded.client_metadata,updated_at=excluded.updated_at",
            [
                client_pk,
                launch_uri,
                backchannel_logout_uri,
                1,
                client_id,
                client_secret_hash,
                issued_at,
                0,
                json.dumps(metadata, ensure_ascii=False, separators=(",", ":")),
                now,
                now,
            ],
        )

    def audit_logs(self, limit=200):
        rows = (
            self.client.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", [limit]).get(
                "rows"
            )
            or []
        )
        result = []
        for row in rows:
            item = AuditLog()
            for key, value in row.items():
                if key == "created_at" and isinstance(value, str):
                    value = datetime.fromisoformat(value)
                if hasattr(AuditLog, key):
                    setattr(item, key, value)
            result.append(item)
        return result

    def backchannel_jobs(self, limit=200):
        rows = (
            self.client.execute(
                "SELECT * FROM backchannel_jobs ORDER BY id DESC LIMIT ?", [limit]
            ).get("rows")
            or []
        )
        result = []
        for row in rows:
            item = BackchannelJob()
            for key, value in row.items():
                if key in {"next_attempt_at", "created_at", "delivered_at"} and isinstance(
                    value, str
                ):
                    value = datetime.fromisoformat(value)
                if hasattr(BackchannelJob, key):
                    setattr(item, key, value)
            result.append(item)
        return result

    def backchannel_counts(self):
        rows = (
            self.client.execute(
                "SELECT status,COUNT(*) AS count FROM backchannel_jobs GROUP BY status"
            ).get("rows")
            or []
        )
        return {row["status"]: int(row["count"]) for row in rows}

    def delete_user(self, user_id: int, *, actor_id: int, ip: str):
        rows = (
            self.client.execute("SELECT * FROM users WHERE id=? LIMIT 1", [user_id]).get("rows")
            or []
        )
        if not rows:
            return None, "not_found"
        target = D1AccountRepository._user(rows[0])
        if target.is_active:
            return target, "active"
        if self.client.execute(
            "SELECT 1 AS found FROM users WHERE merged_into_user_id=? LIMIT 1", [user_id]
        ).get("rows"):
            return target, "merge_target"
        pending = (
            self.client.execute(
                "SELECT COUNT(*) AS count FROM backchannel_jobs WHERE user_id=? AND status<>'delivered'",
                [user_id],
            ).get("rows")
            or []
        )
        if pending and int(pending[0]["count"]):
            return target, "pending_logout"

        now = datetime.now().isoformat(sep=" ")
        eligibility = (
            "EXISTS (SELECT 1 FROM users u WHERE u.id=? AND u.is_active=0 "
            "AND NOT EXISTS (SELECT 1 FROM users child WHERE child.merged_into_user_id=u.id) "
            "AND NOT EXISTS (SELECT 1 FROM backchannel_jobs j WHERE j.user_id=u.id AND j.status<>'delivered'))"
        )
        statements = [
            Statement(
                "UPDATE users SET updated_at=updated_at WHERE id=? AND is_active=0 "
                "AND NOT EXISTS (SELECT 1 FROM users child WHERE child.merged_into_user_id=users.id) "
                "AND NOT EXISTS (SELECT 1 FROM backchannel_jobs j WHERE j.user_id=users.id AND j.status<>'delivered')",
                [user_id],
            ),
            Statement(
                f"UPDATE audit_logs SET actor_user_id=NULL WHERE actor_user_id=? AND {eligibility}",
                [user_id, user_id],
            ),
            Statement(
                f"UPDATE audit_logs SET target_user_id=NULL WHERE target_user_id=? AND {eligibility}",
                [user_id, user_id],
            ),
            Statement(
                f"INSERT INTO audit_logs (actor_user_id,target_user_id,action,ip_address,details_json,created_at) "
                f"SELECT ?,NULL,?,?,?,? WHERE {eligibility}",
                [
                    actor_id,
                    "admin.user_deleted",
                    ip,
                    json.dumps(
                        {"targetSub": target.sub, "targetUsername": target.username},
                        ensure_ascii=False,
                        separators=(",", ":"),
                    ),
                    now,
                    user_id,
                ],
            ),
        ]
        for table in (
            "oauth2_authorization_codes",
            "oauth2_tokens",
            "web_sessions",
            "user_app_memberships",
            "login_aliases",
            "legacy_credentials",
            "backchannel_jobs",
        ):
            statements.append(
                Statement(
                    f"DELETE FROM {table} WHERE user_id=? AND {eligibility}", [user_id, user_id]
                )
            )
        statements.append(
            Statement(
                "DELETE FROM users WHERE id=? AND is_active=0 "
                "AND NOT EXISTS (SELECT 1 FROM users child WHERE child.merged_into_user_id=users.id) "
                "AND NOT EXISTS (SELECT 1 FROM backchannel_jobs j WHERE j.user_id=users.id AND j.status<>'delivered')",
                [user_id],
            )
        )
        results = self.client.batch(statements)
        if (
            not results
            or int(results[0].get("meta", {}).get("changes", 0)) != 1
            or int(results[-1].get("meta", {}).get("changes", 0)) != 1
        ):
            return target, "changed"
        return target, None

    def merge_users(self, source_id: int, target_id: int, *, actor_id: int, ip: str):
        rows = (
            self.client.execute(
                "SELECT * FROM users WHERE id IN (?,?) ORDER BY id", [source_id, target_id]
            ).get("rows")
            or []
        )
        by_id = {int(row["id"]): D1AccountRepository._user(row) for row in rows}
        source = by_id.get(source_id)
        target = by_id.get(target_id)
        if source is None or target is None:
            return source, target, "not_found"
        if source_id == target_id or source.merged_into_user_id or target.merged_into_user_id:
            return source, target, "invalid"

        now = datetime.now().isoformat(sep=" ")
        eligible = (
            "EXISTS (SELECT 1 FROM users s JOIN users t ON t.id=? "
            "WHERE s.id=? AND s.merged_into_user_id IS NULL AND t.merged_into_user_id IS NULL AND s.id<>t.id)"
        )
        statements = [
            Statement(
                "UPDATE users SET updated_at=updated_at WHERE id=? AND merged_into_user_id IS NULL "
                "AND EXISTS (SELECT 1 FROM users t WHERE t.id=? AND t.merged_into_user_id IS NULL AND t.id<>users.id)",
                [source_id, target_id],
            ),
            Statement(
                f"INSERT INTO backchannel_jobs (user_id,client_id,sid,reason,status,attempts,last_error,next_attempt_at,created_at,delivered_at) "
                f"SELECT ?,m.client_id,NULL,'account_merged','pending',0,'',?,?,NULL FROM user_app_memberships m "
                f"JOIN oauth2_clients c ON c.client_id=m.client_id WHERE m.user_id=? AND c.is_active=1 "
                f"AND c.backchannel_logout_uri<>'' AND {eligible}",
                [source_id, now, now, source_id, target_id, source_id],
            ),
            Statement(
                f"UPDATE login_aliases SET user_id=?,updated_at=? WHERE user_id=? AND {eligible}",
                [target_id, now, source_id, target_id, source_id],
            ),
            Statement(
                f"UPDATE legacy_credentials SET user_id=?,updated_at=? WHERE user_id=? AND {eligible}",
                [target_id, now, source_id, target_id, source_id],
            ),
            Statement(
                f"INSERT INTO user_app_memberships (user_id,client_id,first_authorized_at,last_authorized_at) "
                f"SELECT ?,m.client_id,m.first_authorized_at,m.last_authorized_at FROM user_app_memberships m "
                f"WHERE m.user_id=? AND {eligible} ON CONFLICT(user_id,client_id) DO UPDATE SET "
                "first_authorized_at=MIN(user_app_memberships.first_authorized_at,excluded.first_authorized_at),"
                "last_authorized_at=MAX(user_app_memberships.last_authorized_at,excluded.last_authorized_at)",
                [target_id, source_id, target_id, source_id],
            ),
            Statement(
                f"DELETE FROM user_app_memberships WHERE user_id=? AND {eligible}",
                [source_id, target_id, source_id],
            ),
            Statement(
                f"UPDATE web_sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL AND {eligible}",
                [now, source_id, target_id, source_id],
            ),
            Statement(
                f"UPDATE oauth2_tokens SET access_token_revoked_at=? WHERE user_id=? AND access_token_revoked_at=0 AND {eligible}",
                [int(datetime.now().timestamp()), source_id, target_id, source_id],
            ),
            Statement(
                f"UPDATE users SET is_system_admin=1,updated_at=? WHERE id=? AND EXISTS (SELECT 1 FROM users s WHERE s.id=? AND s.is_system_admin=1) AND {eligible}",
                [now, target_id, source_id, target_id, source_id],
            ),
            Statement(
                f"INSERT INTO audit_logs (actor_user_id,target_user_id,action,ip_address,details_json,created_at) "
                f"SELECT ?,?,?,?,?,? WHERE {eligible}",
                [
                    actor_id,
                    target_id,
                    "admin.users_merged",
                    ip,
                    json.dumps({"sourceSub": source.sub}, separators=(",", ":")),
                    now,
                    target_id,
                    source_id,
                ],
            ),
            Statement(
                "UPDATE users SET is_system_admin=0,is_active=0,merged_into_user_id=?,updated_at=? "
                "WHERE id=? AND merged_into_user_id IS NULL AND EXISTS "
                "(SELECT 1 FROM users t WHERE t.id=? AND t.merged_into_user_id IS NULL AND t.id<>users.id)",
                [target_id, now, source_id, target_id],
            ),
        ]
        results = self.client.batch(statements)
        if (
            not results
            or int(results[0].get("meta", {}).get("changes", 0)) != 1
            or int(results[-1].get("meta", {}).get("changes", 0)) != 1
        ):
            return source, target, "changed"
        return source, target, None


def admin_repository():
    from flask import current_app

    return D1AdminRepository(current_app.extensions["d1_gateway_client"])
