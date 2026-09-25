"""Account reads and registration writes for SQLite and the D1 gateway."""
from __future__ import annotations

import secrets
import uuid
import json
from datetime import datetime
from typing import Any

from sqlalchemy import select

from .d1_gateway import D1GatewayClient, Statement
from .extensions import db
from .models import LegacyCredential, LoginAlias, User


class AccountRepository:
    def find_login(self, alias_key: str): ...
    def register(self, values: dict[str, Any], session_values: dict[str, Any], *, ip: str): ...
    def get_user(self, user_id: int): ...
    def active_admin_count(self) -> int: ...
    def update_profile(self, user_id: int, display_name: str, *, ip: str) -> bool: ...
    def change_password(self, user_id: int, password_hash: str, session_values: dict[str, Any], *, ip: str) -> bool: ...
    def account_details(self, user_id: int): ...
    def update_avatar(self, user_id: int, *, avatar_file: str | None, action: str, ip: str) -> bool: ...
    def update_avatar_color(self, user_id: int, color: str, *, ip: str) -> bool: ...
    def find_by_sub(self, subject: str): ...
    def logout_all(self, user_id: int, *, ip: str) -> None: ...
    def home_data(self, user_id: int | None): ...


class AccountConflictError(RuntimeError):
    pass


class SQLiteAccountRepository(AccountRepository):
    def get_user(self, user_id):
        return db.session.get(User, user_id)

    def active_admin_count(self):
        from sqlalchemy import func
        return int(db.session.scalar(select(func.count(User.id)).where(User.is_system_admin.is_(True), User.is_active.is_(True))) or 0)

    def find_login(self, alias_key):
        alias = db.session.scalar(select(LoginAlias).where(LoginAlias.alias_key == alias_key))
        if alias is None:
            return None
        user = alias.user
        legacy = db.session.scalars(select(LegacyCredential).where(
            LegacyCredential.user_id == user.id,
            LegacyCredential.login_alias_key == alias_key,
            LegacyCredential.is_active.is_(True),
        )).all()
        return user, legacy

    def register(self, values, session_values, *, ip):
        from .models import AuditLog, RateLimitEvent, WebSession
        user = User(**values)
        db.session.add(user); db.session.flush()
        db.session.add(LoginAlias(user_id=user.id, alias=values["username"], alias_key=values["username_key"], source="central"))
        db.session.add(RateLimitEvent(action="register", subject=ip, succeeded=True))
        db.session.add(AuditLog(target_user_id=user.id, action="auth.register", ip_address=ip, details_json="{}"))
        item = WebSession(user_id=user.id, **session_values)
        db.session.add(item); db.session.flush()
        return user, item

    def account_details(self, user_id):
        from .models import AppMembership, OAuth2Client
        memberships = db.session.execute(
            select(AppMembership, OAuth2Client)
            .join(OAuth2Client, OAuth2Client.client_id == AppMembership.client_id)
            .where(AppMembership.user_id == user_id)
            .order_by(AppMembership.first_authorized_at)
        ).all()
        aliases = db.session.scalars(
            select(LoginAlias).where(LoginAlias.user_id == user_id).order_by(LoginAlias.id)
        ).all()
        return memberships, aliases

    def find_by_sub(self, subject):
        return db.session.scalar(select(User).where(User.sub == subject))


class D1AccountRepository(AccountRepository):
    def __init__(self, client: D1GatewayClient): self.client = client

    @staticmethod
    def _user(row):
        item = User()
        for key, value in row.items():
            if key in {"avatar_updated_at", "terms_accepted_at", "created_at", "updated_at"} and isinstance(value, str):
                value = datetime.fromisoformat(value)
            if key in {"is_active", "is_system_admin", "must_change_password"} and value is not None:
                value = bool(value)
            if hasattr(User, key): setattr(item, key, value)
        return item

    def find_login(self, alias_key):
        rows = self.client.execute("SELECT u.*, la.alias_key FROM login_aliases la JOIN users u ON u.id=la.user_id WHERE la.alias_key=? LIMIT 1", [alias_key]).get("rows") or []
        if not rows: return None
        row = rows[0]; user = self._user(row)
        legacy_rows = self.client.execute("SELECT * FROM legacy_credentials WHERE user_id=? AND login_alias_key=? AND is_active=1", [row["id"], alias_key]).get("rows") or []
        legacy = [type("LegacyDTO", (), r)() for r in legacy_rows]
        return user, legacy

    def get_user(self, user_id):
        rows = self.client.execute("SELECT * FROM users WHERE id=? LIMIT 1", [user_id]).get("rows") or []
        return self._user(rows[0]) if rows else None

    def active_admin_count(self):
        rows = self.client.execute("SELECT COUNT(*) AS count FROM users WHERE is_system_admin=1 AND is_active=1").get("rows") or []
        return int(rows[0]["count"]) if rows else 0

    @staticmethod
    def _scalar(value):
        return value.isoformat(sep=" ") if isinstance(value, datetime) else value

    @staticmethod
    def _audit(action, user_id, ip, now, details=None):
        return Statement(
            "INSERT INTO audit_logs (actor_user_id,target_user_id,action,ip_address,details_json,created_at) "
            "SELECT ?,?,?,?,?,? WHERE EXISTS (SELECT 1 FROM users WHERE id=?)",
            [user_id, user_id, action, ip, json.dumps(details or {}, ensure_ascii=False, separators=(",", ":")), now, user_id],
        )

    def update_profile(self, user_id, display_name, *, ip):
        now = datetime.now().isoformat(sep=" ")
        results = self.client.batch([
            Statement("UPDATE users SET display_name=?,updated_at=? WHERE id=?", [display_name, now, user_id]),
            self._audit("account.profile_updated", user_id, ip, now),
        ])
        return bool(results and int(results[0].get("meta", {}).get("changes", 0)) == 1)

    def change_password(self, user_id, password_hash, session_values, *, ip):
        now = datetime.now().isoformat(sep=" ")
        columns = ["sid", "token_hash", "user_id", "csrf_token", "auth_time", "created_at", "last_seen_at", "idle_expires_at", "absolute_expires_at"]
        session_params = [self._scalar(session_values.get(column)) for column in columns]
        results = self.client.batch([
            Statement("UPDATE users SET password_hash=?,must_change_password=0,updated_at=? WHERE id=?", [password_hash, now, user_id]),
            Statement("DELETE FROM legacy_credentials WHERE user_id=?", [user_id]),
            Statement("UPDATE web_sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL", [now, user_id]),
            Statement("UPDATE oauth2_tokens SET access_token_revoked_at=? WHERE user_id=? AND access_token_revoked_at=0", [int(datetime.now().timestamp()), user_id]),
            self._audit("account.password_changed", user_id, ip, now),
            Statement(
                f"INSERT INTO web_sessions ({','.join(columns)}) SELECT {','.join('?' for _ in columns)} "
                "WHERE EXISTS (SELECT 1 FROM users WHERE id=?)",
                [*session_params, user_id],
            ),
        ])
        return bool(results and int(results[0].get("meta", {}).get("changes", 0)) == 1)

    def account_details(self, user_id):
        from .models import AppMembership, OAuth2Client
        rows = self.client.execute(
            "SELECT m.id,m.user_id,m.client_id,m.first_authorized_at,m.last_authorized_at,"
            "c.client_metadata,c.is_active FROM user_app_memberships m JOIN oauth2_clients c "
            "ON c.client_id=m.client_id WHERE m.user_id=? ORDER BY m.first_authorized_at",
            [user_id],
        ).get("rows") or []
        memberships = []
        for row in rows:
            membership = AppMembership()
            for key in ("id", "user_id", "client_id", "first_authorized_at", "last_authorized_at"):
                setattr(membership, key, row.get(key))
            client = OAuth2Client()
            client.client_id = row.get("client_id")
            client.set_client_metadata(json.loads(row.get("client_metadata") or "{}"))
            client.is_active = bool(row.get("is_active"))
            memberships.append((membership, client))
        alias_rows = self.client.execute(
            "SELECT id,user_id,alias,alias_key,source,created_at,updated_at FROM login_aliases "
            "WHERE user_id=? ORDER BY id",
            [user_id],
        ).get("rows") or []
        aliases = []
        for row in alias_rows:
            alias = LoginAlias()
            for key, value in row.items():
                if hasattr(LoginAlias, key):
                    setattr(alias, key, value)
            aliases.append(alias)
        return memberships, aliases

    def update_avatar(self, user_id, *, avatar_file, action, ip):
        if action not in {"account.avatar_updated", "account.avatar_deleted"}:
            raise ValueError("invalid avatar audit action")
        now = datetime.now().isoformat(sep=" ")
        results = self.client.batch([
            Statement("UPDATE users SET avatar_file=?,avatar_updated_at=?,updated_at=? WHERE id=?", [avatar_file, now, now, user_id]),
            self._audit(action, user_id, ip, now),
        ])
        return bool(results and int(results[0].get("meta", {}).get("changes", 0)) == 1)

    def update_avatar_color(self, user_id, color, *, ip):
        now = datetime.now().isoformat(sep=" ")
        results = self.client.batch([
            Statement("UPDATE users SET avatar_color=?,avatar_updated_at=?,updated_at=? WHERE id=?", [color, now, now, user_id]),
            self._audit("account.avatar_color_updated", user_id, ip, now),
        ])
        return bool(results and int(results[0].get("meta", {}).get("changes", 0)) == 1)

    def find_by_sub(self, subject):
        rows = self.client.execute("SELECT * FROM users WHERE sub=? LIMIT 1", [subject]).get("rows") or []
        return self._user(rows[0]) if rows else None

    def logout_all(self, user_id, *, ip):
        now = datetime.now().isoformat(sep=" ")
        self.client.batch([
            Statement("UPDATE web_sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL", [now, user_id]),
            Statement("UPDATE oauth2_tokens SET access_token_revoked_at=? WHERE user_id=? AND access_token_revoked_at=0", [int(datetime.now().timestamp()), user_id]),
            self._audit("auth.logout_all", user_id, ip, now),
        ])

    def home_data(self, user_id):
        from .models import OAuth2Client

        rows = self.client.execute(
            "SELECT * FROM oauth2_clients WHERE is_active=1 ORDER BY id"
        ).get("rows") or []
        clients = []
        for row in rows:
            item = OAuth2Client()
            for key, value in row.items():
                if key == "client_metadata":
                    item.set_client_metadata(json.loads(value or "{}"))
                    continue
                if key == "is_active" and value is not None:
                    value = bool(value)
                if hasattr(OAuth2Client, key):
                    setattr(item, key, value)
            clients.append(item)
        memberships = set()
        if user_id is not None:
            membership_rows = self.client.execute(
                "SELECT client_id FROM user_app_memberships WHERE user_id=?", [user_id]
            ).get("rows") or []
            memberships = {row["client_id"] for row in membership_rows}
        return clients, memberships

    def set_user_active(self, user_id, expected_active, new_active, actor_id, ip):
        now = datetime.now().isoformat(sep=" ")
        statements = [Statement("UPDATE users SET is_active=?,updated_at=? WHERE id=? AND is_active=?", [int(new_active), now, user_id, int(expected_active)])]
        if not new_active:
            statements.extend([
                Statement("UPDATE web_sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL", [now, user_id]),
                Statement("UPDATE oauth2_tokens SET access_token_revoked_at=? WHERE user_id=? AND access_token_revoked_at=0", [int(datetime.now().timestamp()), user_id]),
            ])
        statements.append(Statement("INSERT INTO audit_logs (actor_user_id,target_user_id,action,ip_address,details_json,created_at) SELECT ?,?,?,?,?,? WHERE EXISTS (SELECT 1 FROM users WHERE id=? AND is_active=?)", [actor_id, user_id, "admin.user_toggled", ip, '{"isActive":' + ("true" if new_active else "false") + '}', now, user_id, int(new_active)]))
        results = self.client.batch(statements)
        return bool(results and int(results[0].get("meta", {}).get("changes", 0)) == 1)

    def reset_password(self, user_id, password_hash, actor_id, ip):
        now = datetime.now().isoformat(sep=" ")
        results = self.client.batch([
            Statement("UPDATE users SET password_hash=?,must_change_password=1,updated_at=? WHERE id=?", [password_hash, now, user_id]),
            Statement("DELETE FROM legacy_credentials WHERE user_id=?", [user_id]),
            Statement("UPDATE web_sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL", [now, user_id]),
            Statement("UPDATE oauth2_tokens SET access_token_revoked_at=? WHERE user_id=? AND access_token_revoked_at=0", [int(datetime.now().timestamp()), user_id]),
            Statement("INSERT INTO audit_logs (actor_user_id,target_user_id,action,ip_address,details_json,created_at) SELECT ?,?,?,?,?,? WHERE EXISTS (SELECT 1 FROM users WHERE id=?)", [actor_id, user_id, "admin.password_reset", ip, "{}", now, user_id]),
        ])
        return bool(results and int(results[0].get("meta", {}).get("changes", 0)) == 1)

    def register(self, values, session_values, *, ip):
        now = datetime.now().isoformat(sep=" ")
        values = {
            "id": secrets.randbelow(2**62 - 1) + 1,
            "sub": str(uuid.uuid4()),
            "avatar_color": "#6366f1",
            "is_active": 1,
            "is_system_admin": 0,
            "must_change_password": 0,
            **values,
        }
        uid = values["id"]
        cols = list(values) + ["created_at", "updated_at"]
        params = [self._scalar(values[c]) for c in values] + [now, now]
        user_insert = Statement(
            f"INSERT INTO users ({', '.join(cols)}) VALUES ({', '.join('?' for _ in cols)}) "
            "ON CONFLICT(username_key) DO NOTHING",
            params,
        )
        statements = [
            user_insert,
            Statement("INSERT INTO login_aliases (user_id,alias,alias_key,source,created_at,updated_at) SELECT ?,?,?,?,?,? WHERE EXISTS (SELECT 1 FROM users WHERE id=?)", [uid, values["username"], values["username_key"], "central", now, now, uid]),
            Statement("INSERT INTO rate_limit_events (action,subject,succeeded,created_at) SELECT ?,?,1,? WHERE EXISTS (SELECT 1 FROM users WHERE id=?)", ["register", ip, now, uid]),
            Statement("INSERT INTO audit_logs (target_user_id,action,ip_address,details_json,created_at) SELECT ?,?,?,?,? WHERE EXISTS (SELECT 1 FROM users WHERE id=?)", [uid, "auth.register", ip, "{}", now, uid]),
        ]
        sc = ["sid","token_hash","user_id","csrf_token","auth_time","created_at","last_seen_at","idle_expires_at","absolute_expires_at"]
        session_params = [self._scalar(session_values.get(c)) if c != "user_id" else uid for c in sc]
        statements.append(Statement(f"INSERT INTO web_sessions ({','.join(sc)}) SELECT {','.join('?' for _ in sc)} WHERE EXISTS (SELECT 1 FROM users WHERE id=?)", [*session_params, uid]))
        results = self.client.batch(statements)
        if not results or int(results[0].get("meta", {}).get("changes", 0)) != 1:
            raise AccountConflictError("用户名已存在。")
        return self._user(values), session_values


def account_repository():
    from flask import current_app
    if current_app.config.get("ACCOUNTS_DATABASE_BACKEND") == "d1":
        client = current_app.extensions.get("d1_gateway_client")
        if client is not None: return D1AccountRepository(client)
    return SQLiteAccountRepository()
