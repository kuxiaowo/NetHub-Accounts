from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy import select

from .extensions import db
from .models import LegacyCredential, LoginAlias, User
from .security import normalize_imported_alias, normalize_username


@dataclass(frozen=True)
class SourceAccount:
    source_app: str
    source_user_id: str
    username: str
    display_name: str
    is_app_admin: bool
    password_hash: str
    algorithm: str

    def public_dict(self) -> dict[str, Any]:
        return {
            "source_app": self.source_app,
            "source_user_id": self.source_user_id,
            "username": self.username,
            "display_name": self.display_name,
            "is_app_admin": self.is_app_admin,
        }


def _readonly_connection(path: Path) -> sqlite3.Connection:
    if not path.is_file():
        raise ValueError(f"数据库备份不存在：{path}")
    connection = sqlite3.connect(f"file:{path.resolve().as_posix()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    return connection


def read_todo_accounts(path: Path) -> list[SourceAccount]:
    with _readonly_connection(path) as connection:
        rows = connection.execute(
            "SELECT id, nickname, name, role, password_hash FROM users ORDER BY id"
        ).fetchall()
    return [
        SourceAccount(
            source_app="todo",
            source_user_id=str(row["id"]),
            username=str(row["nickname"]),
            display_name=str(row["name"] or row["nickname"]),
            is_app_admin=row["role"] == "admin",
            password_hash=str(row["password_hash"]),
            algorithm="todo_pbkdf2_sha256",
        )
        for row in rows
    ]


def read_techx_accounts(path: Path) -> list[SourceAccount]:
    with _readonly_connection(path) as connection:
        rows = connection.execute(
            "SELECT id, nickname, real_name, is_admin, password_hash FROM users ORDER BY id"
        ).fetchall()
    return [
        SourceAccount(
            source_app="techx",
            source_user_id=str(row["id"]),
            username=str(row["nickname"]),
            # TechX real_name stays in TechX and is never propagated through OIDC.
            display_name=str(row["nickname"]),
            is_app_admin=bool(row["is_admin"]),
            password_hash=str(row["password_hash"]),
            algorithm="werkzeug",
        )
        for row in rows
    ]


def load_sources(todo_db: Path | None, techx_db: Path | None) -> list[SourceAccount]:
    items: list[SourceAccount] = []
    if todo_db:
        items.extend(read_todo_accounts(todo_db))
    if techx_db:
        items.extend(read_techx_accounts(techx_db))
    if not items:
        raise ValueError("至少需要提供一个 TodoList 或 TechX 数据库备份")
    return items


def _valid_hash(item: SourceAccount) -> bool:
    if item.algorithm == "todo_pbkdf2_sha256":
        parts = item.password_hash.split("$")
        return len(parts) == 4 and parts[0] == "pbkdf2_sha256" and parts[1].isdigit()
    if item.algorithm == "werkzeug":
        return item.password_hash.startswith(("scrypt:", "pbkdf2:"))
    return False


def build_plan(items: list[SourceAccount]) -> dict[str, Any]:
    grouped: dict[str, list[SourceAccount]] = {}
    invalid_accounts: list[dict[str, Any]] = []
    for item in items:
        try:
            _, key = normalize_imported_alias(item.username)
        except ValueError as exc:
            invalid_accounts.append({**item.public_dict(), "reason": str(exc)})
            continue
        if not _valid_hash(item):
            invalid_accounts.append({**item.public_dict(), "reason": "无法识别的密码哈希格式"})
        grouped.setdefault(key, []).append(item)

    identities = []
    unresolved = []
    for matches in grouped.values():
        public_sources = [{**item.public_dict(), "keep_login_alias": True} for item in matches]
        try:
            canonical, _ = normalize_username(matches[0].username)
        except ValueError:
            unresolved.append(
                {
                    "reason": "invalid_central_username",
                    "suggested_central_username": "",
                    "sources": public_sources,
                }
            )
            continue
        if len(matches) > 1:
            unresolved.append(
                {
                    "reason": "normalized_username_collision",
                    "suggested_central_username": canonical,
                    "sources": public_sources,
                }
            )
            continue
        identities.append(
            {
                "central_username": canonical,
                "display_name": matches[0].display_name[:80] or canonical,
                "sources": public_sources,
            }
        )
    return {
        "version": 1,
        "summary": {
            "total": len(items),
            "todo": sum(item.source_app == "todo" for item in items),
            "techx": sum(item.source_app == "techx" for item in items),
            "app_admins": sum(item.is_app_admin for item in items),
            "ready_identities": len(identities),
            "unresolved_groups": len(unresolved),
            "invalid_accounts": len(invalid_accounts),
        },
        "identities": identities,
        "unresolved": unresolved,
        "invalid_accounts": invalid_accounts,
    }


def write_plan(plan: dict[str, Any], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(plan, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _source_index(items: list[SourceAccount]) -> dict[tuple[str, str], SourceAccount]:
    return {(item.source_app, item.source_user_id): item for item in items}


def apply_plan(
    plan_path: Path,
    items: list[SourceAccount],
    mapping_output: Path,
) -> dict[str, Any]:
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    if plan.get("version") != 1:
        raise ValueError("不支持的迁移计划版本")
    if plan.get("unresolved") or plan.get("invalid_accounts"):
        raise ValueError("迁移计划仍包含 unresolved 或 invalid_accounts，请先人工处理")
    source_index = _source_index(items)
    invalid_hashes = [item.public_dict() for item in items if not _valid_hash(item)]
    if invalid_hashes:
        raise ValueError(f"数据库备份包含无法识别的密码哈希：{invalid_hashes}")
    seen_sources: set[tuple[str, str]] = set()
    mapping: list[dict[str, str]] = []

    try:
        for identity in plan.get("identities", []):
            central_username, username_key = normalize_username(identity["central_username"])
            display_name = str(identity.get("display_name") or central_username).strip()[:80]
            if not display_name:
                raise ValueError(f"{central_username} 的显示名称为空")
            user = db.session.scalar(select(User).where(User.username_key == username_key))
            if user is None:
                user = User(
                    username=central_username,
                    username_key=username_key,
                    display_name=display_name,
                    password_hash=None,
                    is_active=True,
                )
                db.session.add(user)
                db.session.flush()
                db.session.add(
                    LoginAlias(
                        user_id=user.id,
                        alias=central_username,
                        alias_key=username_key,
                        source="central",
                    )
                )
            for source_ref in identity.get("sources", []):
                source_key = (str(source_ref["source_app"]), str(source_ref["source_user_id"]))
                if source_key in seen_sources:
                    raise ValueError(f"来源账号重复出现在计划中：{source_key}")
                seen_sources.add(source_key)
                source = source_index.get(source_key)
                if source is None:
                    raise ValueError(f"数据库备份中找不到来源账号：{source_key}")
                alias_text, alias_key = normalize_imported_alias(source.username)
                keep_alias = bool(source_ref.get("keep_login_alias", True))
                login_key = alias_key if keep_alias else username_key
                if keep_alias:
                    existing_alias = db.session.scalar(
                        select(LoginAlias).where(LoginAlias.alias_key == alias_key)
                    )
                    if existing_alias and existing_alias.user_id != user.id:
                        raise ValueError(f"登录别名冲突：{alias_text}")
                    if existing_alias is None:
                        db.session.add(
                            LoginAlias(
                                user_id=user.id,
                                alias=alias_text,
                                alias_key=alias_key,
                                source=source.source_app,
                            )
                        )
                credential = db.session.scalar(
                    select(LegacyCredential).where(
                        LegacyCredential.source_app == source.source_app,
                        LegacyCredential.source_user_id == source.source_user_id,
                    )
                )
                if credential and credential.user_id != user.id:
                    raise ValueError(f"来源账号已经映射给其他中央用户：{source_key}")
                if credential is None and user.password_hash is None:
                    db.session.add(
                        LegacyCredential(
                            user_id=user.id,
                            source_app=source.source_app,
                            source_user_id=source.source_user_id,
                            login_alias_key=login_key,
                            algorithm=source.algorithm,
                            password_hash=source.password_hash,
                        )
                    )
                mapping.append(
                    {
                        "source_app": source.source_app,
                        "source_user_id": source.source_user_id,
                        "central_sub": user.sub,
                    }
                )
        expected_sources = {key for key in source_index}
        if seen_sources != expected_sources:
            missing = sorted(expected_sources - seen_sources)
            raise ValueError(f"迁移计划未覆盖全部来源账号：{missing}")
        db.session.commit()
    except Exception:
        db.session.rollback()
        raise

    result = {"version": 1, "mappings": mapping}
    write_plan(result, mapping_output)
    return result
