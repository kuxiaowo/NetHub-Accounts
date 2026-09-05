from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

from sqlalchemy import select

from .avatars import (
    AvatarError,
    _decode_and_compress,
    delete_avatar_file,
    normalize_avatar_color,
    store_avatar,
)
from .extensions import db
from .models import User, utc_now


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON 顶层必须是对象：{path}")
    return value


def build_avatar_plan(
    *,
    mapping_path: Path,
    todo_db: Path | None = None,
    todo_avatar_dir: Path | None = None,
    wiki_manifest: Path | None = None,
) -> dict[str, Any]:
    mapping = _read_json(mapping_path)
    todo_subjects = {
        str(item["source_user_id"]): str(item["central_sub"])
        for item in mapping.get("mappings", [])
        if item.get("source_app") == "todo"
    }
    candidates: dict[str, dict[str, Any]] = {}
    errors: list[dict[str, str]] = []
    conflicts: list[dict[str, str]] = []

    if todo_db:
        if not todo_avatar_dir:
            raise ValueError("提供 --todo-db 时必须同时提供 --todo-avatar-dir")
        connection = sqlite3.connect(f"file:{todo_db.resolve().as_posix()}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            rows = connection.execute(
                "SELECT id, avatar_file, avatar_color FROM users ORDER BY id"
            ).fetchall()
        finally:
            connection.close()
        for row in rows:
            subject = todo_subjects.get(str(row["id"]))
            if not subject:
                errors.append({"source": f"todo:{row['id']}", "reason": "missing_mapping"})
                continue
            candidate = candidates.setdefault(subject, {"central_sub": subject})
            candidate["avatar_color"] = normalize_avatar_color(row["avatar_color"])
            filename = str(row["avatar_file"] or "").strip()
            if filename:
                path = (todo_avatar_dir / filename).resolve()
                if path.parent != todo_avatar_dir.resolve() or not path.is_file():
                    errors.append({"source": f"todo:{row['id']}", "reason": "missing_avatar_file"})
                else:
                    candidate["todo_image"] = str(path)

    if wiki_manifest:
        manifest = _read_json(wiki_manifest)
        for item in manifest.get("errors", []):
            errors.append(
                {
                    "source": str(item.get("source") or "wiki"),
                    "reason": str(item.get("reason") or "manifest_error"),
                }
            )
        for item in manifest.get("avatars", []):
            subject = str(item.get("central_sub") or "").strip()
            path = Path(str(item.get("avatar_path") or ""))
            if not subject:
                errors.append({"source": "wiki", "reason": "missing_central_sub"})
            elif not path.is_file():
                errors.append({"source": f"wiki:{subject}", "reason": "missing_avatar_file"})
            else:
                candidates.setdefault(subject, {"central_sub": subject})["wiki_image"] = str(
                    path.resolve()
                )

    entries = []
    for subject, candidate in sorted(candidates.items()):
        if candidate.get("wiki_image") and candidate.get("todo_image"):
            conflicts.append(
                {
                    "central_sub": subject,
                    "selected": "wiki",
                    "discarded": "todo",
                }
            )
        source_path = candidate.get("wiki_image") or candidate.get("todo_image")
        entry = {
            "central_sub": subject,
            "source": "wiki" if candidate.get("wiki_image") else "todo" if source_path else "color",
            "avatar_path": source_path,
            "avatar_color": candidate.get("avatar_color", "#6366f1"),
        }
        if source_path:
            raw = Path(source_path).read_bytes()
            entry["source_sha256"] = hashlib.sha256(raw).hexdigest()
            try:
                _decode_and_compress(raw)
            except AvatarError as exc:
                errors.append(
                    {
                        "source": f"{entry['source']}:{subject}",
                        "reason": "invalid_avatar_file",
                        "detail": str(exc),
                    }
                )
        entries.append(entry)
    return {
        "version": 1,
        "summary": {
            "ready": len(entries),
            "errors": len(errors),
            "conflicts": len(conflicts),
        },
        "entries": entries,
        "errors": errors,
        "conflicts": conflicts,
    }


def apply_avatar_plan(plan_path: Path) -> dict[str, int]:
    plan = _read_json(plan_path)
    if plan.get("version") != 1:
        raise ValueError("不支持的头像迁移计划版本")
    if plan.get("errors"):
        raise ValueError("头像迁移计划仍包含错误，请先处理后重新生成")
    result = {"imported": 0, "colors": 0, "skipped": 0}
    created_files: list[tuple[User, str]] = []
    try:
        for entry in plan.get("entries", []):
            user = db.session.scalar(select(User).where(User.sub == entry["central_sub"]))
            if user is None:
                raise ValueError(f"Accounts 中找不到用户：{entry['central_sub']}")
            source_path = entry.get("avatar_path")
            # Any timestamp/file means the user has already exercised the Accounts
            # avatar controls. Never undo that choice, including an explicit delete.
            if user.avatar_updated_at is not None or user.avatar_file:
                result["skipped"] += 1
                continue
            color = normalize_avatar_color(entry.get("avatar_color"))
            if user.avatar_color == "#6366f1" and color != user.avatar_color:
                user.avatar_color = color
                user.avatar_updated_at = utc_now()
                result["colors"] += 1
            if not source_path:
                continue
            path = Path(source_path)
            raw = path.read_bytes()
            if hashlib.sha256(raw).hexdigest() != entry.get("source_sha256"):
                raise ValueError(f"头像源文件在 dry-run 后发生变化：{path}")
            filename = store_avatar(user, raw)
            created_files.append((user, filename))
            user.avatar_file = filename
            user.avatar_updated_at = utc_now()
            result["imported"] += 1
        db.session.commit()
    except Exception:
        db.session.rollback()
        for user, filename in created_files:
            delete_avatar_file(user, filename)
        raise
    return result
