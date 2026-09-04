from __future__ import annotations

import base64
import hashlib
import json
import secrets
import sqlite3

from sqlalchemy import select
from werkzeug.security import generate_password_hash

from app.extensions import db
from app.migration_tool import apply_plan, build_plan, load_sources, write_plan
from app.models import LegacyCredential, User
from app.security import authenticate


def todo_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 260_000)
    return "$".join(
        [
            "pbkdf2_sha256",
            "260000",
            base64.urlsafe_b64encode(salt).decode().rstrip("="),
            base64.urlsafe_b64encode(digest).decode().rstrip("="),
        ]
    )


def source_databases(tmp_path, *, collision=False):
    todo = tmp_path / "todo.sqlite3"
    with sqlite3.connect(todo) as connection:
        connection.execute(
            "CREATE TABLE users ("
            "id INTEGER, nickname TEXT, name TEXT, role TEXT, password_hash TEXT)"
        )
        connection.execute(
            "INSERT INTO users VALUES (1, 'alice', 'Alice Todo', 'admin', ?)",
            (todo_hash("todo-password"),),
        )
    techx = tmp_path / "techx.sqlite3"
    with sqlite3.connect(techx) as connection:
        connection.execute(
            "CREATE TABLE users (id INTEGER, nickname TEXT, real_name TEXT, "
            "is_admin INTEGER, password_hash TEXT)"
        )
        connection.execute(
            "INSERT INTO users VALUES (2, ?, 'Bob TechX', 0, ?)",
            ("Alice" if collision else "bob", generate_password_hash("techx-password")),
        )
    return todo, techx


def test_dry_run_does_not_expose_hashes(tmp_path):
    todo, techx = source_databases(tmp_path, collision=True)
    plan = build_plan(load_sources(todo, techx))
    encoded = json.dumps(plan)
    assert "pbkdf2_sha256$" not in encoded
    assert "scrypt:" not in encoded
    assert plan["summary"]["unresolved_groups"] == 1


def test_apply_is_idempotent_and_upgrades_legacy_password(app, tmp_path):
    todo, techx = source_databases(tmp_path)
    items = load_sources(todo, techx)
    plan = build_plan(items)
    plan_path = tmp_path / "plan.json"
    mapping_path = tmp_path / "mapping.json"
    write_plan(plan, plan_path)
    with app.app_context():
        first = apply_plan(plan_path, items, mapping_path)
        second = apply_plan(plan_path, items, mapping_path)
        assert first == second
        assert len(db.session.scalars(select(User)).all()) == 2
        assert len(db.session.scalars(select(LegacyCredential)).all()) == 2
        user = authenticate("ALICE", "todo-password")
        assert user is not None
        assert user.password_hash.startswith("$argon2")
        assert not db.session.scalars(
            select(LegacyCredential).where(LegacyCredential.user_id == user.id)
        ).all()
        apply_plan(plan_path, items, mapping_path)
        assert not db.session.scalars(
            select(LegacyCredential).where(LegacyCredential.user_id == user.id)
        ).all()
