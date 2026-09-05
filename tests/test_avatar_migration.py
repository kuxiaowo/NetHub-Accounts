from __future__ import annotations

import io
import json
import sqlite3

from PIL import Image

from app.avatar_migration import apply_avatar_plan, build_avatar_plan
from app.extensions import db
from app.migration_tool import write_plan
from app.models import User, utc_now
from tests.conftest import create_user


def make_image(path, color):
    output = io.BytesIO()
    Image.new("RGB", (700, 900), color).save(output, format="PNG")
    path.write_bytes(output.getvalue())


def test_avatar_migration_prefers_wiki_and_is_idempotent(app, tmp_path):
    with app.app_context():
        user = create_user()
        user_id = user.id
        subject = user.sub
    mapping = tmp_path / "mapping.json"
    mapping.write_text(
        json.dumps(
            {
                "version": 1,
                "mappings": [
                    {"source_app": "todo", "source_user_id": "1", "central_sub": subject}
                ],
            }
        ),
        encoding="utf-8",
    )
    todo_db = tmp_path / "todo.sqlite3"
    with sqlite3.connect(todo_db) as connection:
        connection.execute(
            "CREATE TABLE users (id INTEGER, avatar_file TEXT, avatar_color TEXT)"
        )
        connection.execute("INSERT INTO users VALUES (1, 'todo.png', '#123456')")
    todo_dir = tmp_path / "todo-avatars"
    todo_dir.mkdir()
    make_image(todo_dir / "todo.png", "red")
    wiki_image = tmp_path / "wiki.png"
    make_image(wiki_image, "blue")
    wiki_manifest = tmp_path / "wiki.json"
    wiki_manifest.write_text(
        json.dumps(
            {
                "version": 1,
                "avatars": [{"central_sub": subject, "avatar_path": str(wiki_image)}],
                "errors": [],
            }
        ),
        encoding="utf-8",
    )

    with app.app_context():
        plan = build_avatar_plan(
            mapping_path=mapping,
            todo_db=todo_db,
            todo_avatar_dir=todo_dir,
            wiki_manifest=wiki_manifest,
        )
        assert plan["summary"] == {"ready": 1, "errors": 0, "conflicts": 1}
        assert plan["entries"][0]["source"] == "wiki"
        plan_path = tmp_path / "avatar-plan.json"
        write_plan(plan, plan_path)
        assert apply_avatar_plan(plan_path) == {"imported": 1, "colors": 1, "skipped": 0}
        migrated = db.session.get(User, user_id)
        migrated_file = migrated.avatar_file
        assert migrated.avatar_color == "#123456"
        assert (app.config["AVATAR_UPLOAD_DIR"] / subject / migrated_file).is_file()
        assert apply_avatar_plan(plan_path) == {"imported": 0, "colors": 0, "skipped": 1}
        assert db.session.get(User, user_id).avatar_file == migrated_file


def test_avatar_migration_reports_errors_and_preserves_central_choice(app, tmp_path):
    with app.app_context():
        user = create_user()
        user.avatar_updated_at = utc_now()
        user.avatar_color = "#abcdef"
        subject = user.sub
        user_id = user.id
        db.session.commit()
    mapping = tmp_path / "mapping.json"
    mapping.write_text(
        json.dumps(
            {
                "mappings": [
                    {"source_app": "todo", "source_user_id": "1", "central_sub": subject}
                ]
            }
        ),
        encoding="utf-8",
    )
    todo_db = tmp_path / "todo.sqlite3"
    with sqlite3.connect(todo_db) as connection:
        connection.execute(
            "CREATE TABLE users (id INTEGER, avatar_file TEXT, avatar_color TEXT)"
        )
        connection.execute("INSERT INTO users VALUES (1, '', '#111111')")
        connection.execute("INSERT INTO users VALUES (2, 'missing.png', '#222222')")
    todo_dir = tmp_path / "todo-avatars"
    todo_dir.mkdir()

    with app.app_context():
        plan = build_avatar_plan(
            mapping_path=mapping,
            todo_db=todo_db,
            todo_avatar_dir=todo_dir,
        )
        assert {item["reason"] for item in plan["errors"]} == {"missing_mapping"}
        # Remove the unresolved legacy row and apply the valid color-only entry.
        plan["errors"] = []
        plan["summary"]["errors"] = 0
        plan_path = tmp_path / "avatar-plan.json"
        write_plan(plan, plan_path)
        assert apply_avatar_plan(plan_path)["skipped"] == 1
        assert db.session.get(User, user_id).avatar_color == "#abcdef"
