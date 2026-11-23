from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import text

from app.extensions import db


def test_accounts_migration_has_one_head_and_upgrades_clean_database(app, monkeypatch):
    monkeypatch.setenv("TURNSTILE_SITE_KEY", "local-migration-test-site")
    monkeypatch.setenv("TURNSTILE_SECRET_KEY", "local-migration-test-secret")
    monkeypatch.setenv("AVATAR_STORAGE_BACKEND", "local")
    monkeypatch.setenv("AVATAR_UPLOAD_DIR", str(app.config["AVATAR_UPLOAD_DIR"]))
    config = Config("alembic.ini")
    assert ScriptDirectory.from_config(config).get_current_head() == "f4bc7a81d203"
    with app.app_context():
        db.drop_all()
    command.upgrade(config, "head")
    with app.app_context():
        assert db.session.execute(text("PRAGMA foreign_key_check")).all() == []
        version = db.session.execute(text("SELECT version_num FROM alembic_version")).scalar()
        assert version == "f4bc7a81d203"
        assert db.session.execute(text("SELECT name FROM community_features")).all() == []
        columns = {row[1] for row in db.session.execute(text("PRAGMA table_info(users)"))}
        assert {"avatar_file", "email_verified_at", "invitation_suspended", "ban_reason"} <= columns
