from __future__ import annotations

from logging.config import fileConfig

from alembic import context

from app import create_app
from app.extensions import db

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

app = create_app({"BACKCHANNEL_WORKER_ENABLED": False})
target_metadata = db.metadata


def run_migrations_offline() -> None:
    with app.app_context():
        context.configure(
            url=app.config["SQLALCHEMY_DATABASE_URI"],
            target_metadata=target_metadata,
            literal_binds=True,
            dialect_opts={"paramstyle": "named"},
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


def run_migrations_online() -> None:
    with app.app_context():
        with db.engine.connect() as connection:
            context.configure(
                connection=connection, target_metadata=target_metadata, compare_type=True
            )
            with context.begin_transaction():
                context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
