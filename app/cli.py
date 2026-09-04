from __future__ import annotations

import getpass
import hashlib
import json
import secrets
import time
from pathlib import Path

import click
from alembic import command
from alembic.config import Config
from sqlalchemy import select

from . import create_app
from .backchannel import deliver_pending_jobs
from .config import PROJECT_ROOT
from .extensions import db
from .migration_tool import apply_plan, build_plan, load_sources, write_plan
from .models import LoginAlias, OAuth2Client, User
from .security import hash_password, normalize_username


def _alembic_config() -> Config:
    config = Config(str(PROJECT_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
    return config


@click.group()
def cli() -> None:
    """NetHub Accounts administration commands."""


@cli.command("db-upgrade")
def db_upgrade() -> None:
    command.upgrade(_alembic_config(), "head")
    click.echo("database upgraded")


@cli.command("bootstrap-admin")
@click.option("--username", prompt=True)
@click.option("--display-name", prompt="Display name")
def bootstrap_admin(username: str, display_name: str) -> None:
    password = getpass.getpass("Password: ")
    confirmation = getpass.getpass("Confirm password: ")
    if password != confirmation:
        raise click.ClickException("passwords do not match")
    display_name = display_name.strip()
    if not display_name or len(display_name) > 80:
        raise click.ClickException("display name must contain 1-80 characters")
    app = create_app({"BACKCHANNEL_WORKER_ENABLED": False})
    with app.app_context():
        normalized, key = normalize_username(username)
        if db.session.scalar(
            select(User).where(User.is_system_admin.is_(True), User.is_active.is_(True))
        ):
            raise click.ClickException("an active system administrator already exists")
        if db.session.scalar(select(LoginAlias).where(LoginAlias.alias_key == key)):
            raise click.ClickException("username already exists")
        user = User(
            username=normalized,
            username_key=key,
            display_name=display_name,
            password_hash=hash_password(password),
            is_system_admin=True,
            is_active=True,
        )
        db.session.add(user)
        db.session.flush()
        db.session.add(
            LoginAlias(user_id=user.id, alias=normalized, alias_key=key, source="central")
        )
        db.session.commit()
        click.echo(f"administrator created: {normalized} ({user.sub})")


@cli.command("register-client")
@click.option("--client-id", required=True)
@click.option("--name", required=True)
@click.option("--redirect-uri", multiple=True, required=True)
@click.option("--launch-uri", required=True)
@click.option("--backchannel-logout-uri", default="")
def register_client(
    client_id: str,
    name: str,
    redirect_uri: tuple[str, ...],
    launch_uri: str,
    backchannel_logout_uri: str,
) -> None:
    if not client_id or len(client_id) > 48:
        raise click.ClickException("client-id must contain 1-48 characters")
    if not name.strip():
        raise click.ClickException("client name cannot be empty")
    if any("*" in uri for uri in redirect_uri):
        raise click.ClickException("wildcard redirect URIs are forbidden")
    for uri in (
        *redirect_uri,
        launch_uri,
        *([backchannel_logout_uri] if backchannel_logout_uri else []),
    ):
        if not (uri.startswith("https://") or uri.startswith("http://127.0.0.1")):
            raise click.ClickException(
                "client URLs must use HTTPS (loopback development is allowed)"
            )
    secret = secrets.token_urlsafe(48)
    app = create_app({"BACKCHANNEL_WORKER_ENABLED": False})
    with app.app_context():
        client = db.session.scalar(select(OAuth2Client).where(OAuth2Client.client_id == client_id))
        if client is None:
            client = OAuth2Client(client_id=client_id, client_id_issued_at=int(time.time()))
            db.session.add(client)
        client.client_secret = "sha256$" + hashlib.sha256(secret.encode()).hexdigest()
        client.client_secret_expires_at = 0
        client.launch_uri = launch_uri
        client.backchannel_logout_uri = backchannel_logout_uri
        client.is_active = True
        client.set_client_metadata(
            {
                "client_name": name,
                "redirect_uris": list(redirect_uri),
                "scope": "openid profile",
                "grant_types": ["authorization_code"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "client_secret_basic",
                "id_token_signed_response_alg": "RS256",
            }
        )
        db.session.commit()
    click.echo("Client secret (shown once):")
    click.echo(secret)


@cli.command("migration-dry-run")
@click.option("--todo-db", type=click.Path(path_type=Path, exists=True))
@click.option("--techx-db", type=click.Path(path_type=Path, exists=True))
@click.option("--output", type=click.Path(path_type=Path), required=True)
def migration_dry_run(todo_db: Path | None, techx_db: Path | None, output: Path) -> None:
    items = load_sources(todo_db, techx_db)
    plan = build_plan(items)
    write_plan(plan, output)
    click.echo(json.dumps(plan["summary"], ensure_ascii=False))
    click.echo(f"plan written: {output}")


@cli.command("migration-apply")
@click.option("--todo-db", type=click.Path(path_type=Path, exists=True))
@click.option("--techx-db", type=click.Path(path_type=Path, exists=True))
@click.option("--plan", "plan_path", type=click.Path(path_type=Path, exists=True), required=True)
@click.option("--mapping-output", type=click.Path(path_type=Path), required=True)
def migration_apply_command(
    todo_db: Path | None,
    techx_db: Path | None,
    plan_path: Path,
    mapping_output: Path,
) -> None:
    items = load_sources(todo_db, techx_db)
    app = create_app({"BACKCHANNEL_WORKER_ENABLED": False})
    with app.app_context():
        result = apply_plan(plan_path, items, mapping_output)
    click.echo(f"applied {len(result['mappings'])} source mappings")


@cli.command("retry-backchannel")
@click.option("--limit", default=50, type=int)
def retry_backchannel(limit: int) -> None:
    app = create_app({"BACKCHANNEL_WORKER_ENABLED": False})
    with app.app_context():
        result = deliver_pending_jobs(limit)
    click.echo(json.dumps(result))


if __name__ == "__main__":
    cli()
