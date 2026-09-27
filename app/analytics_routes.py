"""Administrator-only traffic analysis backed by Caddy's local request index."""

from __future__ import annotations

import csv
import io
from contextlib import closing
from pathlib import Path

from flask import Blueprint, abort, current_app, g, jsonify, render_template, request
from sqlalchemy import select

from . import analytics
from .extensions import db
from .models import User

traffic = Blueprint("traffic", __name__)


@traffic.before_request
def require_admin():
    user = getattr(g, "current_user", None)
    if user is None or not user.is_system_admin:
        abort(403)


def database():
    return analytics.connect(current_app.config["ACCOUNTS_ANALYTICS_DB"])


def csv_cell(value):
    if isinstance(value, str) and value.lstrip(" \t\r\n")[:1] in ("=", "+", "-", "@"):
        return "'" + value
    return value


def checked_query():
    try:
        analytics.filters(request.args)
    except ValueError as exc:
        abort(400, description=str(exc))
    return request.args


def user_names(subs: list[str]) -> dict:
    subs = list(dict.fromkeys(sub for sub in subs if sub))[:50]
    if not subs:
        return {}
    if current_app.config.get("ACCOUNTS_DATABASE_BACKEND") == "d1":
        placeholders = ",".join("?" for _ in subs)
        rows = current_app.extensions["d1_gateway_client"].execute(
            f"SELECT sub,username,display_name FROM users WHERE sub IN ({placeholders})", subs
        ).get("rows") or []
    else:
        rows = db.session.scalars(select(User).where(User.sub.in_(subs))).all()
    return {
        row["sub"] if isinstance(row, dict) else row.sub: {
            "username": row["username"] if isinstance(row, dict) else row.username,
            "displayName": row["display_name"] if isinstance(row, dict) else row.display_name,
        }
        for row in rows
    }


@traffic.get("/admin/analytics")
def page():
    return render_template("analytics.html")


@traffic.get("/admin/analytics/summary")
def summary():
    query = checked_query()
    with closing(database()) as connection:
        result = analytics.summary(connection, query)
    result["userNames"] = user_names([row["value"] for row in result["users"]])
    return jsonify(result)


@traffic.get("/admin/analytics/timeseries")
def timeseries():
    query = checked_query()
    with closing(database()) as connection:
        return jsonify(analytics.timeseries(connection, query))


@traffic.get("/admin/analytics/events")
def events():
    query = checked_query()
    with closing(database()) as connection:
        try:
            result = analytics.event_rows(connection, query)
        except ValueError as exc:
            abort(400, description=str(exc))
    result["userNames"] = user_names([row["user_sub"] for row in result["events"]])
    return jsonify(result)


@traffic.get("/admin/analytics/users/<sub>")
def user_events(sub: str):
    query = dict(checked_query())
    query["userSub"] = sub
    with closing(database()) as connection:
        result = analytics.event_rows(connection, query)
    result["userNames"] = user_names([sub])
    return jsonify(result)


@traffic.get("/admin/analytics/ips/<path:ip>")
def ip_events(ip: str):
    query = dict(checked_query())
    query["ip"] = ip
    with closing(database()) as connection:
        return jsonify(analytics.event_rows(connection, query))


@traffic.get("/admin/analytics/export.csv")
def export_csv():
    query = dict(checked_query())
    query.pop("revealIp", None)
    with closing(database()) as connection:
        result = analytics.event_rows(connection, query, export=True)
    output = io.StringIO()
    fields = [
        "occurred_at", "site", "host", "method", "path", "status", "duration_ms",
        "bytes_sent", "ipMasked", "user_sub", "user_agent", "referer", "country", "ray_id",
    ]
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(
        {
            key: csv_cell(value)
            for key, value in event.items()
        }
        for event in result["events"]
    )
    response = current_app.response_class(output.getvalue(), mimetype="text/csv; charset=utf-8")
    response.headers["Content-Disposition"] = "attachment; filename=nethub-analytics.csv"
    response.headers["Cache-Control"] = "no-store"
    return response


@traffic.get("/admin/analytics/status")
def status():
    path = Path(current_app.config["ACCOUNTS_ANALYTICS_DB"])
    if not path.exists():
        return jsonify(indexed=0, checkpoints=0)
    with closing(database()) as connection:
        indexed = connection.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
        checkpoints = connection.execute("SELECT COUNT(*) FROM checkpoints").fetchone()[0]
        latest = connection.execute("SELECT MAX(occurred_at) FROM requests").fetchone()[0]
    return jsonify(indexed=indexed, checkpoints=checkpoints, latest=latest)
