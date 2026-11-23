"""Site-wide controls shared by registration and Campus Wiki."""

import json

from flask import current_app, g
from sqlalchemy import select
from sqlalchemy.dialects.sqlite import insert

from .d1_gateway import Statement
from .extensions import db
from .models import CommunityFeature, utc_now
from .security import audit, client_ip


def community_features():
    flags = {
        "invitations": current_app.config["REGISTRATION_MODE"] == "invite",
        "comments": False,
        "messages": False,
    }
    if current_app.config["ACCOUNTS_DATABASE_BACKEND"] == "d1":
        rows = current_app.extensions["d1_gateway_client"].execute(
            "SELECT name, enabled FROM community_features"
        )["rows"]
        flags.update({row["name"]: bool(row["enabled"]) for row in rows})
    else:
        flags.update(
            db.session.execute(select(CommunityFeature.name, CommunityFeature.enabled)).all()
        )
    flags["invitations"] = flags["invitations"] and current_app.config["REGISTRATION_ENABLED"]
    return flags


def invite_registration_enabled():
    return community_features()["invitations"]


def set_community_feature(name, enabled):
    details = {"feature": name, "enabled": enabled}
    if current_app.config["ACCOUNTS_DATABASE_BACKEND"] == "d1":
        current_app.extensions["d1_gateway_client"].batch(
            [
                Statement(
                    "INSERT INTO community_features(name,enabled) VALUES (?,?) "
                    "ON CONFLICT(name) DO UPDATE SET enabled=excluded.enabled",
                    [name, int(enabled)],
                ),
                Statement(
                    "INSERT INTO audit_logs"
                    "(actor_user_id,action,ip_address,details_json,created_at) "
                    "VALUES (?,?,?,?,?)",
                    [
                        g.current_user.id,
                        "admin.community_feature",
                        client_ip(),
                        json.dumps(details),
                        utc_now().isoformat(),
                    ],
                ),
            ]
        )
    else:
        stmt = insert(CommunityFeature).values(name=name, enabled=enabled)
        db.session.execute(
            stmt.on_conflict_do_update(index_elements=["name"], set_={"enabled": enabled})
        )
        audit("admin.community_feature", details=details)
        db.session.commit()
