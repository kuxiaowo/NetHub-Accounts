from __future__ import annotations

import json
from contextlib import closing
from datetime import UTC, datetime, timedelta

from app.analytics import _daily_filter, connect, ingest_directory, mask_ip, parse_line, summary
from tests.conftest import create_user, csrf_from


def record(host="auth.nethub.wiki", *, ray="ray-1", edge="172.70.10.2", sub=""):
    return json.dumps(
        {
            "ts": datetime.now(UTC).timestamp(),
            "request": {
                "host": host,
                "method": "GET",
                "uri": "/profile?token=must-not-be-indexed",
                "remote_ip": edge,
                "headers": {
                    "Cf-Connecting-Ip": ["203.0.113.8"],
                    "Cf-Ray": [ray],
                    "Cf-Ipcountry": ["JP"],
                    "User-Agent": ["Firefox"],
                },
            },
            "status": 200,
            "duration": 0.12,
            "size": 100,
            "user_sub": sub,
        }
    ).encode() + b"\n"


def test_parse_trusts_only_cloudflare_edge_and_drops_query():
    trusted = (__import__("ipaddress").ip_network("172.70.0.0/16"),)
    event = parse_line(record(), trusted)
    assert event["ip"] == "203.0.113.8"
    assert event["path"] == "/profile"
    assert event["country"] == "JP"
    assert event["ray_id"] == "ray-1"
    spoofed = parse_line(record(edge="198.51.100.4"), trusted)
    assert spoofed["ip"] == "198.51.100.4"
    assert spoofed["country"] == ""
    assert spoofed["ray_id"] == ""
    assert mask_ip(event["ip"]) == "203.0.113.*"


def test_thirty_day_preset_uses_request_index():
    start = (datetime.now(UTC) - timedelta(days=30)).isoformat()
    assert _daily_filter({"from": start}) is None


def test_ingest_rotation_checkpoint_and_site_totals(tmp_path):
    log = tmp_path / "access.json"
    rotated = tmp_path / "access-2026-09-27T100000.json"
    ips = tmp_path / "cloudflare-ips.txt"
    ips.write_text("172.70.0.0/16\n")
    rotated.write_bytes(record(ray="a"))
    log.write_bytes(record("todolist.nethub.wiki", ray="b") + b'{"partial":')
    database = tmp_path / "analytics.sqlite3"
    first = ingest_directory(database, log, ips)
    assert first["inserted"] == 2
    assert ingest_directory(database, log, ips)["inserted"] == 0
    with log.open("ab") as output:
        output.write(b"true}\n")
        output.write(record("codex.nethub.wiki", ray="c"))
    assert ingest_directory(database, log, ips)["inserted"] == 1
    with closing(connect(database)) as connection:
        counts = connection.execute("SELECT site,COUNT(*) FROM requests GROUP BY site").fetchall()
        assert {row[0]: row[1] for row in counts} == {"accounts": 1, "cas": 1, "todo": 1}
        total = summary(connection, {})["requests"]
        sites = connection.execute("SELECT SUM(requests) FROM daily").fetchone()[0]
        hourly = connection.execute("SELECT SUM(requests) FROM hourly").fetchone()[0]
        assert total == sites == hourly == 3


def test_admin_endpoint_and_masked_csv(app, client, tmp_path):
    app.config["ACCOUNTS_ANALYTICS_DB"] = str(tmp_path / "analytics.sqlite3")
    assert client.get("/admin/analytics/summary").status_code == 403
    with app.app_context():
        user = create_user("admin", admin=True)
        sub = user.sub
    page = client.get("/login")
    login = client.post(
        "/login",
        data={"csrf_token": csrf_from(page), "username": "admin", "password": "password-123"},
    )
    assert login.status_code == 302
    assert client.get("/admin/analytics").headers["X-Nethub-User-Sub"] == sub
    with closing(connect(app.config["ACCOUNTS_ANALYTICS_DB"])) as connection:
        event = parse_line(record(sub=sub), (__import__("ipaddress").ip_network("172.70.0.0/16"),))
        with connection:
            connection.execute(
                f"INSERT INTO requests ({','.join(event)}) VALUES ({','.join('?' for _ in event)})",
                tuple(event.values()),
            )
    response = client.get("/admin/analytics/summary")
    assert response.status_code == 200
    assert response.json["requests"] == 1
    assert response.json["users"][0]["value"] == sub
    events = client.get("/admin/analytics/events").json["events"]
    assert events[0]["ipMasked"] == "203.0.113.*"
    assert "ip" not in events[0]
    assert "203.0.113.8" not in client.get("/admin/analytics/export.csv").text
    assert client.get("/admin/analytics").status_code == 200
