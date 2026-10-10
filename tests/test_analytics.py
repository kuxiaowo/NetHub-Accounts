from __future__ import annotations

import json
from contextlib import closing
from datetime import UTC, datetime, timedelta

from app.analytics import _daily_filter, connect, ingest_directory, mask_ip, parse_line, summary
from tests.conftest import create_user, csrf_from


def record(host="auth.nethub.wiki", *, ray="ray-1", edge="172.70.10.2", sub=""):
    return (
        json.dumps(
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
        ).encode()
        + b"\n"
    )


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


def test_client_snapshot_rejects_cross_origin_and_private_fields(client):
    import base64

    headers = {"Origin": "https://localhost", "Sec-Fetch-Site": "same-origin"}
    assert (
        client.post(
            "/__nethub/client", json={}, headers={"Origin": "https://evil.test"}
        ).status_code
        == 403
    )
    response = client.post(
        "/__nethub/client",
        headers=headers,
        json={
            "timezone": "Asia/Shanghai",
            "page_path": "/login?password=secret#token",
            "languages": ["zh-CN"],
            "password": "must-not-log",
            "hardware_concurrency": 8,
            "permissions": {"deep": "not-accepted"},
            "user_sub": "forged-subject",
        },
    )
    assert response.status_code == 204
    data = json.loads(base64.urlsafe_b64decode(response.headers["X-Nethub-Client-Info"]))
    assert data == {
        "timezone": "Asia/Shanghai",
        "page_path": "/login",
        "languages": ["zh-CN"],
        "hardware_concurrency": 8,
    }
    cookie = response.headers["Set-Cookie"]
    assert "Secure" in cookie and "HttpOnly" in cookie and "SameSite=Lax" in cookie
    second = client.post("/__nethub/client", json={}, headers=headers)
    assert second.headers["X-Nethub-Browser-Id"] == response.headers["X-Nethub-Browser-Id"]
    assert client.post("/__nethub/client", data="x" * 17000, headers=headers).status_code == 413
    assert client.post("/__nethub/client", json=[], headers=headers).status_code == 400


def test_snapshot_indexes_hints_and_filters_forged_fields():
    import base64
    import uuid

    entry = json.loads(record())
    browser = str(uuid.uuid4())
    entry.update(
        browser_id=browser,
        client_info=base64.urlsafe_b64encode(
            json.dumps(
                {
                    "timezone": "Asia/Shanghai",
                    "user_sub": "forged",
                    "page_path": "/?token=secret",
                }
            ).encode()
        ).decode(),
    )
    entry["request"]["uri"] = "/__nethub/client"
    entry["request"]["headers"].update(
        {"Accept-Language": ["zh-CN"], "Sec-CH-UA-Platform": ['"Windows"']}
    )
    event = parse_line(json.dumps(entry).encode(), ())
    assert event["browser_id"] == browser and event["accept_language"] == "zh-CN"
    assert json.loads(event["client_info"]) == {"timezone": "Asia/Shanghai", "page_path": "/"}
    assert json.loads(event["client_hints"])["Sec-CH-UA-Platform"] == '"Windows"'
    assert event["is_noise"] == 1
    entry["client_info"] = "invalid!"
    entry["browser_id"] = "forged-value"
    event = parse_line(json.dumps(entry).encode(), ())
    assert event["browser_id"] == "" and event["client_info"] == "{}"


def test_analytics_schema_upgrade_preserves_requests(tmp_path):
    import sqlite3

    from app.analytics import SCHEMA

    path = tmp_path / "old.sqlite3"
    old_schema = SCHEMA.replace(
        ",\n  browser_id TEXT NOT NULL DEFAULT '', accept_language TEXT NOT NULL DEFAULT '',"
        "\n  client_hints TEXT NOT NULL DEFAULT '{}', client_info TEXT NOT NULL DEFAULT '{}'",
        "",
    )
    with sqlite3.connect(path) as connection:
        connection.executescript(old_schema)
        event = parse_line(record(), ())
        for field in ("browser_id", "accept_language", "client_hints", "client_info"):
            event.pop(field)
        connection.execute(
            f"INSERT INTO requests ({','.join(event)}) VALUES ({','.join('?' for _ in event)})",
            tuple(event.values()),
        )
    with closing(connect(path)) as connection:
        assert connection.execute("SELECT COUNT(*) FROM requests").fetchone()[0] == 1
        assert (
            connection.execute("SELECT browser_id,client_info FROM requests").fetchone()[1] == "{}"
        )
