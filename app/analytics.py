"""Caddy access-log ingestion and the local, read-only-for-web analytics index.

The Accounts identity database may live in D1.  Request analytics deliberately
uses a separate SQLite file on the origin: Caddy is the only event producer and
no HTTP request to any of the five applications writes an analytics event.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import sqlite3
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

SITE_HOSTS = {
    "auth.nethub.wiki": "accounts",
    "nethub.wiki": "wiki",
    "www.nethub.wiki": "wiki",
    "test.nethub.wiki": "wiki",
    "todolist.nethub.wiki": "todo",
    "codex.nethub.wiki": "cas",
    "sdgj.tech": "techx",
    "www.sdgj.tech": "techx",
}
SITES = frozenset(SITE_HOSTS.values())
NOISE_PREFIXES = ("/static/", "/assets/", "/media/", "/resources/", "/favicon")
NOISE_PATHS = frozenset({"/health", "/api/health", "/robots.txt"})
BOT_MARKERS = ("bot", "crawler", "spider", "slurp", "headless")
SCHEMA = """
CREATE TABLE IF NOT EXISTS requests (
  event_id TEXT PRIMARY KEY, occurred_at TEXT NOT NULL, site TEXT NOT NULL,
  host TEXT NOT NULL, method TEXT NOT NULL, path TEXT NOT NULL,
  status INTEGER NOT NULL, duration_ms REAL NOT NULL, bytes_sent INTEGER NOT NULL,
  ip TEXT NOT NULL, edge_ip TEXT NOT NULL, user_sub TEXT NOT NULL,
  user_agent TEXT NOT NULL, referer TEXT NOT NULL, country TEXT NOT NULL,
  ray_id TEXT NOT NULL, is_noise INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_requests_time ON requests(occurred_at);
CREATE INDEX IF NOT EXISTS ix_requests_site_time ON requests(site, occurred_at);
CREATE INDEX IF NOT EXISTS ix_requests_ip_time ON requests(ip, occurred_at);
CREATE INDEX IF NOT EXISTS ix_requests_sub_time ON requests(user_sub, occurred_at);
CREATE INDEX IF NOT EXISTS ix_requests_ray ON requests(ray_id);
CREATE TABLE IF NOT EXISTS daily (
  day TEXT NOT NULL, site TEXT NOT NULL, is_noise INTEGER NOT NULL,
  status_class INTEGER NOT NULL, requests INTEGER NOT NULL DEFAULT 0,
  page_views INTEGER NOT NULL DEFAULT 0, errors INTEGER NOT NULL DEFAULT 0,
  duration_sum_ms REAL NOT NULL DEFAULT 0, bytes_sent INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(day, site, is_noise, status_class)
);
CREATE TABLE IF NOT EXISTS hourly (
  hour TEXT NOT NULL, site TEXT NOT NULL, is_noise INTEGER NOT NULL,
  status_class INTEGER NOT NULL, requests INTEGER NOT NULL DEFAULT 0,
  page_views INTEGER NOT NULL DEFAULT 0, errors INTEGER NOT NULL DEFAULT 0,
  duration_sum_ms REAL NOT NULL DEFAULT 0, bytes_sent INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(hour, site, is_noise, status_class)
);
CREATE TABLE IF NOT EXISTS checkpoints (
  file_id TEXT PRIMARY KEY, offset INTEGER NOT NULL, path TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
"""


def connect(path: str | Path) -> sqlite3.Connection:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA busy_timeout=10000")
    connection.executescript(SCHEMA)
    return connection


def header(headers: dict, name: str) -> str:
    for key, value in headers.items():
        if key.casefold() == name.casefold():
            return str(value[0] if isinstance(value, list) and value else value or "")[:1000]
    return ""


def _safe_referer(value: str) -> str:
    """Keep a useful source URL without persisting query tokens or fragments."""
    try:
        parts = urlsplit(value)
    except ValueError:
        return ""
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        return ""
    return f"{parts.scheme}://{parts.netloc}{parts.path}"[:1000]


def mask_ip(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return "—"
    if address.version == 4:
        return ".".join(value.split(".")[:3]) + ".*"
    return ":".join(address.exploded.split(":")[:4]) + ":****"


def _client_ip(edge: str, claimed: str, trusted: tuple) -> str:
    try:
        edge_address = ipaddress.ip_address(edge)
        if claimed and any(edge_address in network for network in trusted):
            return str(ipaddress.ip_address(claimed))
        return str(edge_address)
    except ValueError:
        return edge[:64]


def parse_line(raw: bytes, trusted: tuple) -> dict | None:
    try:
        item = json.loads(raw)
        request = item["request"]
        host = str(request.get("host", "")).split(":", 1)[0].lower()
        site = SITE_HOSTS.get(host)
        if site is None:
            return None
        when = datetime.fromtimestamp(float(item["ts"]), UTC)
        headers = request.get("headers") or {}
        path = urlsplit(str(request.get("uri", "/"))).path or "/"
        edge = str(request.get("remote_ip") or request.get("client_ip") or "")
        agent = header(headers, "User-Agent")
        sub = str(item.get("user_sub") or "")[:80]
        if sub and (len(sub) != 36 or any(char not in "0123456789abcdef-" for char in sub.lower())):
            sub = ""
        cloudflare_edge = False
        try:
            edge_address = ipaddress.ip_address(edge)
            cloudflare_edge = any(edge_address in network for network in trusted)
        except ValueError:
            pass
        return {
            "event_id": hashlib.sha256(raw.rstrip(b"\r\n")).hexdigest(),
            "occurred_at": when.isoformat(timespec="microseconds"),
            "site": site,
            "host": host,
            "method": str(request.get("method", ""))[:12],
            "path": path[:1000],
            "status": int(item.get("status", 0)),
            "duration_ms": max(0, float(item.get("duration", 0)) * 1000),
            "bytes_sent": max(0, int(item.get("size", 0))),
            "ip": _client_ip(edge, header(headers, "CF-Connecting-IP"), trusted),
            "edge_ip": edge[:64],
            "user_sub": sub,
            "user_agent": agent,
            "referer": _safe_referer(header(headers, "Referer")),
            "country": header(headers, "CF-IPCountry")[:4] if cloudflare_edge else "",
            "ray_id": header(headers, "CF-Ray")[:100] if cloudflare_edge else "",
            "is_noise": int(
                path in NOISE_PATHS
                or path.startswith(NOISE_PREFIXES)
                or any(marker in agent.casefold() for marker in BOT_MARKERS)
            ),
        }
    except (KeyError, TypeError, ValueError, OverflowError, json.JSONDecodeError):
        return None


def trusted_networks(path: str | Path) -> tuple:
    """Load Cloudflare's published CIDRs from a root-maintained local file."""
    lines = Path(path).read_text(encoding="ascii").splitlines()
    networks = tuple(
        ipaddress.ip_network(line.strip())
        for line in lines
        if line.strip() and not line.lstrip().startswith("#")
    )
    if not networks:
        raise ValueError("trusted Cloudflare network list is empty")
    return networks


def ingest(connection: sqlite3.Connection, log_path: str | Path, trusted: tuple) -> dict:
    """Read complete lines only; checkpoint and rollups commit atomically."""
    path = Path(log_path)
    stat = path.stat()
    file_id = f"{stat.st_dev}:{stat.st_ino}"
    checkpoint = connection.execute(
        "SELECT offset FROM checkpoints WHERE file_id=?", (file_id,)
    ).fetchone()
    offset = min(int(checkpoint["offset"]), stat.st_size) if checkpoint else 0
    scanned = inserted = rejected = 0
    with path.open("rb") as stream, connection:
        stream.seek(offset)
        while True:
            start = stream.tell()
            raw = stream.readline()
            if not raw or not raw.endswith(b"\n"):
                stream.seek(start)
                break
            scanned += 1
            entry = parse_line(raw, trusted)
            if entry is None:
                rejected += 1
                continue
            columns = ",".join(entry)
            marks = ",".join("?" for _ in entry)
            cursor = connection.execute(
                f"INSERT OR IGNORE INTO requests ({columns}) VALUES ({marks})",
                tuple(entry.values()),
            )
            if cursor.rowcount:
                inserted += 1
                for table, bucket, key in (
                    ("daily", entry["occurred_at"][:10], "day"),
                    ("hourly", entry["occurred_at"][:13], "hour"),
                ):
                    connection.execute(
                        f"""INSERT INTO {table}
                        ({key},site,is_noise,status_class,requests,page_views,errors,
                         duration_sum_ms,bytes_sent)
                        VALUES (?,?,?,?,1,?,?,?,?)
                        ON CONFLICT({key},site,is_noise,status_class) DO UPDATE SET
                        requests=requests+1,page_views=page_views+excluded.page_views,
                        errors=errors+excluded.errors,
                        duration_sum_ms=duration_sum_ms+excluded.duration_sum_ms,
                        bytes_sent=bytes_sent+excluded.bytes_sent""",
                        (
                            bucket, entry["site"], entry["is_noise"], entry["status"] // 100,
                            int(not entry["is_noise"] and entry["method"] == "GET"),
                            int(entry["status"] >= 500), entry["duration_ms"],
                            entry["bytes_sent"],
                        ),
                    )
        connection.execute(
            """INSERT INTO checkpoints(file_id,offset,path,updated_at) VALUES(?,?,?,?)
            ON CONFLICT(file_id) DO UPDATE SET offset=excluded.offset,path=excluded.path,
            updated_at=excluded.updated_at""",
            (file_id, stream.tell(), str(path), datetime.now(UTC).isoformat()),
        )
    return {"scanned": scanned, "inserted": inserted, "rejected": rejected}


def prune(connection: sqlite3.Connection, now: datetime | None = None) -> None:
    now = now or datetime.now(UTC)
    with connection:
        connection.execute(
            "DELETE FROM requests WHERE occurred_at < ?",
            ((now - timedelta(days=30)).isoformat(),),
        )
        connection.execute(
            "DELETE FROM daily WHERE day < ?", ((now - timedelta(days=365)).date().isoformat(),)
        )
        connection.execute(
            "DELETE FROM hourly WHERE hour < ?", ((now - timedelta(days=365)).isoformat()[:13],)
        )
        connection.execute(
            "DELETE FROM checkpoints WHERE updated_at < ?",
            ((now - timedelta(days=45)).isoformat(),),
        )


def ingest_directory(db_path: str | Path, log_path: str | Path, networks_path: str | Path) -> dict:
    trusted = trusted_networks(networks_path)
    log_path = Path(log_path)
    files = sorted(
        (
            p for p in log_path.parent.iterdir()
            if p.is_file() and not p.name.endswith(".gz")
            and (p.name.startswith(log_path.name + ".")
                 or p.name == log_path.name
                 or (p.name.startswith(log_path.stem + "-")
                     and p.name.endswith(log_path.suffix)))
        ),
        key=lambda p: (p.stat().st_mtime, p.name),
    )
    totals = {"files": len(files), "scanned": 0, "inserted": 0, "rejected": 0}
    with closing(connect(db_path)) as connection:
        for path in files:
            result = ingest(connection, path, trusted)
            for key, value in result.items():
                totals[key] += value
        prune(connection)
    return totals


def filters(query) -> tuple[str, list, dict]:
    site = query.get("site", "all")
    if site != "all" and site not in SITES:
        raise ValueError("invalid site")
    now = datetime.now(UTC)
    since = query.get("from") or (now - timedelta(days=7)).isoformat()
    until = query.get("to") or now.isoformat()
    try:
        start = datetime.fromisoformat(since.replace("Z", "+00:00")).astimezone(UTC)
        end = datetime.fromisoformat(until.replace("Z", "+00:00")).astimezone(UTC)
    except ValueError as exc:
        raise ValueError("invalid date range") from exc
    if start > end or end - start > timedelta(days=365):
        raise ValueError("date range must be within 365 days")
    conditions = ["occurred_at >= ?", "occurred_at <= ?"]
    params: list = [start.isoformat(), end.isoformat()]
    if site != "all":
        conditions.append("site=?")
        params.append(site)
    if query.get("all") != "1":
        conditions.append("is_noise=0")
    for key, column in (
        ("userSub", "user_sub"), ("ip", "ip"), ("rayId", "ray_id"),
        ("status", "status"), ("path", "path"), ("userAgent", "user_agent"),
        ("country", "country"),
    ):
        value = query.get(key)
        if value:
            conditions.append(f"{column}=?")
            params.append(value[:1000])
    return " AND ".join(conditions), params, {"site": site, "from": start, "to": end}


def rows(connection: sqlite3.Connection, sql: str, params=()) -> list[dict]:
    return [dict(row) for row in connection.execute(sql, params)]


def _daily_filter(query) -> tuple[str, list] | None:
    _, _, meta = filters(query)
    # The browser's 30-day preset is a few seconds older by the time it arrives.
    if meta["from"] >= datetime.now(UTC) - timedelta(days=30, minutes=5):
        return None
    if any(
        query.get(key)
        for key in ("userSub", "ip", "rayId", "status", "path", "userAgent", "country")
    ):
        return None
    conditions = ["day>=?", "day<=?"]
    params = [meta["from"].date().isoformat(), meta["to"].date().isoformat()]
    if meta["site"] != "all":
        conditions.append("site=?")
        params.append(meta["site"])
    if query.get("all") != "1":
        conditions.append("is_noise=0")
    return " AND ".join(conditions), params


def event_rows(connection: sqlite3.Connection, query, *, export: bool = False) -> dict:
    where, params, _ = filters(query)
    try:
        page = max(1, int(query.get("page", 1)))
        per_page = min(200, max(1, int(query.get("pageSize", 50))))
    except ValueError as exc:
        raise ValueError("invalid pagination") from exc
    limit = 10000 if export else per_page
    offset = 0 if export else (page - 1) * per_page
    total = connection.execute(f"SELECT COUNT(*) FROM requests WHERE {where}", params).fetchone()[0]
    entries = rows(
        connection,
        f"SELECT * FROM requests WHERE {where} ORDER BY occurred_at DESC LIMIT ? OFFSET ?",
        [*params, limit, offset],
    )
    for entry in entries:
        entry["ipMasked"] = mask_ip(entry["ip"])
        if query.get("revealIp") != "1":
            entry.pop("ip")
        entry.pop("event_id")
        entry.pop("edge_ip")
    return {"total": total, "page": page, "pageSize": per_page, "events": entries}


def summary(connection: sqlite3.Connection, query) -> dict:
    where, params, _ = filters(query)
    daily = _daily_filter(query)
    if daily is not None:
        day_where, day_params = daily
        aggregate = connection.execute(
            f"""SELECT COALESCE(SUM(requests),0) requests,
            COALESCE(SUM(page_views),0) pageViews,
            COALESCE(SUM(errors),0) errors,
            COALESCE(SUM(duration_sum_ms),0) durationSum,
            COALESCE(SUM(bytes_sent),0) bytesSent FROM daily WHERE {day_where}""",
            day_params,
        ).fetchone()
        values = dict(aggregate)
        count = values["requests"]
        values["avgMs"] = values.pop("durationSum") / count if count else 0
        values["errorRate"] = values["errors"] / count if count else 0
        values.update(uniqueIps=None, uniqueUsers=None, p95Ms=None, historical=True)
        for label, column in (("sites", "site"), ("statuses", "status_class")):
            values[label] = rows(
                connection,
                f"SELECT {column} value,SUM(requests) count FROM daily WHERE {day_where} "
                f"GROUP BY {column} ORDER BY count DESC",
                day_params,
            )
        values["statuses"] = [
            {"value": f"{item['value']}xx", "count": item["count"]}
            for item in values["statuses"]
        ]
        for label in ("paths", "users", "ips", "agents", "countries", "referrers", "slow"):
            values[label] = []
        return values
    aggregate = connection.execute(
        f"""SELECT COUNT(*) requests,
        COALESCE(SUM(CASE WHEN method='GET' THEN 1 ELSE 0 END),0) pageViews,
        COUNT(DISTINCT NULLIF(ip,'')) uniqueIps, COUNT(DISTINCT NULLIF(user_sub,'')) uniqueUsers,
        COALESCE(SUM(status>=500),0) errors, COALESCE(AVG(duration_ms),0) avgMs,
        COALESCE(SUM(bytes_sent),0) bytesSent FROM requests WHERE {where}""",
        params,
    ).fetchone()
    values = dict(aggregate)
    count = values["requests"]
    if count:
        rank = max(0, int((count - 1) * 0.95))
        values["p95Ms"] = connection.execute(
            f"SELECT duration_ms FROM requests WHERE {where} ORDER BY duration_ms LIMIT 1 OFFSET ?",
            [*params, rank],
        ).fetchone()[0]
    else:
        values["p95Ms"] = 0
    values["errorRate"] = values["errors"] / count if count else 0
    for label, column in (
        ("sites", "site"), ("statuses", "status"), ("paths", "path"),
        ("users", "user_sub"), ("ips", "ip"), ("agents", "user_agent"),
        ("countries", "country"), ("referrers", "referer"),
    ):
        values[label] = rows(
            connection,
            f"SELECT {column} value, COUNT(*) count FROM requests WHERE {where} "
            f"GROUP BY {column} ORDER BY count DESC LIMIT 12",
            params,
        )
    for item in values["ips"]:
        item["masked"] = mask_ip(item["value"])
        if query.get("revealIp") != "1":
            item.pop("value")
    values["slow"] = rows(
        connection,
        f"SELECT site,path,status,duration_ms occurredMs FROM requests WHERE {where} "
        "ORDER BY duration_ms DESC LIMIT 10",
        params,
    )
    return values


def timeseries(connection: sqlite3.Connection, query) -> list[dict]:
    where, params, _ = filters(query)
    daily = _daily_filter(query)
    if daily is not None:
        day_where, day_params = daily
        return rows(
            connection,
            f"SELECT day bucket,site,SUM(requests) requests,SUM(errors) errors,"
            f"SUM(duration_sum_ms)/SUM(requests) avgMs FROM daily WHERE {day_where} "
            "GROUP BY day,site ORDER BY day,site",
            day_params,
        )
    return rows(
        connection,
        f"SELECT substr(occurred_at,1,13) bucket,site,COUNT(*) requests,"
        f"SUM(status>=500) errors,AVG(duration_ms) avgMs FROM requests WHERE {where} "
        "GROUP BY bucket,site ORDER BY bucket,site",
        params,
    )


def default_database_path() -> str:
    default = Path(__file__).resolve().parent.parent / "data/analytics.sqlite3"
    return os.getenv("ACCOUNTS_ANALYTICS_DB", str(default))
