"""Run with a systemd timer: python -m app.analytics_cli ingest ..."""

from __future__ import annotations

import argparse
import json

from .analytics import default_database_path, ingest_directory


def main() -> None:
    parser = argparse.ArgumentParser(description="Index Caddy JSON access logs for Accounts")
    parser.add_argument("command", choices=["ingest"])
    parser.add_argument("--database", default=default_database_path())
    parser.add_argument("--log", default="/var/log/caddy/access.json")
    parser.add_argument("--cloudflare-ips", default="/etc/nethub/cloudflare-ips.txt")
    args = parser.parse_args()
    print(json.dumps(ingest_directory(args.database, args.log, args.cloudflare_ips)))


if __name__ == "__main__":
    main()
