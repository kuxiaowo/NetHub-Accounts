from __future__ import annotations

import argparse
import ipaddress
from pathlib import Path


def quote_systemd(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def render_unit(app_dir: Path, python_bin: Path, host: str, port: int) -> str:
    ipaddress.ip_address(host)
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    command = (
        f"{quote_systemd(str(python_bin))} -m gunicorn --workers 1 "
        f"--bind {host}:{port} --access-logfile - wsgi:app"
    )
    return f"""[Unit]
Description=NetHub Accounts OIDC Provider
After=network.target

[Service]
Type=simple
WorkingDirectory={app_dir}
ExecStart={command}
Restart=always
RestartSec=3
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=default.target
"""


def main() -> None:
    parser = argparse.ArgumentParser(description="Render the NetHub Accounts user service")
    parser.add_argument("--app-dir", type=Path, required=True)
    parser.add_argument("--python-bin", type=Path, required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=3400)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    content = render_unit(args.app_dir.resolve(), args.python_bin.resolve(), args.host, args.port)
    args.output.write_text(content, encoding="utf-8")


if __name__ == "__main__":
    main()
