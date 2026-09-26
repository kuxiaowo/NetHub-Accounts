"""Copy existing local avatar WebP objects to R2 without changing database keys.

Run `python -m app.avatar_r2_migration --source-dir PATH` to inspect, then
repeat with `--apply` during the Accounts cutover. Local files are never removed.
"""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path

from PIL import Image

from .avatar_gateway import AVATAR_KEY, AvatarGatewayClient
from .config import PROJECT_ROOT


def migrate(source_dir: Path, gateway: AvatarGatewayClient, *, apply: bool) -> dict[str, int]:
    root = source_dir.resolve(strict=True)
    counts = {"uploaded": 0, "already_present": 0, "pending": 0}
    for path in sorted(root.glob("*/*.webp")):
        if path.is_symlink() or path.parent.is_symlink() or not path.is_file():
            raise ValueError(f"Unsafe avatar path: {path}")
        key = f"avatars/{path.parent.name}/{path.name}"
        if not AVATAR_KEY.fullmatch(key):
            raise ValueError(f"Invalid avatar key: {key}")
        body = path.read_bytes()
        if len(body) > 262144 or len(body) < 12:
            raise ValueError(f"Invalid avatar size: {path}")
        with Image.open(path) as image:
            if image.format != "WEBP":
                raise ValueError(f"Avatar is not WebP: {path}")
            image.verify()
        digest = hashlib.sha256(body).hexdigest()
        existing = gateway.head(key)
        if existing:
            if existing != (len(body), digest):
                raise ValueError(f"R2 avatar differs from the local file: {key}")
            counts["already_present"] += 1
        elif apply:
            gateway.put(key, body)
            if gateway.head(key) != (len(body), digest):
                raise RuntimeError(f"R2 avatar verification failed: {key}")
            counts["uploaded"] += 1
        else:
            counts["pending"] += 1
    return counts


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, default=PROJECT_ROOT / "data/uploads/avatars")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    gateway = AvatarGatewayClient(
        os.getenv("AVATAR_R2_GATEWAY_URL", "https://wiki-media.nethub.wiki"),
        os.environ["AVATAR_R2_HMAC_SECRET"],
    )
    for label, value in migrate(args.source_dir, gateway, apply=args.apply).items():
        print(f"{label}: {value}")


if __name__ == "__main__":
    main()
