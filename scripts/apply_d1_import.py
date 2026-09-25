"""Apply an export_sqlite_to_d1.py manifest to an empty D1 database.

The caller must explicitly choose --local or --remote. A partial import is
never resumed: discard that destination and apply again to a fresh database.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path


def _name(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def _run(wrangler: str, database: str, config: Path, location: str, option: str, value: str) -> list[dict]:
    command = [wrangler, "d1", "execute", database, "--config", str(config), location,
               option, value, "--json", "--yes"]
    result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", check=False)
    if result.returncode:
        raise RuntimeError(f"Wrangler failed ({result.returncode}): {result.stdout}\n{result.stderr}")
    # Remote --file writes upload progress to stdout before its JSON result.
    # Accept only a complete JSON array at the end of that output.
    response = None
    decoder = json.JSONDecoder()
    for position, character in enumerate(result.stdout):
        if character != "[":
            continue
        try:
            candidate, end = decoder.raw_decode(result.stdout[position:])
        except json.JSONDecodeError:
            continue
        if not result.stdout[position + end:].strip():
            response = candidate
            break
    if response is None:
        raise RuntimeError(f"Wrangler returned invalid JSON: {result.stdout[:500]}")
    if not isinstance(response, list) or any(not item.get("success") for item in response):
        raise RuntimeError(f"D1 rejected SQL: {response}")
    return response


def _query(wrangler: str, database: str, config: Path, location: str, sql: str) -> list[dict]:
    result = _run(wrangler, database, config, location, "--command", sql)
    if len(result) != 1:
        raise RuntimeError("expected one D1 query result")
    return result[0].get("results") or []


def apply(manifest_path: Path, database: str, config: Path, *, remote: bool, wrangler: str | None = None) -> None:
    wrangler = wrangler or shutil.which("wrangler")
    if not wrangler:
        raise RuntimeError("Wrangler CLI was not found")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("require_empty_destination") is not True:
        raise ValueError("manifest does not require an empty destination")
    entries = manifest.get("files")
    counts = manifest.get("tables")
    if not isinstance(entries, list) or not entries or not isinstance(counts, dict):
        raise ValueError("invalid export manifest")
    paths: list[Path] = []
    for entry in entries:
        path = manifest_path.parent / entry["file"]
        if path.name != entry["file"] or path.suffix != ".sql":
            raise ValueError("unsafe SQL file in manifest")
        contents = path.read_bytes()
        if len(contents) != entry["bytes"] or hashlib.sha256(contents).hexdigest() != entry["sha256"]:
            raise ValueError(f"SQL file changed: {path.name}")
        paths.append(path)
    location = "--remote" if remote else "--local"
    existing = _query(
        wrangler, database, config, location,
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name NOT GLOB 'sqlite_*' AND name NOT GLOB '_cf_*' LIMIT 1",
    )
    if existing:
        raise RuntimeError(f"destination is not empty: {existing[0]['name']}")
    for path in paths:
        print(f"Applying {path.name}", flush=True)
        _run(wrangler, database, config, location, "--file", str(path))
    select_parts = [
        f"SELECT '{name.replace(chr(39), chr(39) * 2)}' AS table_name, "
        f"COUNT(*) AS row_count FROM {_name(name)}"
        for name in counts
    ]
    observed: list[dict] = []
    for offset in range(0, len(select_parts), 5):
        observed.extend(_query(wrangler, database, config, location,
                               " UNION ALL ".join(select_parts[offset:offset + 5])))
    actual = {row["table_name"]: int(row["row_count"]) for row in observed}
    if actual != counts:
        raise RuntimeError(f"D1 row counts differ: expected {counts}, got {actual}")
    violations = _query(wrangler, database, config, location, "PRAGMA foreign_key_check")
    if violations:
        raise RuntimeError(f"D1 foreign key violations: {violations[:3]}")
    check = _query(wrangler, database, config, location, "PRAGMA quick_check")
    if check != [{"quick_check": "ok"}]:
        raise RuntimeError(f"D1 quick_check failed: {check}")
    expected_sequences = manifest.get("sequences") or {}
    if expected_sequences:
        sequence_rows = _query(wrangler, database, config, location,
                               "SELECT name, seq FROM sqlite_sequence")
        sequences = {row["name"]: int(row["seq"]) for row in sequence_rows}
        if sequences != expected_sequences:
            raise RuntimeError(f"D1 sequences differ: expected {expected_sequences}, got {sequences}")
    print(json.dumps({"database": database, "tables": actual, "status": "verified"}, ensure_ascii=False))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("database", help="Wrangler D1 database name or binding")
    parser.add_argument("--config", required=True, type=Path, help="Wrangler config with D1 binding")
    parser.add_argument("--wrangler", help="path to Wrangler executable")
    location = parser.add_mutually_exclusive_group(required=True)
    location.add_argument("--remote", action="store_true")
    location.add_argument("--local", action="store_true")
    args = parser.parse_args()
    apply(args.manifest, args.database, args.config, remote=args.remote, wrangler=args.wrangler)


if __name__ == "__main__":
    main()
