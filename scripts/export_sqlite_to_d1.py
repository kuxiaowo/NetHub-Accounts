"""Export a consistent SQLite snapshot as ordered SQL for a fresh D1 database.

This tool never connects to Cloudflare. Run each numbered SQL file with
``wrangler d1 execute <database> --remote --file <file>`` in manifest order.
The destination must be empty; reruns require a new empty D1 database.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import tempfile
from contextlib import closing
from pathlib import Path


def _name(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def _tables(db: sqlite3.Connection) -> list[tuple[str, str]]:
    rows = db.execute(
        "SELECT name, sql FROM sqlite_master WHERE type='table' "
        "AND name NOT GLOB 'sqlite_*' ORDER BY name"
    ).fetchall()
    if any(not row[1] for row in rows):
        raise ValueError("a table has no CREATE statement")
    return [(str(name), str(sql)) for name, sql in rows]


def _data_order(db: sqlite3.Connection, tables: list[str]) -> list[str]:
    names = set(tables)
    dependencies = {
        table: {
            str(row[2])
            for row in db.execute(f"PRAGMA foreign_key_list({_name(table)})")
            if str(row[2]) in names and str(row[2]) != table
        }
        for table in tables
    }
    ordered: list[str] = []
    while dependencies:
        ready = sorted(name for name, parents in dependencies.items() if not parents)
        if not ready:
            raise ValueError(f"cyclic cross-table foreign keys: {sorted(dependencies)}")
        ordered.extend(ready)
        for name in ready:
            del dependencies[name]
        for parents in dependencies.values():
            parents.difference_update(ready)
    return ordered


def _data_sql(db: sqlite3.Connection, table: str):
    columns = [str(row[1]) for row in db.execute(f"PRAGMA table_info({_name(table)})")]
    if not columns:
        raise ValueError(f"table {table!r} has no ordinary columns")
    quoted = ", ".join(map(_name, columns))
    expressions = ", ".join(f"quote({_name(column)})" for column in columns)
    width = len(columns)
    # The rowid order keeps the usual parent-before-child order for self-FKs.
    # The local replay below verifies that this is true for the actual data.
    try:
        rows = db.execute(f"SELECT {expressions}, {quoted} FROM {_name(table)} ORDER BY rowid")
    except sqlite3.OperationalError:
        rows = db.execute(f"SELECT {expressions}, {quoted} FROM {_name(table)}")
    for row in rows:
        literals = list(row[:width])
        for index, value in enumerate(row[width:]):
            # SQLite's SQL parser normalizes CRLF inside a quoted string,
            # and quote() truncates text at NUL. A hex text expression keeps
            # those stored bytes exact during D1 import.
            if isinstance(value, str) and ("\r" in value or "\x00" in value):
                literals[index] = f"CAST(X'{value.encode('utf-8').hex()}' AS TEXT)"
        yield f"INSERT INTO {_name(table)} ({quoted}) VALUES ({', '.join(literals)});\n"


def _write(path: Path, statements: list[str]) -> dict:
    contents = "".join(statements).encode("utf-8")
    path.write_bytes(contents)
    return {
        "file": path.name,
        "bytes": len(contents),
        "sha256": hashlib.sha256(contents).hexdigest(),
    }


def _rows(db: sqlite3.Connection, table: str) -> list[tuple]:
    try:
        return db.execute(f"SELECT * FROM {_name(table)} ORDER BY rowid").fetchall()
    except sqlite3.OperationalError:
        return db.execute(f"SELECT * FROM {_name(table)}").fetchall()


def _verify(files: list[Path], source: sqlite3.Connection, tables: list[str]) -> None:
    # Replaying the exact exported SQL catches broken quoting, FK ordering,
    # unsupported generated columns, and trigger/index side effects locally.
    with closing(sqlite3.connect(":memory:")) as target:
        target.execute("PRAGMA foreign_keys=ON")
        for path in files:
            target.executescript(path.read_text(encoding="utf-8"))
        errors = target.execute("PRAGMA foreign_key_check").fetchall()
        if errors:
            raise ValueError(f"exported SQL violates foreign keys: {errors[:3]}")
        for table in tables:
            original = _rows(source, table)
            copied = _rows(target, table)
            if original != copied:
                raise ValueError(f"{table}: exported rows differ from the snapshot")
        original_sequences = (
            source.execute("SELECT name, seq FROM sqlite_sequence ORDER BY name").fetchall()
            if _has_sequence(source)
            else []
        )
        copied_sequences = (
            target.execute("SELECT name, seq FROM sqlite_sequence ORDER BY name").fetchall()
            if _has_sequence(target)
            else []
        )
        if original_sequences != copied_sequences:
            raise ValueError("sqlite_sequence differs after replay")


def _has_sequence(db: sqlite3.Connection) -> bool:
    return (
        db.execute("SELECT 1 FROM sqlite_master WHERE name='sqlite_sequence'").fetchone()
        is not None
    )


def export(source_path: Path, output_dir: Path, max_chunk_bytes: int) -> dict:
    if max_chunk_bytes < 1024:
        raise ValueError("max_chunk_bytes must be at least 1024")
    if output_dir.exists() and any(output_dir.iterdir()):
        raise ValueError("output directory must be empty")
    output_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as temporary:
        snapshot_path = Path(temporary) / "snapshot.sqlite3"
        with closing(
            sqlite3.connect(f"file:{source_path.resolve().as_posix()}?mode=ro", uri=True)
        ) as live:
            with closing(sqlite3.connect(snapshot_path)) as backup:
                live.backup(backup)
        with closing(sqlite3.connect(snapshot_path)) as db:
            db.execute("PRAGMA foreign_keys=ON")
            if db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise ValueError("source SQLite quick_check failed")
            if db.execute("PRAGMA foreign_key_check").fetchone():
                raise ValueError("source SQLite foreign_key_check failed")
            tables = _tables(db)
            names = [name for name, _ in tables]
            files: list[Path] = []
            entries: list[dict] = []

            def add(filename: str, statements: list[str]) -> None:
                path = output_dir / filename
                entries.append(_write(path, statements))
                files.append(path)

            add("000-schema.sql", [sql.rstrip(";\n") + ";\n" for _, sql in tables])
            chunk: list[str] = []
            size = 0
            number = 1
            counts: dict[str, int] = {}
            for table in _data_order(db, names):
                counts[table] = 0
                for statement in _data_sql(db, table):
                    length = len(statement.encode("utf-8"))
                    if length > max_chunk_bytes:
                        raise ValueError(f"{table}: a row exceeds max_chunk_bytes")
                    if chunk and size + length > max_chunk_bytes:
                        add(f"{number:03d}-data.sql", chunk)
                        number += 1
                        chunk, size = [], 0
                    chunk.append(statement)
                    size += length
                    counts[table] += 1
            if chunk:
                add(f"{number:03d}-data.sql", chunk)
                number += 1
            if _has_sequence(db):
                sequence = []
                for table, value in db.execute(
                    "SELECT name, seq FROM sqlite_sequence ORDER BY name"
                ):
                    table_literal = db.execute("SELECT quote(?)", (table,)).fetchone()[0]
                    sequence.append(
                        f"UPDATE sqlite_sequence SET seq={int(value)} WHERE name={table_literal};\n"
                    )
                    sequence.append(
                        f"INSERT INTO sqlite_sequence(name,seq) SELECT {table_literal},{int(value)} WHERE NOT EXISTS (SELECT 1 FROM sqlite_sequence WHERE name={table_literal});\n"
                    )
                if sequence:
                    add(f"{number:03d}-sequence.sql", sequence)
                    number += 1
            other = db.execute(
                "SELECT type, name, sql FROM sqlite_master "
                "WHERE type IN ('index','trigger','view') AND sql IS NOT NULL "
                "ORDER BY CASE type WHEN 'index' THEN 0 WHEN 'view' THEN 1 ELSE 2 END, name"
            ).fetchall()
            if other:
                add(
                    f"{number:03d}-objects.sql",
                    [str(sql).rstrip(";\n") + ";\n" for _, _, sql in other],
                )
            _verify(files, db, names)
            manifest = {
                "source": str(source_path.resolve()),
                "source_sha256": hashlib.sha256(snapshot_path.read_bytes()).hexdigest(),
                "tables": counts,
                "sequences": {
                    str(name): int(value)
                    for name, value in db.execute("SELECT name, seq FROM sqlite_sequence")
                }
                if _has_sequence(db)
                else {},
                "files": entries,
                "require_empty_destination": True,
            }
            (output_dir / "manifest.json").write_text(
                json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
            )
            return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="SQLite database path")
    parser.add_argument("output_dir", type=Path, help="new or empty output directory")
    parser.add_argument("--max-chunk-bytes", type=int, default=500_000)
    args = parser.parse_args()
    manifest = export(args.source, args.output_dir, args.max_chunk_bytes)
    print(json.dumps({"tables": manifest["tables"], "files": len(manifest["files"])}))


if __name__ == "__main__":
    main()
