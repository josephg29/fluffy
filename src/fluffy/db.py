"""SQLite connection + migration runner (decision D3).

One database file, WAL mode, ``busy_timeout=5000``. Migrations are numbered
``NNNN_name.sql`` scripts applied in order at ``Guard`` init, tracked in a
``schema_version`` table.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

__all__ = ["connect", "default_migrations_dir", "migrate", "utc_now_iso"]

DEFAULT_DB_PATH = Path.home() / ".fluffy" / "state.db"


def utc_now_iso() -> str:
    """UTC ISO-8601 timestamp string (the only timestamp format we store)."""
    return datetime.now(UTC).isoformat()


def default_migrations_dir() -> Path:
    """Locate the bundled migrations directory.

    Installed wheels ship migrations inside the package
    (``fluffy/migrations``); an editable/source checkout keeps them at the
    repo root per D10.
    """
    packaged = Path(__file__).resolve().parent / "migrations"
    if packaged.is_dir():
        return packaged
    repo_root = Path(__file__).resolve().parents[2] / "migrations"
    if repo_root.is_dir():
        return repo_root
    raise FileNotFoundError("fluffy migrations directory not found")


def connect(path: str | Path | None = None) -> sqlite3.Connection:
    """Open (creating if needed) the state database with WAL + busy timeout."""
    db_path = Path(path).expanduser() if path is not None else DEFAULT_DB_PATH
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def migrate(conn: sqlite3.Connection, migrations_dir: str | Path | None = None) -> list[int]:
    """Apply pending ``NNNN_*.sql`` migrations in order. Returns versions applied."""
    directory = Path(migrations_dir) if migrations_dir is not None else default_migrations_dir()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY, applied_ts TEXT)"
    )
    conn.commit()
    applied = {int(row[0]) for row in conn.execute("SELECT version FROM schema_version")}
    done: list[int] = []
    for script in sorted(directory.glob("*.sql")):
        try:
            version = int(script.name.split("_", 1)[0])
        except ValueError as exc:
            raise ValueError(f"migration filename not numbered: {script.name}") from exc
        if version in applied:
            continue
        conn.executescript(script.read_text(encoding="utf-8"))
        conn.execute(
            "INSERT INTO schema_version (version, applied_ts) VALUES (?, ?)",
            (version, utc_now_iso()),
        )
        conn.commit()
        done.append(version)
    return done
