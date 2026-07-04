from __future__ import annotations

from pathlib import Path

from fluffy import db


def test_connect_enables_wal_and_busy_timeout(tmp_path: Path) -> None:
    conn = db.connect(tmp_path / "state.db")
    try:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 5000
    finally:
        conn.close()


def test_migrate_creates_all_five_tables(tmp_path: Path) -> None:
    conn = db.connect(tmp_path / "state.db")
    try:
        applied = db.migrate(conn)
        assert applied == [1, 2, 3, 4]
        tables = {
            row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        assert {
            "audit_log",
            "spend_ledger",
            "confirmations",
            "action_whitelist",
            "permissions",
            "schema_version",
        } <= tables
        indexes = {
            row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")
        }
        assert "idx_spend_ledger_card_ts" in indexes
        assert "idx_permissions_live_kind_subject" in indexes
    finally:
        conn.close()


def test_migrate_is_idempotent(tmp_path: Path) -> None:
    conn = db.connect(tmp_path / "state.db")
    try:
        assert db.migrate(conn) == [1, 2, 3, 4]
        assert db.migrate(conn) == []
        versions = [row[0] for row in conn.execute("SELECT version FROM schema_version")]
        assert versions == [1, 2, 3, 4]
    finally:
        conn.close()


def test_spend_ledger_state_check_constraint(tmp_path: Path) -> None:
    import sqlite3

    import pytest

    conn = db.connect(tmp_path / "state.db")
    try:
        db.migrate(conn)
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO spend_ledger (card_id, ts, amount_cents, state, call_id)"
                " VALUES ('c', 't', 1, 'bogus', 'x')"
            )
    finally:
        conn.close()
