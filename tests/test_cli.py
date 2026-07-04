"""`fluffy audit tail` / `fluffy audit grep` console entry point tests."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from conftest import make_charge
from fluffy import Blocked, Guard, SpendPolicy
from fluffy.cli import main


@pytest.fixture()
def populated_db(tmp_path: Path) -> Path:
    db = tmp_path / "state.db"
    with Guard(db_path=db) as guard:
        guard.add_spend_policy(SpendPolicy(card_id="ops"))
        charge = make_charge(guard)
        charge(amount_cents=1000)  # reserved -> settled
        with pytest.raises(Blocked):
            charge(amount_cents=9000)  # denied
    return db


def test_audit_tail(populated_db: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["audit", "tail", "-n", "50", "--db", str(populated_db)]) == 0
    out = capsys.readouterr().out
    lines = out.strip().splitlines()
    assert len(lines) >= 4
    assert any("spend_settled" in line for line in lines)
    assert any("spend_denied" in line and "blocked" in line for line in lines)
    # tail order is oldest first
    assert lines == sorted(lines, key=lambda ln: ln.split("  ")[0])


def test_audit_tail_n_limits_rows(populated_db: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["audit", "tail", "-n", "2", "--db", str(populated_db)]) == 0
    assert len(capsys.readouterr().out.strip().splitlines()) == 2


def test_audit_grep(populated_db: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["audit", "grep", "denied", "--db", str(populated_db)]) == 0
    out = capsys.readouterr().out
    lines = out.strip().splitlines()
    assert lines and all("denied" in line for line in lines)

    assert main(["audit", "grep", "no-such-term-anywhere", "--db", str(populated_db)]) == 0
    assert capsys.readouterr().out.strip() == ""


def test_audit_grep_matches_detail_json(
    populated_db: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # requested_cents=9000 only appears inside detail_json
    assert main(["audit", "grep", "9000", "--db", str(populated_db)]) == 0
    out = capsys.readouterr().out
    assert "spend_denied" in out


# --------------------------------------------------- the CLI is a pure reader


def test_missing_db_path_errors_without_creating_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    missing = tmp_path / "typo.db"
    assert main(["audit", "tail", "--db", str(missing)]) != 0
    assert str(missing) in capsys.readouterr().err
    assert not missing.exists(), "the CLI must never create a database"


def test_db_without_audit_table_means_no_events(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    empty = tmp_path / "empty.db"
    sqlite3.connect(empty).close()  # a real sqlite file, but never migrated
    assert main(["audit", "tail", "--db", str(empty)]) == 0
    assert capsys.readouterr().out.strip() == ""


def test_cli_opens_read_only(populated_db: Path) -> None:
    before = populated_db.read_bytes()
    assert main(["audit", "tail", "--db", str(populated_db)]) == 0
    assert populated_db.read_bytes() == before
