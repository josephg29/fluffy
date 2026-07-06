"""``fluffy`` console entry point (stdlib argparse only).

Commands::

    fluffy audit tail [-n 50] [--db PATH]
    fluffy audit grep <term> [-n 200] [--db PATH]

Both read the audit log written by every guard (one consistent event
vocabulary across all four guards — see docs/events.md). Output is one line
per event: ``ts  event  decision  tool  call_id  detail_json``. Detail JSON is
already redacted at write time, so nothing here can leak a secret.

The CLI is strictly a reader: the database is opened read-only and never
migrated, and a missing file is an error rather than a freshly created DB.
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path

from . import __version__
from .audit import audit_grep, audit_tail
from .db import DEFAULT_DB_PATH

__all__ = ["main"]

#: Column order of every output line (also the header row on a terminal).
COLUMNS = ("ts", "event", "decision", "tool", "call_id", "detail_json")


def _interactive() -> bool:
    """Is stdout a terminal? (Seam for tests; capture replaces stdout.)"""
    isatty = getattr(sys.stdout, "isatty", None)
    return bool(isatty and isatty())


def _print_rows(rows: Iterable[sqlite3.Row], empty_message: str) -> None:
    """One line per event, ``COLUMNS`` order.

    A header row and a friendly empty-result message appear only on a
    terminal, so piped output stays clean machine-readable lines.
    """
    interactive = _interactive()
    printed = False
    for row in rows:
        if interactive and not printed:
            print("  ".join(COLUMNS))
        printed = True
        print("  ".join(str(row[col]) for col in COLUMNS))
    if not printed and interactive:
        print(empty_message)


def _open_readonly(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def _build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--db", default=None, help=f"state database (default {DEFAULT_DB_PATH})")

    parser = argparse.ArgumentParser(prog="fluffy", description="fluffy guard-layer CLI")
    parser.add_argument("--version", action="version", version=f"fluffy-guard {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    audit = sub.add_parser("audit", help="inspect the audit log")
    audit_sub = audit.add_subparsers(dest="audit_command", required=True)

    tail = audit_sub.add_parser("tail", parents=[common], help="show the most recent audit events")
    tail.add_argument("-n", type=_non_negative, default=50, help="number of events (default 50)")

    grep = audit_sub.add_parser("grep", parents=[common], help="search audit events for a term")
    grep.add_argument("term", help="substring to search for (case-insensitive)")
    grep.add_argument("-n", type=_non_negative, default=200, help="max matches shown (default 200)")

    return parser


def _non_negative(value: str) -> int:
    n = int(value)
    if n < 0:  # a negative SQLite LIMIT means "no limit" — never dump the table
        raise argparse.ArgumentTypeError(f"-n must be >= 0, got {n}")
    return n


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    db_path = Path(args.db).expanduser() if args.db is not None else DEFAULT_DB_PATH
    if not db_path.exists():
        print(f"fluffy: no state database at {db_path}", file=sys.stderr)
        return 2
    conn = _open_readonly(db_path)
    try:
        if args.audit_command == "tail":
            _print_rows(audit_tail(conn, args.n), "(no audit events yet)")
        else:
            _print_rows(
                audit_grep(conn, args.term, args.n),
                f"(no audit events match {args.term!r})",
            )
    except sqlite3.OperationalError as exc:
        if "no such table" not in str(exc):
            raise
        # An un-migrated (or foreign) database simply has no events yet.
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
