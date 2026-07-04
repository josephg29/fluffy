from __future__ import annotations

import logging
import sqlite3
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from fluffy import Decision, DestructiveSpec, Guard, PermissionRequest, SpendSpec, ToolMeta
from fluffy.db import connect, migrate, utc_now_iso
from fluffy.permissions import PermissionBroker
from fluffy.redact import RedactionFilter, clear_secret_stores, register_secret_store
from fluffy.secrets import MemorySecretStore


def events(guard: Guard, n: int = 50) -> list[tuple[str, str]]:
    """(event, decision) projection of the audit tail — shared test helper."""
    return [(row["event"], row["decision"]) for row in guard.audit_tail(n)]


class ScriptedApprover:
    """Test approver returning a fixed decision (or ``None`` = abstain)."""

    def __init__(self, decision: Decision | None) -> None:
        self.decision = decision
        self.seen: list[PermissionRequest] = []

    async def decide(self, req: PermissionRequest) -> Decision | None:
        self.seen.append(req)
        return self.decision


def approve_all(decider: str = "scripted", expires_in_s: int | None = None) -> ScriptedApprover:
    return ScriptedApprover(
        Decision(approved=True, decider=decider, message="Approved.", expires_in_s=expires_in_s)
    )


def spend_meta(
    card_id: str = "ops",
    name: str = "stripe.charge",
    amount_from: Callable[..., int] | None = None,
) -> ToolMeta:
    return ToolMeta(
        name=name,
        tags=frozenset({"spend"}),
        spend=SpendSpec(
            card_id=card_id,
            amount_from=amount_from or (lambda args, kwargs: kwargs["amount_cents"]),
        ),
    )


def destructive_meta(name: str = "delete_project", resource_kind: str = "repo") -> ToolMeta:
    return ToolMeta(
        name=name,
        tags=frozenset({"destructive"}),
        destructive=DestructiveSpec(
            resource_kind=resource_kind,
            summary_from=lambda args, kwargs: (
                f"This deletes the {resource_kind} `{args[0]}`. This cannot be undone."
            ),
        ),
    )


def seed_whitelist(conn: sqlite3.Connection, tool: str, resource_kind: str) -> None:
    """Whitelist ``(tool, resource_kind)`` directly, as a remembered confirm would."""
    conn.execute(
        "INSERT OR IGNORE INTO action_whitelist (tool, resource_kind, added_ts) VALUES (?, ?, ?)",
        (tool, resource_kind, utc_now_iso()),
    )
    conn.commit()


def make_charge(guard: Guard, card_id: str = "ops") -> Callable[..., str]:
    def charge(*, amount_cents: int) -> str:
        return f"charged {amount_cents}"

    wrapped = guard.wrap(charge, meta=spend_meta(card_id))
    return wrapped  # type: ignore[return-value]


def ledger_rows(conn: sqlite3.Connection, card_id: str = "ops") -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM spend_ledger WHERE card_id = ? ORDER BY id", (card_id,)
    ).fetchall()


def grant_access(guard: Guard, tool_name: str) -> None:
    """Grant persistent access to a 'restricted'-tagged tool via the real broker.

    Tests that use ``"restricted"`` only as "some guard tag" (to exercise the
    full pipeline) call this; FLUF-4 gave the tag real deny-by-default
    semantics. The grant goes through ``PermissionBroker.request`` with a
    scripted always-approve approver — the same path production grants take.
    Driving the coroutine by hand keeps this callable from sync and async
    tests alike: a scripted approver never awaits, so the request completes
    in a single step.
    """
    broker = PermissionBroker(guard.connection, [approve_all()])
    coro = broker.request(
        PermissionRequest(
            kind="access_grant",
            subject=tool_name,
            value=None,
            duration="persistent",
            rationale="test setup",
        )
    )
    try:
        coro.send(None)
    except StopIteration as stop:
        assert stop.value.approved is True
    else:
        coro.close()
        raise AssertionError("scripted broker request should complete without awaiting")


@pytest.fixture(autouse=True)
def _clean_redaction_state() -> Iterator[None]:
    """Backstop: keep the module-level store registry and root logger clean.

    ``Guard.close()`` undoes its own installs; this scrub catches anything a
    test registered directly or leaked on failure.
    """
    yield
    clear_secret_stores()
    root = logging.getLogger()
    for f in list(root.filters):
        if isinstance(f, RedactionFilter):
            root.removeFilter(f)
    for handler in root.handlers:
        for f in list(handler.filters):
            if isinstance(f, RedactionFilter):
                handler.removeFilter(f)


@pytest.fixture()
def guard(tmp_path: Path) -> Iterator[Guard]:
    with Guard(db_path=tmp_path / "state.db") as g:
        yield g


@pytest.fixture()
def conn(tmp_path: Path) -> Iterator[sqlite3.Connection]:
    """An open, fully migrated state database."""
    c = connect(tmp_path / "state.db")
    migrate(c)
    yield c
    c.close()


@pytest.fixture()
def registered_store() -> MemorySecretStore:
    """An empty in-memory store registered with the global redaction registry."""
    store = MemorySecretStore()
    register_secret_store(store)
    return store
