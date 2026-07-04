"""Guard pipeline tests, including the FLUF-1 acceptance criteria."""

from __future__ import annotations

import json
import logging
import sqlite3
from pathlib import Path

import pytest

from fluffy import Guard, ToolMeta

SECRET = "sup3r-s3cret-db-pass"
HANDLE = "{{secret:db_pass}}"


# ------------------------------------------------------- secret handle roundtrip


def test_secret_handle_roundtrip(
    guard: Guard, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Tool sees the real value; logs, audit rows, result, and DB bytes do not."""
    caplog.set_level(logging.INFO)
    guard.secret_store.put("db_pass", SECRET)
    seen: list[str] = []

    def connect_db(password: str) -> str:
        seen.append(password)
        logging.getLogger("tool.connect").info("connecting with %s", password)
        return f"connected using {password}"

    wrapped = guard.wrap(connect_db, meta=ToolMeta(name="db.connect", tags={"restricted"}))
    result = wrapped(HANDLE)

    # tool received the real value
    assert seen == [SECRET]
    # returned result contains only the handle
    assert result == f"connected using {HANDLE}"
    assert SECRET not in str(result)
    # caplog output contains only the handle
    assert SECRET not in caplog.text
    assert HANDLE in caplog.text
    # audit rows contain only the handle
    rows = guard.audit_tail(10)
    assert len(rows) == 1
    assert rows[0]["tool"] == "db.connect"
    assert rows[0]["decision"] == "ok"
    detail = rows[0]["detail_json"]
    assert SECRET not in detail
    assert HANDLE in detail
    # grep the DB file bytes (including WAL) for the secret -> absent
    guard.close()
    for suffix in ("", "-wal", "-shm"):
        f = tmp_path / f"state.db{suffix}"
        if f.exists():
            assert SECRET.encode() not in f.read_bytes()


# ------------------------------------------------------------------ async tools


async def test_async_wrapped_tool_works(guard: Guard) -> None:
    """Secrets resolve/mask on the fast path too — 'net' is not a guard tag."""
    guard.secret_store.put("tok", "async-secret-token")

    async def fetch(token: str, n: int) -> str:
        assert token == "async-secret-token"
        return f"fetched {n} with {token}"

    wrapped = guard.wrap(fetch, meta=ToolMeta(name="api.fetch", tags={"net"}))
    result = await wrapped("{{secret:tok}}", 3)
    assert result == "fetched 3 with {{secret:tok}}"


async def test_async_after_hooks_run_when_tool_raises(guard: Guard) -> None:
    async def boom() -> None:
        raise ValueError("async kaboom")

    wrapped = guard.wrap(boom, meta=ToolMeta(name="api.boom", tags={"restricted"}))
    with pytest.raises(ValueError, match="async kaboom"):
        await wrapped()
    rows = guard.audit_tail(5)
    assert rows[-1]["decision"] == "error"
    assert "async kaboom" in rows[-1]["detail_json"]


# ------------------------------------------------- after() hooks on tool errors


def test_after_interceptors_run_when_tool_raises(guard: Guard) -> None:
    ran: list[str] = []

    class Probe:
        def before(self, ctx: object) -> None:
            ran.append("before")

        def after(self, ctx: object) -> None:
            ran.append("after")

    # splice a probe into the after chain to observe the guarantee directly
    guard._after_chain = (Probe(), *guard._after_chain)

    def explode() -> None:
        raise RuntimeError("tool blew up")

    wrapped = guard.wrap(explode, meta=ToolMeta(name="x.explode", tags={"restricted"}))
    with pytest.raises(RuntimeError, match="tool blew up"):
        wrapped()
    assert "after" in ran
    # and the audit interceptor (an after hook) recorded the failure
    rows = guard.audit_tail(5)
    assert rows[-1]["decision"] == "error"


def test_after_hook_exception_does_not_mask_result(guard: Guard) -> None:
    class Bad:
        def before(self, ctx: object) -> None:
            return None

        def after(self, ctx: object) -> None:
            raise RuntimeError("after hook bug")

    guard._after_chain = (Bad(), *guard._after_chain)
    wrapped = guard.wrap(lambda: "ok", meta=ToolMeta(name="t.fine", tags={"restricted"}))
    assert wrapped() == "ok"


# ------------------------------------------------------------- untagged hot path


def test_untagged_call_performs_zero_sqlite_statements(guard: Guard) -> None:
    statements: list[str] = []
    guard.connection.set_trace_callback(statements.append)
    try:
        wrapped = guard.wrap(lambda a, b: a + b, meta=ToolMeta(name="math.add"))
        assert wrapped(2, 3) == 5
        assert wrapped(b=1, a=2) == 3
        # non-guard tags take the same zero-I/O fast path (D8)
        tagged = guard.wrap(lambda: "hi", meta=ToolMeta(name="net.ping", tags={"net"}))
        assert tagged() == "hi"
    finally:
        guard.connection.set_trace_callback(None)
    assert statements == []


def test_guard_tagged_call_writes_exactly_one_audit_row(guard: Guard) -> None:
    wrapped = guard.wrap(lambda: "done", meta=ToolMeta(name="t.tagged", tags={"restricted"}))
    wrapped()
    rows = guard.audit_tail(10)
    assert len(rows) == 1
    assert rows[0]["event"] == "call"
    detail = json.loads(rows[0]["detail_json"])
    assert detail["result"] == "done"


# ---------------------------------------------------------------------- misc


def test_wrap_preserves_function_identity(guard: Guard) -> None:
    def my_tool(x: int) -> int:
        """docstring"""
        return x

    wrapped = guard.wrap(my_tool, meta=ToolMeta(name="t"))
    assert wrapped.__name__ == "my_tool"
    assert wrapped.__doc__ == "docstring"


def test_guard_reopens_existing_db(tmp_path: Path) -> None:
    g1 = Guard(db_path=tmp_path / "state.db")
    g1.close()
    g2 = Guard(db_path=tmp_path / "state.db")  # migrations idempotent
    assert isinstance(g2.connection, sqlite3.Connection)
    g2.close()
