"""FLUF-4 permission broker + guardian bot tests (decision D7)."""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from conftest import ScriptedApprover, approve_all, events, make_charge, spend_meta
from fluffy import (
    ConsoleApprover,
    Decision,
    Guard,
    GuardianBot,
    PermissionDenied,
    PermissionRequest,
    SpendLimitExceeded,
    SpendPolicy,
    ToolMeta,
)
from fluffy.spend import Caps


def deny_all(decider: str = "scripted") -> ScriptedApprover:
    return ScriptedApprover(
        Decision(approved=False, decider=decider, message="Denied: not this time.")
    )


def abstain() -> ScriptedApprover:
    return ScriptedApprover(None)


def budget_req(delta_cents: int, card_id: str = "ops", duration: str = "once") -> PermissionRequest:
    return PermissionRequest(
        kind="budget_increase",
        subject=card_id,
        value=delta_cents,
        duration=duration,  # type: ignore[arg-type]
        rationale="need to cover a larger charge",
    )


def access_req(tool_name: str, duration: str = "persistent") -> PermissionRequest:
    return PermissionRequest(
        kind="access_grant",
        subject=tool_name,
        value=None,
        duration=duration,  # type: ignore[arg-type]
        rationale="need this tool for the task",
    )


def restricted_meta(name: str = "prod.db.query") -> ToolMeta:
    return ToolMeta(name=name, tags=frozenset({"restricted"}))


def permission_rows(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM permissions ORDER BY id").fetchall()


def race_two(worker: Callable[[threading.Barrier], str]) -> list[str]:
    """Run ``worker(barrier)`` in two threads; return sorted outcomes.

    Worker exceptions are captured and re-raised here instead of dying
    silently inside the thread.
    """
    barrier = threading.Barrier(2)
    results: list[str] = []
    errors: list[BaseException] = []

    def run() -> None:
        try:
            results.append(worker(barrier))
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=run) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    if errors:
        raise errors[0]
    return sorted(results)


@pytest.fixture()
def approving_guard(tmp_path: Path) -> Any:
    with Guard(db_path=tmp_path / "state.db", approvers=[approve_all()]) as g:
        g.add_spend_policy(SpendPolicy(card_id="ops"))  # $25 per-use / daily
        yield g


# ------------------------------------------------------ once budget increases


def test_once_grant_admits_one_spend_then_is_consumed(approving_guard: Guard) -> None:
    """Acceptance: $25 cap, $40 blocked -> once grant -> retry ok -> $40 blocked again."""
    charge = make_charge(approving_guard)
    with pytest.raises(SpendLimitExceeded):
        charge(amount_cents=4000)

    decision = approving_guard.request_permission_sync(budget_req(1500, duration="once"))
    assert decision.approved is True

    assert charge(amount_cents=4000) == "charged 4000"

    # The grant is consumed: an identical spend fails again.
    with pytest.raises(SpendLimitExceeded):
        charge(amount_cents=4000)
    rows = permission_rows(approving_guard.connection)
    assert len(rows) == 1
    assert rows[0]["consumed_ts"] is not None


def test_once_grant_not_consumed_by_spend_that_fits_base_caps(approving_guard: Guard) -> None:
    approving_guard.request_permission_sync(budget_req(1500, duration="once"))
    charge = make_charge(approving_guard)
    assert charge(amount_cents=1000) == "charged 1000"  # fits the $25 base caps
    rows = permission_rows(approving_guard.connection)
    assert rows[0]["consumed_ts"] is None  # still live for the spend that needs it


def test_tool_error_restores_consumed_once_grant(approving_guard: Guard) -> None:
    approving_guard.request_permission_sync(budget_req(1500, duration="once"))

    def broken(*, amount_cents: int) -> str:
        raise RuntimeError("card network down")

    wrapped: Any = approving_guard.wrap(broken, meta=spend_meta())
    with pytest.raises(RuntimeError):
        wrapped(amount_cents=4000)

    rows = permission_rows(approving_guard.connection)
    assert rows[0]["consumed_ts"] is None  # released spend gave the grant back
    assert "grant_restored" in [event for event, _ in events(approving_guard, 30)]
    # And the restored grant admits the retry.
    assert make_charge(approving_guard)(amount_cents=4000) == "charged 4000"


def test_effective_caps_layer_grants_on_base_policy(approving_guard: Guard) -> None:
    base = Caps(per_use_cap_cents=2500, daily_cap_cents=2500)
    now = datetime.now(UTC)
    assert approving_guard._spend.effective_caps("ops", now) == base

    approving_guard.request_permission_sync(budget_req(1500, duration="persistent"))
    boosted = Caps(per_use_cap_cents=4000, daily_cap_cents=4000)
    assert approving_guard._spend.effective_caps("ops", now) == boosted


# ------------------------------------------------------------ persistence


def test_persistent_grant_survives_guard_restart(tmp_path: Path) -> None:
    db_path = tmp_path / "state.db"
    with Guard(db_path=db_path, approvers=[approve_all()]) as g1:
        g1.add_spend_policy(SpendPolicy(card_id="ops"))
        decision = g1.request_permission_sync(budget_req(1500, duration="persistent"))
        assert decision.approved is True
        with pytest.raises(SpendLimitExceeded):
            make_charge(g1)(amount_cents=4500)  # above even the boosted caps

    with Guard(db_path=db_path) as g2:  # default (console) chain: no approvals here
        g2.add_spend_policy(SpendPolicy(card_id="ops"))
        assert make_charge(g2)(amount_cents=4000) == "charged 4000"
        # Persistent: not consumed by use.
        assert permission_rows(g2.connection)[0]["consumed_ts"] is None


# ------------------------------------------------------------- guardian bot


async def test_guardian_bot_auto_approves_under_threshold(tmp_path: Path) -> None:
    with Guard(db_path=tmp_path / "state.db", approvers=[GuardianBot(100)]) as g:
        g.add_spend_policy(SpendPolicy(card_id="ops"))
        decision = await g.request_permission(budget_req(50))
        assert decision.approved is True
        assert decision.decider == "guardian_bot"
        row = g.audit_tail(5)[-1]
        assert row["event"] == "permission_granted"
        assert '"decider": "guardian_bot"' in row["detail_json"]
        assert permission_rows(g.connection)[0]["decider"] == "guardian_bot"


async def test_guardian_bot_abstains_over_threshold_falls_through(tmp_path: Path) -> None:
    fallback = deny_all("human")
    with Guard(db_path=tmp_path / "state.db", approvers=[GuardianBot(100), fallback]) as g:
        g.add_spend_policy(SpendPolicy(card_id="ops"))
        decision = await g.request_permission(budget_req(1000))
        assert decision.approved is False
        assert decision.decider == "human"
        assert len(fallback.seen) == 1  # the $10 request fell through to it


async def test_guardian_bot_alone_over_threshold_denies_exhausted(tmp_path: Path) -> None:
    with Guard(db_path=tmp_path / "state.db", approvers=[GuardianBot(100)]) as g:
        g.add_spend_policy(SpendPolicy(card_id="ops"))
        decision = await g.request_permission(budget_req(1000))
        assert decision.approved is False
        assert decision.decider == "exhausted"
        assert decision.message  # relayable verbatim
        assert permission_rows(g.connection) == []


async def test_guardian_bot_always_abstains_on_access_grant(tmp_path: Path) -> None:
    with Guard(db_path=tmp_path / "state.db", approvers=[GuardianBot(10_000)]) as g:
        decision = await g.request_permission(access_req("prod.db.query"))
        assert decision.approved is False
        assert decision.decider == "exhausted"


async def test_guardian_bot_abstains_on_malformed_value(tmp_path: Path) -> None:
    with Guard(db_path=tmp_path / "state.db", approvers=[GuardianBot(100)]) as g:
        g.add_spend_policy(SpendPolicy(card_id="ops"))
        req = PermissionRequest(
            kind="budget_increase", subject="ops", value="fifty", duration="once", rationale="?"
        )
        assert (await g.request_permission(req)).decider == "exhausted"


# ------------------------------------------------------------------- denials


async def test_denied_request_writes_no_row_and_message_is_usable(tmp_path: Path) -> None:
    with Guard(db_path=tmp_path / "state.db", approvers=[deny_all()]) as g:
        g.add_spend_policy(SpendPolicy(card_id="ops"))
        decision = await g.request_permission(budget_req(1500))
        assert decision.approved is False
        assert isinstance(decision.message, str) and decision.message.strip()
        assert permission_rows(g.connection) == []
        assert ("permission_denied", "denied") in events(g, 10)


# ------------------------------------------------------------ console approver


async def test_console_approver_abstains_without_tty(tmp_path: Path) -> None:
    # pytest runs with a non-TTY stdin; no input_fn injected -> abstain, no hang.
    assert await ConsoleApprover().decide(budget_req(1500)) is None
    with Guard(db_path=tmp_path / "state.db") as g:  # default chain = [ConsoleApprover]
        g.add_spend_policy(SpendPolicy(card_id="ops"))
        decision = await g.request_permission(budget_req(1500))
        assert decision.approved is False
        assert decision.decider == "exhausted"


async def test_console_approver_scripted_approve_and_deny() -> None:
    rendered: list[str] = []
    approver = ConsoleApprover(input_fn=iter(["approve"]).__next__, output_fn=rendered.append)
    req = budget_req(1500)
    decision = await approver.decide(req)
    assert decision is not None and decision.approved is True
    assert decision.decider == "console"
    text = "\n".join(rendered)
    for fragment in ("budget_increase", "ops", "1500", "once", "larger charge"):
        assert fragment in text  # kind/subject/value/duration/rationale all rendered

    denier = ConsoleApprover(input_fn=iter(["deny"]).__next__, output_fn=rendered.append)
    denied = await denier.decide(req)
    assert denied is not None and denied.approved is False


async def test_console_approver_reprompts_on_garbage_and_abstains_on_eof() -> None:
    out: list[str] = []
    approver = ConsoleApprover(input_fn=iter(["what", "yes"]).__next__, output_fn=out.append)
    decision = await approver.decide(budget_req(10))
    assert decision is not None and decision.approved is True
    assert any("approve" in line and "deny" in line for line in out)  # re-prompt happened

    eof = ConsoleApprover(input_fn=iter(["hmm"]).__next__, output_fn=out.append)
    assert await eof.decide(budget_req(10)) is None  # script exhausted -> abstain


# --------------------------------------------------------------- access grants


def test_restricted_tool_denied_without_grant(approving_guard: Guard) -> None:
    tool: Any = approving_guard.wrap(lambda: "secret data", meta=restricted_meta())
    with pytest.raises(PermissionDenied) as excinfo:
        tool()
    assert "restricted" in str(excinfo.value)
    assert ("access_denied", "blocked") in events(approving_guard, 10)


def test_restricted_tool_runs_with_persistent_grant(approving_guard: Guard) -> None:
    approving_guard.request_permission_sync(access_req("prod.db.query"))
    tool: Any = approving_guard.wrap(lambda: "secret data", meta=restricted_meta())
    assert tool() == "secret data"
    assert tool() == "secret data"  # persistent: not consumed
    assert ("access_allowed", "ok") in events(approving_guard, 20)


def test_restricted_once_grant_consumed_on_first_use(approving_guard: Guard) -> None:
    approving_guard.request_permission_sync(access_req("prod.db.query", duration="once"))
    tool: Any = approving_guard.wrap(lambda: "secret data", meta=restricted_meta())
    assert tool() == "secret data"
    with pytest.raises(PermissionDenied):
        tool()


def test_access_grant_expiry_honored_via_now_fn(tmp_path: Path) -> None:
    # Expiry is the APPROVER's call: the scripted approver bounds its own
    # approval to one hour via Decision.expires_in_s.
    start = datetime(2026, 7, 3, 12, 0, tzinfo=UTC)
    with Guard(db_path=tmp_path / "state.db", approvers=[approve_all(expires_in_s=3600)]) as g:
        g._permission.now_fn = lambda: start
        g._broker.now_fn = lambda: start
        g.request_permission_sync(access_req("prod.db.query"))

        tool: Any = g.wrap(lambda: "secret data", meta=restricted_meta())
        assert tool() == "secret data"  # inside the approver-set lifetime

        g._permission.now_fn = lambda: start + timedelta(hours=2)
        with pytest.raises(PermissionDenied):
            tool()


def test_budget_grant_expiry_honored_via_now_fn(tmp_path: Path) -> None:
    start = datetime(2026, 7, 3, 12, 0, tzinfo=UTC)
    with Guard(db_path=tmp_path / "state.db", approvers=[approve_all(expires_in_s=3600)]) as g:
        g.add_spend_policy(SpendPolicy(card_id="ops"))
        g._spend.now_fn = lambda: start
        g._broker.now_fn = lambda: start
        g.request_permission_sync(budget_req(1500, duration="persistent"))
        charge = make_charge(g)

        g._spend.now_fn = lambda: start + timedelta(hours=2)
        with pytest.raises(SpendLimitExceeded):
            charge(amount_cents=4000)  # grant expired: back to base caps


# ---------------------------------------------------------------- concurrency


def test_two_spends_race_one_once_grant_exactly_one_succeeds(tmp_path: Path) -> None:
    db_path = tmp_path / "state.db"
    with Guard(db_path=db_path, approvers=[approve_all()]) as setup:
        setup.add_spend_policy(SpendPolicy(card_id="ops"))
        assert setup.request_permission_sync(budget_req(1500, duration="once")).approved

    def worker(barrier: threading.Barrier) -> str:
        with Guard(db_path=db_path) as g:
            g.add_spend_policy(SpendPolicy(card_id="ops"))
            charge = make_charge(g)
            barrier.wait()
            try:
                charge(amount_cents=4000)
                return "settled"
            except SpendLimitExceeded:
                return "blocked"

    assert race_two(worker) == ["blocked", "settled"]

    check = sqlite3.connect(db_path)
    try:
        states = [r[0] for r in check.execute("SELECT state FROM spend_ledger")]
        assert states == ["settled"]  # the loser reserved nothing
        consumed = [r[0] for r in check.execute("SELECT consumed_ts IS NOT NULL FROM permissions")]
        assert consumed == [1]  # the single grant was consumed exactly once
    finally:
        check.close()


def test_two_restricted_calls_race_one_once_access_grant(tmp_path: Path) -> None:
    db_path = tmp_path / "state.db"
    with Guard(db_path=db_path, approvers=[approve_all()]) as setup:
        assert setup.request_permission_sync(access_req("prod.db.query", duration="once")).approved

    def worker(barrier: threading.Barrier) -> str:
        with Guard(db_path=db_path) as g:
            tool: Any = g.wrap(lambda: "secret data", meta=restricted_meta())
            barrier.wait()
            try:
                tool()
                return "ran"
            except PermissionDenied:
                return "denied"

    assert race_two(worker) == ["denied", "ran"]


# -------------------------------------------------------------- chain ordering


async def test_chain_first_non_abstain_wins(tmp_path: Path) -> None:
    second = approve_all("second")
    third = deny_all("third")
    with Guard(db_path=tmp_path / "state.db", approvers=[abstain(), second, third]) as g:
        g.add_spend_policy(SpendPolicy(card_id="ops"))
        decision = await g.request_permission(budget_req(1500))
        assert decision.approved is True
        assert decision.decider == "second"
        assert third.seen == []  # never consulted


async def test_granted_audit_row_carries_decider(tmp_path: Path) -> None:
    with Guard(db_path=tmp_path / "state.db", approvers=[approve_all("boss")]) as g:
        g.add_spend_policy(SpendPolicy(card_id="ops"))
        await g.request_permission(budget_req(1500))
        row = g.audit_tail(5)[-1]
        assert row["event"] == "permission_granted"
        assert '"decider": "boss"' in row["detail_json"]
