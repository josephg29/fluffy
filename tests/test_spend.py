"""FLUF-2 spend guard tests (decision D5)."""

from __future__ import annotations

import sqlite3
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import pytest

from conftest import events, ledger_rows, make_charge, spend_meta
from fluffy import Guard, GuardConfigError, SpendLimitExceeded, SpendPolicy, ToolMeta
from fluffy.spend import Caps, day_window_utc

LA = ZoneInfo("America/Los_Angeles")


@pytest.fixture()
def spend_guard(guard: Guard) -> Guard:
    guard.add_spend_policy(SpendPolicy(card_id="ops"))  # $25 per-use / $25 daily defaults
    return guard


# ---------------------------------------------------------------- basic caps


def test_over_cap_blocked_with_full_message_and_no_ledger_residue(spend_guard: Guard) -> None:
    charge = make_charge(spend_guard)
    with pytest.raises(SpendLimitExceeded) as excinfo:
        charge(amount_cents=5000)
    exc = excinfo.value
    message = str(exc)
    assert "$50.00" in message  # requested
    assert "$25.00" in message  # cap
    assert "$0.00" in message  # spent today
    assert "remaining" in message and "$25.00 remaining" in message
    assert exc.requested_cents == 5000
    assert exc.cap_cents == 2500
    assert exc.spent_cents == 0
    assert exc.remaining_cents == 2500
    assert exc.cap_kind == "per-use"
    assert exc.payload == {
        "requested_cents": 5000,
        "cap_cents": 2500,
        "spent_cents": 0,
        "remaining_cents": 2500,
        "cap_kind": "per-use",
    }
    # No ledger residue: nothing reserved, nothing at all for the card.
    assert ledger_rows(spend_guard.connection) == []


def test_success_settles_then_over_cap_blocks_with_spent_today(spend_guard: Guard) -> None:
    charge = make_charge(spend_guard)
    assert charge(amount_cents=1000) == "charged 1000"
    rows = ledger_rows(spend_guard.connection)
    assert [(r["amount_cents"], r["state"]) for r in rows] == [(1000, "settled")]

    with pytest.raises(SpendLimitExceeded) as excinfo:
        charge(amount_cents=5000)
    assert excinfo.value.spent_cents == 1000
    assert "$10.00 already spent today" in str(excinfo.value)


def test_daily_cap_blocks_even_under_per_use_cap(guard: Guard) -> None:
    guard.add_spend_policy(
        SpendPolicy(card_id="ops", per_use_cap_cents=10_000, daily_cap_cents=2500)
    )
    charge = make_charge(guard)
    charge(amount_cents=2000)
    with pytest.raises(SpendLimitExceeded) as excinfo:
        charge(amount_cents=1000)  # under per-use, over daily
    exc = excinfo.value
    assert exc.cap_cents == 2500
    assert exc.spent_cents == 2000
    assert exc.remaining_cents == 500
    assert "daily cap" in str(exc)
    assert "$5.00 remaining" in str(exc)


# ---------------------------------------------------------------- concurrency


def test_concurrent_spends_exactly_one_settles_50x(tmp_path: Path) -> None:
    """Two $15 spends race a $25 daily cap: exactly one settles, one raises."""
    db_path = tmp_path / "state.db"
    with Guard(db_path=db_path):
        pass  # run migrations once up front

    def run_race(card_id: str) -> list[str]:
        barrier = threading.Barrier(2)
        results: list[str] = []

        def worker() -> None:
            with Guard(db_path=db_path) as g:
                g.add_spend_policy(SpendPolicy(card_id=card_id))
                charge = make_charge(g, card_id)
                barrier.wait()
                try:
                    charge(amount_cents=1500)
                    outcome = "settled"
                except SpendLimitExceeded:
                    outcome = "blocked"
            # No lock needed: list.append is atomic and both threads are
            # joined before results is read.
            results.append(outcome)

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        return results

    check = sqlite3.connect(db_path)
    try:
        for i in range(50):
            card_id = f"card-{i}"
            assert sorted(run_race(card_id)) == ["blocked", "settled"], f"iteration {i}"
            states = [
                row[0]
                for row in check.execute(
                    "SELECT state FROM spend_ledger WHERE card_id = ?", (card_id,)
                )
            ]
            assert states == ["settled"], f"iteration {i}: {states}"
    finally:
        check.close()


# ------------------------------------------------------------- release paths


def test_tool_error_releases_reservation_and_restores_budget(spend_guard: Guard) -> None:
    def broken(*, amount_cents: int) -> str:
        raise RuntimeError("card network down")

    wrapped: Any = spend_guard.wrap(broken, meta=spend_meta())
    with pytest.raises(RuntimeError):
        wrapped(amount_cents=1000)
    rows = ledger_rows(spend_guard.connection)
    assert [(r["amount_cents"], r["state"]) for r in rows] == [(1000, "released")]

    # Next spend sees the full budget again: the whole daily cap fits.
    charge = make_charge(spend_guard)
    assert charge(amount_cents=2500) == "charged 2500"


def test_stale_reservation_treated_as_released(spend_guard: Guard) -> None:
    """Crash-orphaned `reserved` rows older than 15 min stop counting."""
    now = datetime(2026, 7, 3, 12, 0, tzinfo=UTC)
    spend_guard._spend.now_fn = lambda: now
    stale_ts = (now - timedelta(minutes=16)).isoformat()
    spend_guard.connection.execute(
        "INSERT INTO spend_ledger (card_id, ts, amount_cents, state, call_id)"
        " VALUES ('ops', ?, 2000, 'reserved', 'crashed-call')",
        (stale_ts,),
    )
    spend_guard.connection.commit()

    charge = make_charge(spend_guard)
    assert charge(amount_cents=2500) == "charged 2500"  # orphan not counted


def test_fresh_reservation_still_counts(spend_guard: Guard) -> None:
    now = datetime(2026, 7, 3, 12, 0, tzinfo=UTC)
    spend_guard._spend.now_fn = lambda: now
    fresh_ts = (now - timedelta(minutes=5)).isoformat()
    spend_guard.connection.execute(
        "INSERT INTO spend_ledger (card_id, ts, amount_cents, state, call_id)"
        " VALUES ('ops', ?, 1000, 'reserved', 'in-flight-call')",
        (fresh_ts,),
    )
    spend_guard.connection.commit()

    charge = make_charge(spend_guard)
    with pytest.raises(SpendLimitExceeded) as excinfo:
        charge(amount_cents=2000)
    assert excinfo.value.spent_cents == 1000


# ------------------------------------------------------------ timezone window


def test_tz_window_spends_straddling_local_midnight_land_on_different_days(
    guard: Guard,
) -> None:
    guard.add_spend_policy(SpendPolicy(card_id="ops", tz="America/Los_Angeles"))
    charge = make_charge(guard)
    interceptor = guard._spend

    late = datetime(2026, 7, 1, 23, 30, tzinfo=LA)
    interceptor.now_fn = lambda: late
    assert charge(amount_cents=2000) == "charged 2000"

    # Still the same LA day: budget nearly gone.
    later_same_day = datetime(2026, 7, 1, 23, 45, tzinfo=LA)
    interceptor.now_fn = lambda: later_same_day
    with pytest.raises(SpendLimitExceeded):
        charge(amount_cents=1000)

    # 00:30 the next LA day: fresh window, same-size spend fits again.
    past_midnight = datetime(2026, 7, 2, 0, 30, tzinfo=LA)
    interceptor.now_fn = lambda: past_midnight
    assert charge(amount_cents=2000) == "charged 2000"


def test_day_window_utc_bounds() -> None:
    now = datetime(2026, 7, 1, 23, 30, tzinfo=LA)  # PDT = UTC-7
    start, end = day_window_utc(now, "America/Los_Angeles")
    assert start == "2026-07-01T07:00:00+00:00"
    assert end == "2026-07-02T07:00:00+00:00"


# ---------------------------------------------------------------- persistence


def test_restart_persistence_new_guard_sees_prior_spend(tmp_path: Path) -> None:
    db_path = tmp_path / "state.db"
    with Guard(db_path=db_path) as g1:
        g1.add_spend_policy(SpendPolicy(card_id="ops"))
        make_charge(g1)(amount_cents=1000)

    with Guard(db_path=db_path) as g2:
        g2.add_spend_policy(SpendPolicy(card_id="ops"))
        with pytest.raises(SpendLimitExceeded) as excinfo:
            make_charge(g2)(amount_cents=2000)
        assert excinfo.value.spent_cents == 1000
        # And a fitting spend still works.
        assert make_charge(g2)(amount_cents=1500) == "charged 1500"


# ------------------------------------------------------------- caps seam


def test_effective_caps_returns_base_policy_caps(guard: Guard) -> None:
    """The FLUF-4 seam: today it returns exactly the base policy caps.

    ``now`` is part of the seam signature (FLUF-4 grant expiry) but must not
    affect base-policy caps.
    """
    guard.add_spend_policy(SpendPolicy(card_id="ops", per_use_cap_cents=1234, daily_cap_cents=5678))
    expected = Caps(per_use_cap_cents=1234, daily_cap_cents=5678)
    assert guard._spend.effective_caps("ops", datetime.now(UTC)) == expected
    assert guard._spend.effective_caps("ops", datetime(2020, 1, 1, tzinfo=UTC)) == expected


# ---------------------------------------------------------------------- audit


def test_settled_and_denied_spends_visible_in_audit_tail(spend_guard: Guard) -> None:
    charge = make_charge(spend_guard)
    charge(amount_cents=1000)
    with pytest.raises(SpendLimitExceeded):
        charge(amount_cents=5000)

    evs = events(spend_guard, 20)
    assert ("spend_reserved", "ok") in evs
    assert ("spend_settled", "ok") in evs
    assert ("spend_denied", "blocked") in evs
    assert ("call", "ok") in evs
    assert ("call", "blocked") in evs


def test_released_spend_visible_in_audit_tail(spend_guard: Guard) -> None:
    def broken(*, amount_cents: int) -> str:
        raise RuntimeError("boom")

    wrapped: Any = spend_guard.wrap(broken, meta=spend_meta())
    with pytest.raises(RuntimeError):
        wrapped(amount_cents=500)
    assert "spend_released" in [event for event, _ in events(spend_guard, 20)]


# --------------------------------------------------------------- config errors


def test_missing_policy_raises_config_error_no_residue(guard: Guard) -> None:
    charge = make_charge(guard, card_id="unknown-card")
    with pytest.raises(GuardConfigError, match="no spend policy"):
        charge(amount_cents=100)
    assert ledger_rows(guard.connection, "unknown-card") == []


def test_spend_tag_without_spec_raises_config_error_at_wrap(spend_guard: Guard) -> None:
    with pytest.raises(GuardConfigError, match="no SpendSpec"):
        spend_guard.wrap(
            lambda **kwargs: "ok", meta=ToolMeta(name="pay", tags=frozenset({"spend"}))
        )


def test_spend_spec_without_tag_raises_config_error_at_wrap(spend_guard: Guard) -> None:
    meta = spend_meta()
    untagged = ToolMeta(name=meta.name, spend=meta.spend)  # spec, but no "spend" tag
    with pytest.raises(GuardConfigError, match="not tagged 'spend'"):
        spend_guard.wrap(lambda **kwargs: "ok", meta=untagged)


def test_non_positive_amount_raises_config_error(spend_guard: Guard) -> None:
    charge = make_charge(spend_guard)
    with pytest.raises(GuardConfigError, match="positive integer"):
        charge(amount_cents=0)
    assert ledger_rows(spend_guard.connection) == []


# ----------------------------------------------------------------------- async


async def test_async_spend_tool_settles_and_blocks(spend_guard: Guard) -> None:
    async def charge(*, amount_cents: int) -> str:
        return f"charged {amount_cents}"

    wrapped: Any = spend_guard.wrap(charge, meta=spend_meta())
    assert await wrapped(amount_cents=1000) == "charged 1000"
    with pytest.raises(SpendLimitExceeded):
        await wrapped(amount_cents=5000)
    rows = ledger_rows(spend_guard.connection)
    assert [(r["amount_cents"], r["state"]) for r in rows] == [(1000, "settled")]
