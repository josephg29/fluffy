"""Spend guard: hard per-use and daily caps over a SQLite ledger (decision D5).

Semantics:

- "Daily" is a calendar day in the policy's timezone, computed from the UTC
  ledger at query time — no reset job, restart-safe by construction. Window
  bounds are computed in Python with :mod:`zoneinfo`; the SQL compares UTC
  ISO-8601 strings.
- **Two-phase, atomic**: ``before`` runs ``BEGIN IMMEDIATE``, sums today's
  ``reserved`` + ``settled`` rows for the card, and inserts a ``reserved`` row
  if the spend fits — check and reserve share one write transaction, so
  concurrent over-cap racing is impossible. ``after`` flips the row to
  ``settled`` on success or ``released`` on tool error.
- **Crash-orphaned reservations**: a process that dies between reserve and
  settle leaves a ``reserved`` row behind. The daily-sum query treats
  ``reserved`` rows older than :data:`RESERVATION_TTL` (15 minutes) as
  released — they simply stop counting against the cap. The rows themselves
  are left in place for the audit trail.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, time, timedelta
from zoneinfo import ZoneInfo

from .audit import write_audit_row
from .context import CallContext
from .db import utc_now, utc_now_iso
from .exceptions import GuardConfigError, SpendLimitExceeded
from .permissions import BudgetGrant, active_budget_grants, consume_grants, restore_grants

__all__ = ["RESERVATION_TTL", "Caps", "SpendInterceptor", "SpendPolicy", "day_window_utc"]

#: Reserved rows older than this are treated as released by the daily sum.
RESERVATION_TTL = timedelta(minutes=15)

#: Spec default: $25.00 per-use and daily (D5).
DEFAULT_CAP_CENTS = 2500


@dataclass(frozen=True, slots=True)
class SpendPolicy:
    """Per-card spend caps. Money is integer cents; ``tz`` scopes the day."""

    card_id: str
    per_use_cap_cents: int = DEFAULT_CAP_CENTS
    daily_cap_cents: int = DEFAULT_CAP_CENTS
    tz: str = "America/Los_Angeles"


@dataclass(frozen=True, slots=True)
class Caps:
    """Effective caps for a card at spend time."""

    per_use_cap_cents: int
    daily_cap_cents: int


@dataclass(frozen=True, slots=True)
class _PendingSpend:
    """before() -> after() state for one in-flight spend (the sanctioned
    per-call ``_pending`` pattern): the reserved ledger row plus any ``once``
    grants this spend consumed, so a released spend can restore them."""

    ledger_id: int
    consumed_grant_ids: tuple[int, ...]


def day_window_utc(now: datetime, tz: str | ZoneInfo) -> tuple[str, str]:
    """[start, end) of ``now``'s calendar day in ``tz``, as UTC ISO strings.

    All ledger timestamps are UTC ISO-8601, so the window bounds are converted
    to UTC and compared lexicographically in SQL. Callers that already hold a
    :class:`ZoneInfo` (the interceptor caches one per policy) pass it directly.
    """
    zone = ZoneInfo(tz) if isinstance(tz, str) else tz
    local_day = now.astimezone(zone).date()
    start = datetime.combine(local_day, time.min, tzinfo=zone)
    end = datetime.combine(local_day + timedelta(days=1), time.min, tzinfo=zone)
    return utc_now_iso(start), utc_now_iso(end)


def _caps_with_grants(policy: SpendPolicy, grants: Sequence[BudgetGrant]) -> Caps:
    """Pure cap math over (policy, grants) — the one boost formula.

    Every live grant raises both the per-use and the daily cap by its delta —
    a granted increase must clear both dimensions or the retried spend it was
    approved for would still bounce off the per-use cap. Being a pure function
    of its inputs, this is what FLUF-5's effective-caps cache will memoize.
    """
    boost = sum(g.amount_cents for g in grants)
    return Caps(
        per_use_cap_cents=policy.per_use_cap_cents + boost,
        daily_cap_cents=policy.daily_cap_cents + boost,
    )


class SpendInterceptor:
    """Reserve-then-settle spend guard around ``"spend"``-tagged tools.

    The pipeline only routes guard-tagged calls here (D8 fast path), but a
    guarded call may carry other tags — so ``before`` still skips anything
    without the ``"spend"`` tag.

    ``now_fn`` is injectable for time-freezing tests; it must return an
    aware :class:`~datetime.datetime`.
    """

    def __init__(
        self,
        conn: sqlite3.Connection,
        now_fn: Callable[[], datetime] | None = None,
    ) -> None:
        self._conn = conn
        self.now_fn: Callable[[], datetime] = now_fn or utc_now
        self._policies: dict[str, SpendPolicy] = {}
        # card_id -> validated ZoneInfo, cached at add_policy time so
        # day_window_utc doesn't reconstruct it on every spend.
        self._zones: dict[str, ZoneInfo] = {}
        # call_id -> _PendingSpend, settled/released in after(). This
        # before()->after() dict is the sanctioned per-call state pattern
        # for interceptors.
        self._pending: dict[str, _PendingSpend] = {}

    # ---------------------------------------------------------------- policy

    def add_policy(self, policy: SpendPolicy) -> None:
        """Register (or replace) the policy for ``policy.card_id``."""
        zone = ZoneInfo(policy.tz)  # fail fast on a bad timezone name
        if policy.per_use_cap_cents <= 0 or policy.daily_cap_cents <= 0:
            raise GuardConfigError(f"spend caps must be positive: {policy!r}")
        self._policies[policy.card_id] = policy
        self._zones[policy.card_id] = zone

    def effective_caps(self, card_id: str, now: datetime) -> Caps:
        """The single cap-lookup seam: base policy + active grants (D7).

        Delegates to the pure :func:`_caps_with_grants` over the card's live
        grants (unconsumed, unexpired at ``now``). ``before()`` does not call
        this — it fetches the grants once inside its ``BEGIN IMMEDIATE``
        transaction and runs the same pure function, so cap math and grant
        consumption see one snapshot.
        """
        policy = self._policy_for(card_id)
        grants = active_budget_grants(self._conn, card_id, utc_now_iso(now))
        return _caps_with_grants(policy, grants)

    def _policy_for(self, card_id: str) -> SpendPolicy:
        try:
            return self._policies[card_id]
        except KeyError:
            raise GuardConfigError(f"no spend policy registered for card {card_id!r}") from None

    # -------------------------------------------------------------- pipeline

    def before(self, ctx: CallContext) -> None:
        if "spend" not in ctx.tool.tags:
            return
        spec = ctx.tool.spend
        if spec is None:
            raise GuardConfigError(f"tool {ctx.tool.name!r} is tagged 'spend' but has no SpendSpec")
        amount = spec.amount_from(ctx.args, ctx.kwargs)
        if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0:
            raise GuardConfigError(
                f"amount_from for tool {ctx.tool.name!r} must return positive integer "
                f"cents, got {amount!r}"
            )
        policy = self._policy_for(spec.card_id)  # one registry fetch per spend

        now = self.now_fn()
        now_iso = utc_now_iso(now)
        day_start, day_end = day_window_utc(now, self._zones[spec.card_id])
        stale_cutoff = utc_now_iso(now - RESERVATION_TTL)

        # Check + reserve (+ once-grant consumption, D7) share one write
        # transaction (D5): BEGIN IMMEDIATE takes the write lock up front so
        # no other connection can reserve — or consume a grant — between our
        # sum and our insert. The per-use check lives inside the transaction
        # too, because grants raise both caps and must not race the consume.
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            # Grants are fetched exactly once per spend, inside the write
            # transaction (the FLUF-2 seam contract): the same snapshot feeds
            # the pure cap math and the once-grant consume below, atomically.
            grants = active_budget_grants(self._conn, spec.card_id, now_iso)
            caps = _caps_with_grants(policy, grants)
            spent = self._spent_today(spec.card_id, day_start, day_end, stale_cutoff)
            if amount > caps.per_use_cap_cents:
                self._conn.rollback()
                self._deny(ctx, spec.card_id, amount, caps, spent, over_per_use=True)
            if spent + amount > caps.daily_cap_cents:
                self._conn.rollback()
                self._deny(ctx, spec.card_id, amount, caps, spent, over_per_use=False)
            consumed_ids = self._consume_once_grants(policy, grants, now_iso, amount, spent, ctx)
            cursor = self._conn.execute(
                "INSERT INTO spend_ledger (card_id, ts, amount_cents, state, call_id)"
                " VALUES (?, ?, ?, 'reserved', ?)",
                (spec.card_id, now_iso, amount, ctx.call_id),
            )
            ledger_id = cursor.lastrowid
            assert ledger_id is not None
            write_audit_row(
                self._conn,
                call_id=ctx.call_id,
                tool=ctx.tool.name,
                event="spend_reserved",
                decision="ok",
                detail={
                    "card_id": spec.card_id,
                    "amount_cents": amount,
                    "spent_today_cents": spent,
                    "ledger_id": ledger_id,
                    "consumed_grant_ids": list(consumed_ids),
                },
            )
            self._conn.commit()
        except BaseException:
            if self._conn.in_transaction:
                self._conn.rollback()
            raise
        self._pending[ctx.call_id] = _PendingSpend(
            ledger_id=ledger_id, consumed_grant_ids=tuple(consumed_ids)
        )

    def after(self, ctx: CallContext) -> None:
        pending = self._pending.pop(ctx.call_id, None)
        if pending is None:
            return  # no reservation was made (denied, untagged, or other tags)
        state = "settled" if ctx.error is None else "released"
        self._conn.execute(
            "UPDATE spend_ledger SET state = ? WHERE id = ?",
            (state, pending.ledger_id),
        )
        if state == "released" and pending.consumed_grant_ids:
            # The tool failed, so the money never moved: give the once-grants
            # back (permissions.py owns the write; expiry still applies).
            restore_grants(self._conn, pending.consumed_grant_ids)
            write_audit_row(
                self._conn,
                call_id=ctx.call_id,
                tool=ctx.tool.name,
                event="grant_restored",
                decision="ok",
                detail={"grant_ids": list(pending.consumed_grant_ids)},
            )
        write_audit_row(
            self._conn,
            call_id=ctx.call_id,
            tool=ctx.tool.name,
            event=f"spend_{state}",
            decision="ok" if state == "settled" else "released",
            detail={"ledger_id": pending.ledger_id},
        )
        self._conn.commit()

    # ---------------------------------------------------------------- internals

    def _consume_once_grants(
        self,
        policy: SpendPolicy,
        grants: Sequence[BudgetGrant],
        now_iso: str,
        amount: int,
        spent: int,
        ctx: CallContext,
    ) -> list[int]:
        """Consume the ``once`` grants this spend actually needs (D7).

        Runs inside the caller's ``BEGIN IMMEDIATE`` transaction, after the
        cap checks passed, over the same ``grants`` snapshot the caps were
        computed from. A spend that fits under base policy + persistent grants
        consumes nothing; otherwise ``once`` grants are consumed oldest-first
        until the spend fits. Every consumed grant raises the per-use and the
        daily dimension by the same delta, so a single headroom counter — the
        tighter of the two to start — decides. The caps already admitted the
        spend, so the loop always terminates with enough headroom.
        """
        persistent_boost = sum(g.amount_cents for g in grants if g.duration == "persistent")
        headroom = min(policy.per_use_cap_cents, policy.daily_cap_cents - spent) + persistent_boost
        consumed: list[int] = []
        for grant in grants:
            if grant.duration != "once":
                continue
            if amount <= headroom:
                break
            consumed.append(grant.id)
            headroom += grant.amount_cents
        if consumed:
            consume_grants(self._conn, consumed, now_iso)
            write_audit_row(
                self._conn,
                call_id=ctx.call_id,
                tool=ctx.tool.name,
                event="grant_consumed",
                decision="ok",
                detail={"card_id": policy.card_id, "grant_ids": consumed, "amount_cents": amount},
            )
        return consumed

    def _spent_today(self, card_id: str, day_start: str, day_end: str, stale_cutoff: str) -> int:
        """Sum of settled + live-reserved cents for the card in [day_start, day_end).

        ``reserved`` rows older than :data:`RESERVATION_TTL` are crash orphans
        and are treated as released — excluded from the sum.
        """
        row = self._conn.execute(
            "SELECT COALESCE(SUM(amount_cents), 0) FROM spend_ledger"
            " WHERE card_id = ? AND ts >= ? AND ts < ?"
            " AND (state = 'settled' OR (state = 'reserved' AND ts > ?))",
            (card_id, day_start, day_end, stale_cutoff),
        ).fetchone()
        return int(row[0])

    def _deny(
        self,
        ctx: CallContext,
        card_id: str,
        amount: int,
        caps: Caps,
        spent: int,
        *,
        over_per_use: bool,
    ) -> None:
        """Audit the denial (own transaction — the reserve txn is rolled back)."""
        remaining = max(caps.daily_cap_cents - spent, 0)
        exc = SpendLimitExceeded(
            requested_cents=amount,
            cap_cents=caps.per_use_cap_cents if over_per_use else caps.daily_cap_cents,
            spent_cents=spent,
            remaining_cents=remaining,
            cap_kind="per-use" if over_per_use else "daily",
            call_id=ctx.call_id,
        )
        write_audit_row(
            self._conn,
            call_id=ctx.call_id,
            tool=ctx.tool.name,
            event="spend_denied",
            decision="blocked",
            detail={"card_id": card_id, **exc.payload},
        )
        self._conn.commit()
        raise exc
