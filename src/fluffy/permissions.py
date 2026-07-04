"""Permission broker + guardian bot (decision D7).

Request model: :class:`PermissionRequest` has exactly two kinds —

- ``budget_increase``: ``subject`` is a spend card id; ``value`` is the
  **increase delta in integer cents** on top of the card's base caps. The
  spend guard's cap lookup becomes base policy + active grants
  (:meth:`fluffy.spend.SpendInterceptor.effective_caps`); ``once`` grants are
  consumed inside the same ``BEGIN IMMEDIATE`` spend transaction that uses
  them, so cap check and grant consumption cannot race.
- ``access_grant``: ``subject`` is a tool name; tools tagged ``"restricted"``
  are denied by :class:`PermissionInterceptor` unless an unexpired grant for
  the tool exists.

Decisions come from an **approver chain** — first non-abstain wins. An
approver is one async method (``decide(req) -> Decision | None``, ``None`` =
abstain/escalate), so a web or Slack approver is a one-method class the host
plugs in; nothing else in fluffy changes. The default chain is
``[ConsoleApprover()]``. :class:`GuardianBot` ships **disabled by default** —
it participates only if the host puts it in the chain.

Denials raise nothing at request time: the agent gets a structured
:class:`fluffy.Decision` with a message it can relay verbatim.
"""

from __future__ import annotations

import json
import sqlite3
import sys
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal, Protocol, TypeGuard

from .audit import write_audit_row
from .context import CallContext, Decision
from .db import utc_now, utc_now_iso
from .exceptions import PermissionDenied, _dollars

__all__ = [
    "ApprovalChain",
    "Approver",
    "BudgetGrant",
    "ConsoleApprover",
    "GuardianBot",
    "PermissionBroker",
    "PermissionInterceptor",
    "PermissionRequest",
    "active_budget_grants",
    "consume_grants",
    "restore_grants",
]

PermissionKind = Literal["budget_increase", "access_grant"]
Duration = Literal["once", "persistent"]

#: The one live-grant predicate: a grant counts iff it is unconsumed and
#: unexpired. Parameterized on a ``now_iso`` UTC ISO-8601 string.
LIVE_GRANT_SQL = "consumed_ts IS NULL AND (expires_ts IS NULL OR expires_ts > ?)"


def _is_positive_cents(value: object) -> TypeGuard[int]:
    """True for a positive ``int`` that is not a ``bool`` (money hygiene)."""
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


@dataclass(frozen=True, slots=True)
class PermissionRequest:
    """An agent's ask for more budget or access (D7).

    ``value`` for ``budget_increase`` is the increase delta in integer cents
    (how much *more* than the base caps); for ``access_grant`` it is optional
    free-form context (the grant itself is keyed by ``subject``).
    """

    kind: PermissionKind
    subject: str
    value: int | str | None
    duration: Duration
    rationale: str


class Approver(Protocol):
    """One decision-maker in the approval chain.

    Return a :class:`Decision` to decide, or ``None`` to abstain and let the
    next approver in the chain see the request.
    """

    async def decide(self, req: PermissionRequest) -> Decision | None: ...


class ApprovalChain:
    """First non-abstain decision wins; all abstain -> deny ``"exhausted"``."""

    def __init__(self, approvers: Sequence[Approver]) -> None:
        self._approvers: tuple[Approver, ...] = tuple(approvers)

    async def decide(self, req: PermissionRequest) -> Decision:
        for approver in self._approvers:
            decision = await approver.decide(req)
            if decision is not None:
                return decision
        return Decision(
            approved=False,
            decider="exhausted",
            message=(
                f"Permission denied: no approver would decide the {req.kind} request "
                f"for {req.subject!r} (every approver abstained). "
                "Ask the user to review it directly."
            ),
        )


class GuardianBot:
    """Auto-approves tiny budget increases; abstains on everything else.

    Approves ``budget_increase`` requests whose increase delta is under
    ``auto_approve_under_cents``; abstains otherwise, and always abstains on
    ``access_grant``. **Off by default** — it participates only if the host
    puts it in the approver chain.
    """

    DECIDER = "guardian_bot"

    def __init__(self, auto_approve_under_cents: int = 100) -> None:
        self.auto_approve_under_cents = auto_approve_under_cents

    async def decide(self, req: PermissionRequest) -> Decision | None:
        if req.kind != "budget_increase":
            return None  # access is never the bot's call
        delta = req.value
        if not _is_positive_cents(delta):
            return None  # malformed value: escalate, don't guess
        if delta >= self.auto_approve_under_cents:
            return None
        return Decision(
            approved=True,
            decider=self.DECIDER,
            message=(
                f"Approved: budget increase of {_dollars(delta)} for {req.subject!r} "
                f"is under the {_dollars(self.auto_approve_under_cents)} "
                "guardian auto-approve threshold."
            ),
        )


class ConsoleApprover:
    """Renders the request on the console and reads ``approve``/``deny`` from stdin.

    Non-TTY guard: with no injected ``input_fn`` and stdin not a terminal
    (CI, pipes, agent subprocesses) it **abstains** instead of hanging on
    ``input()``. ``input_fn``/``output_fn`` are injectable so demos and tests
    can script the console.
    """

    DECIDER = "console"

    def __init__(
        self,
        input_fn: Callable[[], str] | None = None,
        output_fn: Callable[[str], None] | None = None,
    ) -> None:
        self._input = input_fn
        self._output: Callable[[str], None] = output_fn if output_fn is not None else print

    async def decide(self, req: PermissionRequest) -> Decision | None:
        read = self._input
        if read is None:
            if not sys.stdin.isatty():
                return None  # abstain: nobody is at this console
            read = self._prompt
        self._output(
            "fluffy permission request\n"
            f"  kind:      {req.kind}\n"
            f"  subject:   {req.subject}\n"
            f"  value:     {req.value}\n"
            f"  duration:  {req.duration}\n"
            f"  rationale: {req.rationale}"
        )
        while True:
            try:
                answer = read().strip().lower()
            except (EOFError, StopIteration):
                return None  # console went away mid-decision: abstain
            if answer in {"approve", "a", "yes", "y"}:
                return Decision(
                    approved=True,
                    decider=self.DECIDER,
                    message=(
                        f"Approved at the console: {req.kind} for {req.subject!r} ({req.duration})."
                    ),
                )
            if answer in {"deny", "d", "no", "n"}:
                return Decision(
                    approved=False,
                    decider=self.DECIDER,
                    message=(
                        f"Permission denied at the console: the {req.kind} request "
                        f"for {req.subject!r} was rejected by the user."
                    ),
                )
            self._output("please type 'approve' or 'deny'")

    @staticmethod
    def _prompt() -> str:
        return input("approve/deny> ")


# --------------------------------------------------------------------- grants


@dataclass(frozen=True, slots=True)
class BudgetGrant:
    """An active ``budget_increase`` permissions row, decoded."""

    id: int
    amount_cents: int
    duration: str


def active_budget_grants(conn: sqlite3.Connection, card_id: str, now_iso: str) -> list[BudgetGrant]:
    """Live ``budget_increase`` grants for a card: unconsumed and unexpired at ``now_iso``.

    Rows whose ``value_json`` is not a positive integer are ignored (the
    broker only writes integers for this kind; anything else is foreign data).
    Callers that must not race grant consumption call this *inside* their own
    write transaction — the function only reads.
    """
    rows = conn.execute(
        "SELECT id, value_json, duration FROM permissions"
        " WHERE kind = 'budget_increase' AND subject = ?"
        f" AND {LIVE_GRANT_SQL} ORDER BY id",
        (card_id, now_iso),
    ).fetchall()
    grants: list[BudgetGrant] = []
    for row in rows:
        try:
            amount = json.loads(row["value_json"])
        except (TypeError, ValueError):
            continue
        if not _is_positive_cents(amount):
            continue
        grants.append(
            BudgetGrant(id=int(row["id"]), amount_cents=amount, duration=str(row["duration"]))
        )
    return grants


# Grant *writes* live here, next to the grant reads: one module owns every
# mutation of the permissions table, so the FLUF-5 effective_caps cache gets a
# single invalidation choke point (broker insert + consume/restore below).


def consume_grants(conn: sqlite3.Connection, ids: Sequence[int], now_iso: str) -> None:
    """Mark grants consumed at ``now_iso``.

    Runs inside the caller's write transaction (the spend guard's
    ``BEGIN IMMEDIATE`` block); never commits.
    """
    if not ids:
        return
    conn.executemany(
        "UPDATE permissions SET consumed_ts = ? WHERE id = ?",
        [(now_iso, grant_id) for grant_id in ids],
    )


def restore_grants(conn: sqlite3.Connection, ids: Sequence[int]) -> None:
    """Un-consume grants — a released spend gives its ``once`` grants back.

    Expiry still applies to the restored grants. Never commits.
    """
    if not ids:
        return
    placeholders = ",".join("?" * len(ids))
    conn.execute(
        f"UPDATE permissions SET consumed_ts = NULL WHERE id IN ({placeholders})",
        tuple(ids),
    )


# --------------------------------------------------------------------- broker


class PermissionBroker:
    """Runs the approver chain and persists approved grants (D7).

    ``now_fn`` is injectable for time-freezing tests; it must return an aware
    :class:`~datetime.datetime`.
    """

    def __init__(
        self,
        conn: sqlite3.Connection,
        approvers: Sequence[Approver],
        now_fn: Callable[[], datetime] | None = None,
    ) -> None:
        self._conn = conn
        self.chain = ApprovalChain(approvers)
        self.now_fn: Callable[[], datetime] = now_fn or utc_now

    async def request(self, req: PermissionRequest) -> Decision:
        """Run the chain; on approval write the grant row; audit either way.

        Grant lifetime is the *approver's* call, not the requester's: an
        approver may set ``Decision.expires_in_s`` and the broker writes
        ``expires_ts = now + expires_in_s``. ``None`` means no expiry
        (``expires_ts`` NULL — persistent grants live until revoked, ``once``
        grants until consumed).
        """
        request_id = str(uuid.uuid4())
        decision = await self.chain.decide(req)
        now = self.now_fn()
        now_iso = utc_now_iso(now)
        detail: dict[str, object] = {
            "request_id": request_id,
            "kind": req.kind,
            "subject": req.subject,
            "value": req.value,
            "duration": req.duration,
            "rationale": req.rationale,
            "decider": decision.decider,
            "message": decision.message,
        }
        if decision.approved:
            expires_iso = (
                utc_now_iso(now + timedelta(seconds=decision.expires_in_s))
                if decision.expires_in_s is not None
                else None
            )
            cursor = self._conn.execute(
                "INSERT INTO permissions"
                " (kind, subject, value_json, granted_ts, expires_ts, decider, duration)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    req.kind,
                    req.subject,
                    json.dumps(req.value),
                    now_iso,
                    expires_iso,
                    decision.decider,
                    req.duration,
                ),
            )
            detail["grant_id"] = cursor.lastrowid
            if expires_iso is not None:
                detail["expires_ts"] = expires_iso
            event, audit_decision = "permission_granted", "ok"
        else:
            event, audit_decision = "permission_denied", "denied"
        write_audit_row(
            self._conn,
            call_id=request_id,
            tool="fluffy.permissions",
            event=event,
            decision=audit_decision,
            detail=detail,
        )
        self._conn.commit()
        return decision


# ---------------------------------------------------------------- interceptor


class PermissionInterceptor:
    """Access gate around ``"restricted"``-tagged tools (D7 ``access_grant``).

    The pipeline only routes guard-tagged calls here (D8 fast path), but a
    guarded call may carry other tags — so ``before`` still skips anything
    without the ``"restricted"`` tag.

    A persistent unexpired grant for ``subject == tool.name`` lets the call
    through. Otherwise one ``once`` grant is consumed atomically (the state
    checks live inside a single UPDATE, so two racing calls cannot both
    consume the same grant). No grant -> :class:`fluffy.PermissionDenied`.
    A consumed ``once`` access grant stays consumed even if the tool then
    fails — access was exercised.

    ``now_fn`` is injectable for time-freezing tests; it must return an aware
    :class:`~datetime.datetime`.
    """

    DECIDER = "permission_interceptor"

    def __init__(
        self,
        conn: sqlite3.Connection,
        now_fn: Callable[[], datetime] | None = None,
    ) -> None:
        self._conn = conn
        self.now_fn: Callable[[], datetime] = now_fn or utc_now

    def before(self, ctx: CallContext) -> None:
        if "restricted" not in ctx.tool.tags:
            return
        now_iso = utc_now_iso(self.now_fn())

        # One probe covers both durations, persistent-first: a persistent
        # grant always wins (nothing to consume), otherwise the oldest live
        # once-grant is the candidate. The loop only repeats on a lost
        # consume race.
        while True:
            row = self._conn.execute(
                "SELECT id, duration FROM permissions"
                " WHERE kind = 'access_grant' AND subject = ?"
                f" AND {LIVE_GRANT_SQL}"
                " ORDER BY duration = 'once', id LIMIT 1",
                (ctx.tool.name, now_iso),
            ).fetchone()
            if row is None:
                break
            grant_id = int(row["id"])
            if row["duration"] != "once":
                # No commit: the terminal AuditInterceptor.after commits (same
                # deferred-INSERT pattern as the confirm whitelist fast path).
                self._audit_allowed(ctx, grant_id=grant_id, consumed=False)
                return
            # Conditional UPDATE is the race arbiter: two calls can both
            # SELECT the same row, but only one flips consumed_ts from NULL.
            cursor = self._conn.execute(
                "UPDATE permissions SET consumed_ts = ? WHERE id = ? AND consumed_ts IS NULL",
                (now_iso, grant_id),
            )
            if cursor.rowcount == 1:
                self._audit_allowed(ctx, grant_id=grant_id, consumed=True)
                self._conn.commit()  # consumption must stick even if the tool fails
                return
            # Lost the race for that row; re-probe for the next live grant.

        exc = PermissionDenied(
            request_id="",
            decider=self.DECIDER,
            message=(
                f"Blocked: tool {ctx.tool.name!r} is restricted and no active access "
                "grant covers it. File a permission request — "
                f"PermissionRequest(kind='access_grant', subject={ctx.tool.name!r}, ...) — "
                "via guard.request_permission() and retry once it is approved."
            ),
            call_id=ctx.call_id,
        )
        write_audit_row(
            self._conn,
            call_id=ctx.call_id,
            tool=ctx.tool.name,
            event="access_denied",
            decision="blocked",
            detail={"subject": ctx.tool.name, "decider": self.DECIDER},
        )
        self._conn.commit()
        raise exc

    def after(self, ctx: CallContext) -> None:
        return None  # once-grants are consumed in before(); nothing to settle

    def _audit_allowed(self, ctx: CallContext, *, grant_id: int | None, consumed: bool) -> None:
        write_audit_row(
            self._conn,
            call_id=ctx.call_id,
            tool=ctx.tool.name,
            event="access_allowed",
            decision="ok",
            detail={"subject": ctx.tool.name, "grant_id": grant_id, "consumed": consumed},
        )
