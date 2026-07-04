"""Confirmation gate for destructive actions (decision D6).

Destructive actions are **declared, not inferred**: ``ToolMeta(tags=
{"destructive"}, destructive=DestructiveSpec(resource_kind=..., summary_from=
...))``. A built-in rule pack additionally flags tool names matching
:data:`DESTRUCTIVE_NAME_RE` as a safety net — a match without a
``DestructiveSpec`` and no whitelist entry raises :class:`GuardConfigError` at
``wrap()`` time, forcing the author to declare or whitelist.

Flow is a challenge/retry loop (agent-friendly, no blocking I/O inside the
pipeline):

1. First call raises :class:`ConfirmationRequired` carrying ``challenge_id``,
   a plain-language ``summary`` from ``summary_from(args, kwargs)``, and
   ``phrase_format`` (``"DELETE <nn>"``). The concrete phrase uses a fresh
   2-digit nonce from ``secrets.randbelow(100)`` so it can't be
   muscle-memoried. The phrase travels over the **human channel** — the host
   reads it via ``Guard.challenge_phrase()``; it is deliberately absent from
   the exception the agent sees.
2. The user types the phrase; the host calls
   ``guard.confirm(challenge_id, typed_phrase)``.
3. The agent retries the original call with ``fluffy_challenge_id=<id>``;
   the interceptor pops that kwarg (the tool never sees it), verifies
   confirmed-and-unused, marks it used, and lets the call through.

Challenges expire after 5 minutes and are single-use. Wrong phrase:
``confirm()`` returns ``False`` and increments an attempt counter; 3 failures
voids the challenge. ``confirm(..., remember=True)`` also inserts into
``action_whitelist``; future calls matching (tool, resource_kind) skip the
gate and audit as ``whitelisted``.
"""

from __future__ import annotations

import re
import secrets
import sqlite3
import uuid
from collections.abc import Callable
from datetime import datetime, timedelta

from .audit import write_audit_row
from .context import CallContext, DestructiveSpec, ToolMeta
from .db import utc_now, utc_now_iso
from .exceptions import ConfirmationRequired, GuardConfigError

__all__ = [
    "CHALLENGE_TTL",
    "DESTRUCTIVE_NAME_RE",
    "MAX_ATTEMPTS",
    "PHRASE_FORMAT",
    "ConfirmInterceptor",
    "check_wrap_meta",
]

#: Challenges expire this long after creation (D6).
CHALLENGE_TTL = timedelta(minutes=5)

#: Wrong-phrase attempts before a challenge is voided (D6).
MAX_ATTEMPTS = 3

#: Expired, never-used challenge rows swept per new challenge (bounded so a
#: backlog can't stall the write transaction that piggybacks the sweep).
CLEANUP_BATCH = 100

#: The shape of every confirmation phrase, as shown to the agent (D2).
PHRASE_FORMAT = "DELETE <nn>"

#: D6 safety-net rule pack: tool names that look destructive.
DESTRUCTIVE_NAME_RE = re.compile(r"\b(delete|drop|destroy|remove|truncate|migrate)\b")


def _looks_destructive(name: str) -> bool:
    """Does the tool name match the D6 safety-net regex?

    Underscores are word characters, so ``drop_database`` would slip past a
    bare ``\\b`` boundary; names are normalized (``_`` -> space) before
    matching so snake_case names are caught too.
    """
    return DESTRUCTIVE_NAME_RE.search(name.replace("_", " ")) is not None


def check_wrap_meta(conn: sqlite3.Connection, meta: ToolMeta) -> None:
    """Wrap-time safety net (D6) — called by ``Guard.wrap()``.

    - A destructive-looking name with no ``DestructiveSpec`` and no
      ``action_whitelist`` entry for the tool raises: declare or whitelist.
    - A ``DestructiveSpec`` without the ``"destructive"`` tag raises: the tag
      is what routes the call through the gate, so a spec without it would be
      a silently-bypassed declaration.
    - The ``"destructive"`` tag without a ``DestructiveSpec`` raises: the gate
      needs a resource kind and a summary, and only the meta is required to
      decide that — so it fails here, at wrap time, not at call time.
    """
    if meta.destructive is not None and "destructive" not in meta.tags:
        raise GuardConfigError(
            f"tool {meta.name!r} declares a DestructiveSpec but is not tagged "
            "'destructive'; add the tag or drop the spec"
        )
    if "destructive" in meta.tags and meta.destructive is None:
        raise GuardConfigError(
            f"tool {meta.name!r} is tagged 'destructive' but has no DestructiveSpec"
        )
    if meta.destructive is None and _looks_destructive(meta.name):
        row = conn.execute(
            "SELECT 1 FROM action_whitelist WHERE tool = ? LIMIT 1", (meta.name,)
        ).fetchone()
        if row is None:
            raise GuardConfigError(
                f"tool {meta.name!r} looks destructive (matches "
                f"{DESTRUCTIVE_NAME_RE.pattern!r}) but has no DestructiveSpec; "
                "declare it with ToolMeta(tags={'destructive'}, destructive=...) "
                "or whitelist it in action_whitelist"
            )


class ConfirmInterceptor:
    """Challenge/retry confirmation gate around ``"destructive"``-tagged tools.

    The pipeline only routes guard-tagged calls here (D8 fast path), but a
    guarded call may carry other tags — so ``before`` still skips anything
    without the ``"destructive"`` tag.

    ``now_fn`` is injectable for time-freezing tests; it must return an aware
    :class:`~datetime.datetime`.
    """

    def __init__(
        self,
        conn: sqlite3.Connection,
        now_fn: Callable[[], datetime] | None = None,
    ) -> None:
        self._conn = conn
        self.now_fn: Callable[[], datetime] = now_fn or utc_now
        # (tool, resource_kind) pairs from action_whitelist, loaded lazily.
        # The table is only ever written through this same object
        # (confirm(remember=True)), which keeps the cache in step; a
        # cross-process writer would stale it, but single-Guard-per-process
        # is the design (D2).
        self._whitelist_cache: set[tuple[str, str]] | None = None

    # -------------------------------------------------------------- pipeline

    def before(self, ctx: CallContext) -> None:
        if "destructive" not in ctx.tool.tags:
            return
        spec = ctx.tool.destructive
        if spec is None:  # pragma: no cover - check_wrap_meta rejects this at wrap()
            raise RuntimeError(
                f"internal error: tool {ctx.tool.name!r} is tagged 'destructive' with no "
                "DestructiveSpec; check_wrap_meta should have rejected it at wrap time"
            )
        now = self.now_fn()
        now_iso = utc_now_iso(now)

        # The retry path: pop the kwarg first so the tool never sees it,
        # whatever happens next.
        challenge_id = ctx.kwargs.pop("fluffy_challenge_id", None)
        if challenge_id is not None and self._consume(ctx, str(challenge_id), now_iso):
            return  # confirmed + unused -> marked used, call allowed

        # No (valid) challenge presented: whitelist, or a fresh challenge.
        if self._whitelisted(ctx.tool.name, spec.resource_kind):
            write_audit_row(
                self._conn,
                call_id=ctx.call_id,
                tool=ctx.tool.name,
                event="whitelisted",
                decision="ok",
                detail={"resource_kind": spec.resource_kind},
            )
            # No commit here: the terminal AuditInterceptor.after commits, and
            # write_audit_row's contract leaves transactions to the caller —
            # the whitelist fast path stays a single memory lookup + one
            # deferred INSERT.
            return
        raise self._create_challenge(ctx, spec, now)

    def after(self, ctx: CallContext) -> None:
        return None  # challenges are consumed in before(); nothing to settle

    # ------------------------------------------------------------ guard API

    def challenge_phrase(self, challenge_id: str) -> str | None:
        """The exact phrase for a challenge — **host/human-channel use only**.

        The phrase is intentionally not in :class:`ConfirmationRequired`; the
        host shows it to the human out-of-band so a prompt-injected agent
        can't confirm itself. Returns ``None`` for an unknown challenge.
        """
        row = self._conn.execute(
            "SELECT phrase FROM confirmations WHERE challenge_id = ?", (challenge_id,)
        ).fetchone()
        return None if row is None else str(row["phrase"])

    def confirm(self, challenge_id: str, typed_phrase: str, remember: bool = False) -> bool:
        """Verify a typed phrase against a pending challenge (D6).

        Exact match, case-sensitive, surrounding whitespace stripped, against
        an unexpired, unused, un-voided (<3 failed attempts) challenge. On
        success the challenge is marked confirmed; ``remember=True`` also
        whitelists (tool, resource_kind). Wrong phrase returns ``False`` and
        increments the attempt counter; the third failure voids the challenge.
        """
        row = self._conn.execute(
            "SELECT * FROM confirmations WHERE challenge_id = ?", (challenge_id,)
        ).fetchone()
        if row is None:
            return False  # unknown id: nothing to audit against
        call_id, tool = str(row["call_id"]), str(row["tool"])
        now_iso = utc_now_iso(self.now_fn())

        reason: str | None = None
        # "Voided" is derived, not stored: state stays pending/confirmed and
        # the attempt counter is the single source of truth for the 3-strike
        # rule (D6).
        if int(row["attempts"]) >= MAX_ATTEMPTS:
            reason = "voided"
        elif row["used"]:
            reason = "already_used"
        elif now_iso >= str(row["expires_ts"]):
            reason = "expired"
        if reason is not None:
            self._audit_confirm_failed(call_id, tool, challenge_id, reason)
            self._conn.commit()
            return False

        if typed_phrase.strip() != str(row["phrase"]):
            attempts = int(row["attempts"]) + 1
            voided = attempts >= MAX_ATTEMPTS
            self._conn.execute(
                "UPDATE confirmations SET attempts = ? WHERE challenge_id = ?",
                (attempts, challenge_id),
            )
            self._audit_confirm_failed(call_id, tool, challenge_id, "wrong_phrase", attempts)
            if voided:
                write_audit_row(
                    self._conn,
                    call_id=call_id,
                    tool=tool,
                    event="challenge_voided",
                    decision="voided",
                    detail={"challenge_id": challenge_id, "attempts": attempts},
                )
            self._conn.commit()
            return False

        self._conn.execute(
            "UPDATE confirmations SET state = 'confirmed' WHERE challenge_id = ?",
            (challenge_id,),
        )
        detail: dict[str, object] = {"challenge_id": challenge_id}
        if remember:
            resource_kind = str(row["resource_kind"])
            self._conn.execute(
                "INSERT OR IGNORE INTO action_whitelist (tool, resource_kind, added_ts)"
                " VALUES (?, ?, ?)",
                (tool, resource_kind, now_iso),
            )
            if self._whitelist_cache is not None:  # keep the loaded cache in step
                self._whitelist_cache.add((tool, resource_kind))
            detail["remembered"] = {"tool": tool, "resource_kind": resource_kind}
        write_audit_row(
            self._conn,
            call_id=call_id,
            tool=tool,
            event="confirm_ok",
            decision="ok",
            detail=detail,
        )
        self._conn.commit()
        return True

    # ------------------------------------------------------------- internals

    def _consume(self, ctx: CallContext, challenge_id: str, now_iso: str) -> bool:
        """Mark a confirmed, unused, unexpired challenge as used (single-use).

        Any other state — unknown id, unconfirmed, already used, expired, or a
        different tool's challenge — returns ``False`` and the caller falls
        through to a fresh challenge. The state checks live inside one UPDATE
        so two racing retries can't both consume the same challenge.
        """
        cursor = self._conn.execute(
            "UPDATE confirmations SET used = 1 WHERE challenge_id = ? AND tool = ?"
            " AND state = 'confirmed' AND attempts < ? AND used = 0 AND expires_ts > ?",
            (challenge_id, ctx.tool.name, MAX_ATTEMPTS, now_iso),
        )
        consumed = cursor.rowcount == 1
        if consumed:  # the 0-row miss changed nothing; only a hit needs a commit
            self._conn.commit()
        return consumed

    def _whitelisted(self, tool: str, resource_kind: str) -> bool:
        # Hot path: a memory lookup, no SELECT per call. Loaded lazily so
        # rows written by earlier processes (remember=True, then restart)
        # are honored; see __init__ for the single-writer caveat.
        if self._whitelist_cache is None:
            self._whitelist_cache = {
                (str(r["tool"]), str(r["resource_kind"]))
                for r in self._conn.execute("SELECT tool, resource_kind FROM action_whitelist")
            }
        return (tool, resource_kind) in self._whitelist_cache

    def _create_challenge(
        self, ctx: CallContext, spec: DestructiveSpec, now: datetime
    ) -> ConfirmationRequired:
        challenge_id = str(uuid.uuid4())
        nonce = secrets.randbelow(100)
        phrase = f"DELETE {nonce:02d}"
        summary = spec.summary_from(ctx.args, ctx.kwargs)
        now_iso = utc_now_iso(now)
        expires_iso = utc_now_iso(now + CHALLENGE_TTL)
        # Piggyback a bounded sweep of expired, never-used challenges on this
        # write transaction. (This sqlite build lacks LIMIT-on-DELETE, hence
        # the rowid subselect.)
        self._conn.execute(
            "DELETE FROM confirmations WHERE rowid IN ("
            " SELECT rowid FROM confirmations WHERE expires_ts < ? AND used = 0 LIMIT ?)",
            (now_iso, CLEANUP_BATCH),
        )
        self._conn.execute(
            "INSERT INTO confirmations (challenge_id, call_id, phrase, summary,"
            " created_ts, expires_ts, used, tool, resource_kind, attempts, state)"
            " VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, 0, 'pending')",
            (
                challenge_id,
                ctx.call_id,
                phrase,
                summary,
                now_iso,
                expires_iso,
                ctx.tool.name,
                spec.resource_kind,
            ),
        )
        write_audit_row(
            self._conn,
            call_id=ctx.call_id,
            tool=ctx.tool.name,
            event="challenge_created",
            decision="blocked",
            # The phrase itself stays out of the audit detail: audit rows are
            # host-readable but the phrase belongs to the human channel only.
            detail={
                "challenge_id": challenge_id,
                "resource_kind": spec.resource_kind,
                "summary": summary,
                "expires_ts": expires_iso,
            },
        )
        self._conn.commit()
        # Deliberate D6 deviation (hardening): the exception carries only the
        # challenge id, summary, and *format* of the phrase. The phrase itself
        # travels via the host channel (Guard.challenge_phrase), never inside
        # the agent-visible exception, so a prompt-injected agent can't
        # confirm its own destructive call.
        return ConfirmationRequired(
            challenge_id=challenge_id,
            summary=summary,
            phrase_format=PHRASE_FORMAT,
            call_id=ctx.call_id,
        )

    def _audit_confirm_failed(
        self,
        call_id: str,
        tool: str,
        challenge_id: str,
        reason: str,
        attempts: int | None = None,
    ) -> None:
        detail: dict[str, object] = {"challenge_id": challenge_id, "reason": reason}
        if attempts is not None:
            detail["attempts"] = attempts
        write_audit_row(
            self._conn,
            call_id=call_id,
            tool=tool,
            event="confirm_failed",
            decision="failed",
            detail=detail,
        )
