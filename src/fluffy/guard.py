"""Guard + interceptor pipeline (decision D2).

Fixed pipeline order — secrets resolve last on the way in, redact first on the
way out, and audit is terminal so settlement hooks run before the audit row is
written::

    PermissionInterceptor -> SpendInterceptor -> ConfirmInterceptor
        -> SecretResolveInterceptor -> [tool executes]
        -> SecretRedactInterceptor -> ConfirmInterceptor -> SpendInterceptor
        -> PermissionInterceptor -> AuditInterceptor

The pipeline owns the D8 fast path: at ``wrap()`` time the tool's tags are
intersected with :data:`GUARD_TAGS`, and calls with no matching guard tag run
only secret resolution/redaction (memory-only, zero I/O). Interceptors never
re-implement that gate.

``after()`` hooks are guaranteed to run even when the tool (or a ``before``
hook) raises, and must not raise themselves.
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import inspect
import logging
import sqlite3
from collections.abc import Callable, Coroutine, Iterator, Sequence
from pathlib import Path
from types import TracebackType
from typing import Any, ParamSpec, Protocol, TypeVar, cast

from . import db as _db
from .audit import AuditInterceptor, audit_tail
from .confirm import ConfirmInterceptor, check_wrap_meta
from .context import CallContext, Decision, ToolMeta
from .db import utc_now_iso
from .permissions import (
    Approver,
    ConsoleApprover,
    PermissionBroker,
    PermissionInterceptor,
    PermissionRequest,
)
from .redact import RedactionFilter, register_secret_store, unregister_secret_store
from .secrets import (
    MemorySecretStore,
    SecretRedactInterceptor,
    SecretResolveInterceptor,
    SecretStore,
)
from .spend import SpendInterceptor, SpendPolicy

__all__ = ["GUARD_TAGS", "Guard", "Interceptor"]

P = ParamSpec("P")
R = TypeVar("R")

_log = logging.getLogger("fluffy.guard")

#: Tags that route a call through the full guard pipeline (D8). Anything else
#: takes the memory-only fast path: secret resolution in, redaction out.
GUARD_TAGS: frozenset[str] = frozenset({"spend", "destructive", "restricted"})


class Interceptor(Protocol):
    """One stage of the guard pipeline."""

    def before(self, ctx: CallContext) -> None:
        """Runs before the tool; raise :class:`fluffy.Blocked` to stop the call."""
        ...

    def after(self, ctx: CallContext) -> None:
        """Observe/settle after the tool; must not raise."""
        ...


class Guard:
    """One guard per agent process. Wrap tools; the pipeline does the rest."""

    def __init__(
        self,
        db_path: str | Path | None = None,
        secret_store: SecretStore | None = None,
        approvers: Sequence[Approver] | None = None,
    ) -> None:
        self.secret_store: SecretStore = (
            secret_store if secret_store is not None else MemorySecretStore()
        )
        # D7 default chain: the console. GuardianBot is off unless the host
        # passes it in explicitly.
        self.approvers: list[Approver] = (
            list(approvers) if approvers is not None else [ConsoleApprover()]
        )

        self.connection: sqlite3.Connection = _db.connect(db_path)
        _db.migrate(self.connection)

        register_secret_store(self.secret_store)
        self._install_logging_filter()

        self._broker = PermissionBroker(self.connection, self.approvers)
        self._permission = PermissionInterceptor(self.connection)
        self._spend = SpendInterceptor(self.connection)
        self._confirm = ConfirmInterceptor(self.connection)
        self._resolve = SecretResolveInterceptor(self.secret_store)
        self._redact = SecretRedactInterceptor(self.secret_store)
        self._audit = AuditInterceptor(self.connection)

        # Runs in order before the tool (D2 fixed order).
        self._before_chain: tuple[Interceptor, ...] = (
            self._permission,
            self._spend,
            self._confirm,
            self._resolve,
        )
        # Runs in order after the tool: redact first, then settlement hooks,
        # audit terminal (D2) so it records their outcomes.
        self._after_chain: tuple[Interceptor, ...] = (
            self._redact,
            self._confirm,
            self._spend,
            self._permission,
            self._audit,
        )
        # D8 fast path for calls with no guard tags: memory-only, zero I/O —
        # secrets still resolve and results are still masked.
        self._fast_before: tuple[Interceptor, ...] = (self._resolve,)
        self._fast_after: tuple[Interceptor, ...] = (self._redact,)

    # ------------------------------------------------------------------ setup

    def _install_logging_filter(self) -> None:
        """Attach the redaction filter to the root logger and its handlers.

        Logger-level filters only see records logged directly on that logger,
        so the filter is also attached to every current root handler (which
        receive propagated records from the whole tree). Known limitation:
        handlers added to the root logger *after* Guard init are not covered.
        """
        self._logging_filter = RedactionFilter()
        self._filter_targets: list[logging.Filterer] = []
        root = logging.getLogger()
        for target in (root, *root.handlers):
            if not any(isinstance(f, RedactionFilter) for f in target.filters):
                target.addFilter(self._logging_filter)
                self._filter_targets.append(target)

    # ------------------------------------------------------------------- wrap

    def wrap(
        self, tool_fn: Callable[P, R], meta: ToolMeta
    ) -> Callable[P, R] | Callable[P, Coroutine[Any, Any, R]]:
        """Wrap a sync or async callable in the guard pipeline.

        Raises :class:`fluffy.GuardConfigError` here — not at call time — for
        the D6 safety net: a destructive-looking tool name with no
        ``DestructiveSpec`` and no whitelist entry.
        """
        check_wrap_meta(self.connection, meta)
        guarded = bool(GUARD_TAGS.intersection(meta.tags))
        before_chain = self._before_chain if guarded else self._fast_before
        after_chain = self._after_chain if guarded else self._fast_after

        if inspect.iscoroutinefunction(tool_fn):
            async_fn = cast(Callable[P, Coroutine[Any, Any, R]], tool_fn)

            @functools.wraps(async_fn)
            async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
                with self._pipeline(meta, args, dict(kwargs), before_chain, after_chain) as ctx:
                    ctx.result = await async_fn(*ctx.args, **ctx.kwargs)
                return cast(R, ctx.result)

            return async_wrapper

        @functools.wraps(tool_fn)
        def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            with self._pipeline(meta, args, dict(kwargs), before_chain, after_chain) as ctx:
                ctx.result = tool_fn(*ctx.args, **ctx.kwargs)
            return cast(R, ctx.result)

        return sync_wrapper

    # --------------------------------------------------------------- pipeline

    @contextlib.contextmanager
    def _pipeline(
        self,
        meta: ToolMeta,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        before_chain: tuple[Interceptor, ...],
        after_chain: tuple[Interceptor, ...],
    ) -> Iterator[CallContext]:
        """The shared sync/async bracket around one tool call.

        Makes the context, runs the before hooks, yields for execution,
        captures any ``BaseException`` on the context, and — the invariant,
        defined once here — always runs the after hooks.
        """
        ctx = self._make_context(meta, args, kwargs)
        try:
            for interceptor in before_chain:
                interceptor.before(ctx)
            yield ctx
        except BaseException as exc:
            ctx.error = exc
            raise
        finally:
            self._run_after(ctx, after_chain)

    def _make_context(
        self, meta: ToolMeta, args: tuple[Any, ...], kwargs: dict[str, Any]
    ) -> CallContext:
        return CallContext(tool=meta, args=args, kwargs=kwargs)

    def _run_after(self, ctx: CallContext, chain: tuple[Interceptor, ...]) -> None:
        """Run every after() hook; they are guaranteed to run and never raise."""
        ctx.ended_at = utc_now_iso()
        for interceptor in chain:
            try:
                interceptor.after(ctx)
            except Exception:
                _log.exception(
                    "after() hook %s failed for call %s",
                    type(interceptor).__name__,
                    ctx.call_id,
                )

    # ---------------------------------------------------------------- helpers

    def add_spend_policy(self, policy: SpendPolicy) -> None:
        """Register (or replace) the spend policy for a card (D5)."""
        self._spend.add_policy(policy)

    async def request_permission(self, req: PermissionRequest) -> Decision:
        """Run the approver chain for a permission request (D7).

        On approval a ``permissions`` row is written and takes effect
        immediately — same conversation, no restart. Denials raise nothing:
        the returned :class:`Decision` has ``approved=False`` and a message
        the agent can relay verbatim. Grant expiry is the approver's call —
        an approver may set ``Decision.expires_in_s`` — never the requesting
        agent's; without it, grants have no expiry (``once`` grants still die
        on first use).
        """
        return await self._broker.request(req)

    def request_permission_sync(self, req: PermissionRequest) -> Decision:
        """Sync shim over :meth:`request_permission` for non-async hosts.

        Runs its own event loop, so it must not be called from inside a
        running loop — ``await guard.request_permission(...)`` there instead.
        """
        return asyncio.run(self.request_permission(req))

    def confirm(self, challenge_id: str, typed_phrase: str, remember: bool = False) -> bool:
        """Verify a typed confirmation phrase for a destructive-action challenge (D6).

        Host-facing: the typed phrase must come from the human channel. On
        success the agent may retry the blocked call with
        ``fluffy_challenge_id=<challenge_id>``. ``remember=True`` also
        whitelists the (tool, resource_kind) so future matching calls skip
        the gate.
        """
        return self._confirm.confirm(challenge_id, typed_phrase, remember=remember)

    def challenge_phrase(self, challenge_id: str) -> str | None:
        """The confirmation phrase for a challenge — host/human-channel use only (D6).

        Deliberately absent from :class:`fluffy.ConfirmationRequired`: the host
        shows the phrase to the human out-of-band so a prompt-injected agent
        can't confirm itself. ``None`` for an unknown challenge id.
        """
        return self._confirm.challenge_phrase(challenge_id)

    def audit_tail(self, n: int = 20) -> list[sqlite3.Row]:
        """The last ``n`` audit rows, oldest first."""
        return audit_tail(self.connection, n)

    def close(self) -> None:
        """Undo everything ``__init__`` installed: filters, store registration, DB."""
        for target in self._filter_targets:
            target.removeFilter(self._logging_filter)
        self._filter_targets.clear()
        unregister_secret_store(self.secret_store)
        self.connection.close()

    def __enter__(self) -> Guard:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()
