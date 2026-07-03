"""Call context and tool metadata (decision D2)."""

from __future__ import annotations

import uuid
from collections.abc import Callable, Set
from dataclasses import dataclass, field
from typing import Any

from .db import utc_now_iso

__all__ = [
    "CallContext",
    "Decision",
    "DestructiveSpec",
    "SpendSpec",
    "ToolMeta",
]


@dataclass(frozen=True, slots=True)
class SpendSpec:
    """How to extract the amount for a spend-tagged tool."""

    card_id: str
    amount_from: Callable[[tuple[Any, ...], dict[str, Any]], int]


@dataclass(frozen=True, slots=True)
class DestructiveSpec:
    """Declares a destructive tool: what it destroys and how to summarize it."""

    resource_kind: str
    summary_from: Callable[[tuple[Any, ...], dict[str, Any]], str]


@dataclass(frozen=True, slots=True)
class ToolMeta:
    """Static metadata attached to a wrapped tool."""

    name: str
    tags: Set[str] = frozenset()
    spend: SpendSpec | None = None
    destructive: DestructiveSpec | None = None


@dataclass(frozen=True, slots=True)
class Decision:
    """Outcome of a permission/approval step."""

    approved: bool
    decider: str
    message: str


@dataclass(slots=True)
class CallContext:
    """Mutable per-call state threaded through the interceptor pipeline.

    Identity fields (``call_id``, ``tool``) are set once at creation;
    ``args``/``kwargs``/``result``/``error`` are updated by interceptors
    (secret resolution rewrites args, redaction rewrites the result).
    """

    tool: ToolMeta
    args: tuple[Any, ...]
    kwargs: dict[str, Any]
    call_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    decisions: list[Decision] = field(default_factory=list)
    started_at: str = field(default_factory=utc_now_iso)
    ended_at: str | None = None
    result: Any = None
    error: BaseException | None = None
