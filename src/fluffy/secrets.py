"""Secret store + handle substitution (decision D4).

Agents and transcripts only ever see handles — the literal string
``{{secret:name}}``. Real values are substituted at the last moment before
tool execution and masked back to handles on the way out.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from typing import Any, Protocol, runtime_checkable

from .context import CallContext

__all__ = [
    "HANDLE_RE",
    "MemorySecretStore",
    "SecretRedactInterceptor",
    "SecretResolveInterceptor",
    "SecretStore",
    "handle_for",
]

_NAME_RE = re.compile(r"[A-Za-z0-9_.\-]+")
HANDLE_RE = re.compile(r"\{\{secret:(" + _NAME_RE.pattern + r")\}\}")
_HANDLE_PREFIX = "{{secret:"


def handle_for(name: str) -> str:
    return _HANDLE_PREFIX + name + "}}"


@runtime_checkable
class SecretStore(Protocol):
    """Pluggable secret backend (a Vault store can implement this later)."""

    def put(self, name: str, value: str) -> None: ...

    def resolve(self, name: str) -> str: ...

    def known_values(self) -> Iterable[str]: ...

    def items(self) -> Iterable[tuple[str, str]]: ...


class MemorySecretStore:
    """In-process secret store. Values never leave the process."""

    def __init__(self) -> None:
        self._secrets: dict[str, str] = {}

    def put(self, name: str, value: str) -> None:
        if not _NAME_RE.fullmatch(name):
            raise ValueError(f"invalid secret name: {name!r}")
        self._secrets[name] = value

    def resolve(self, name: str) -> str:
        try:
            return self._secrets[name]
        except KeyError:
            raise KeyError(f"unknown secret: {name!r}") from None

    def known_values(self) -> Iterable[str]:
        return tuple(value for _, value in self.items())

    def items(self) -> Iterable[tuple[str, str]]:
        return tuple(self._secrets.items())


def _walk(value: Any, leaf: Callable[[str], str]) -> Any:
    """Deep-walk ``value``, applying ``leaf`` to every string.

    Containers (dict/list/tuple/set) are rebuilt only when a child actually
    changed; otherwise the original object is returned unmodified, keeping the
    untouched (hot-path) case allocation-free.
    """
    if isinstance(value, str):
        return leaf(value)
    if isinstance(value, dict):
        changed = False
        out: dict[Any, Any] = {}
        for key, val in value.items():
            new_key = _walk(key, leaf)
            new_val = _walk(val, leaf)
            changed = changed or new_key is not key or new_val is not val
            out[new_key] = new_val
        return out if changed else value
    if isinstance(value, (list, tuple, set)):
        walked = [_walk(item, leaf) for item in value]
        if all(new is old for new, old in zip(walked, value, strict=True)):
            return value
        if isinstance(value, list):
            return walked
        if isinstance(value, tuple):
            return tuple(walked)
        return set(walked)
    return value


def _resolve_leaf(store: SecretStore) -> Callable[[str], str]:
    """String transform replacing ``{{secret:name}}`` handles with real values."""

    def leaf(text: str) -> str:
        if _HANDLE_PREFIX not in text:  # fast path: preserve identity, skip the regex
            return text
        return HANDLE_RE.sub(lambda m: store.resolve(m.group(1)), text)

    return leaf


class SecretResolveInterceptor:
    """Substitutes secret handles in args/kwargs just before execution."""

    def __init__(self, store: SecretStore) -> None:
        self._store = store

    def before(self, ctx: CallContext) -> None:
        leaf = _resolve_leaf(self._store)
        ctx.args = _walk(ctx.args, leaf)
        ctx.kwargs = _walk(ctx.kwargs, leaf)

    def after(self, ctx: CallContext) -> None:  # pragma: no cover - no-op
        return None


class SecretRedactInterceptor:
    """Masks known secret values (raw or encoded) back to handles in the result."""

    def __init__(self, store: SecretStore) -> None:
        self._store = store

    def before(self, ctx: CallContext) -> None:
        return None

    def after(self, ctx: CallContext) -> None:
        # Deferred import: redact.py imports from this module at top level.
        from .redact import mask_known_values

        items = tuple(self._store.items())
        if not items:  # nothing can match — leave the result untouched
            return

        def leaf(text: str) -> str:
            return mask_known_values(text, items)

        if ctx.result is not None:
            ctx.result = _walk(ctx.result, leaf)
        if ctx.error is not None and ctx.error.args:
            ctx.error.args = tuple(_walk(arg, leaf) for arg in ctx.error.args)
