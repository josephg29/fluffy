"""Two-layer redaction (decision D4).

Layer 1 — known-value scrub: exact match against every registered secret
store's values (raw, URL-encoded, and base64 forms), replaced with the
secret's ``{{secret:name}}`` handle.

Layer 2 — pattern scrub: Luhn-validated 13-19 digit card numbers (with spaces
or dashes), API-key shapes (``sk-``, ``sk_live_``, ``ghp_``, ``AKIA``), and
generic 32+ character high-entropy tokens (≥ 4.5 bits/char Shannon entropy).

Delivery: :func:`redact` for transcript text, :class:`RedactionFilter` for the
logging tree. The audit writer applies :func:`redact` unconditionally.
"""

from __future__ import annotations

import base64
import functools
import logging
import math
import re
import traceback
import urllib.parse
from collections.abc import Iterable

from .secrets import SecretStore, handle_for

__all__ = [
    "RedactionFilter",
    "clear_secret_stores",
    "mask_known_values",
    "redact",
    "register_secret_store",
    "unregister_secret_store",
]

CARD_PLACEHOLDER = "[REDACTED:card]"
KEY_PLACEHOLDER = "[REDACTED:key]"
TOKEN_PLACEHOLDER = "[REDACTED:token]"

_ENTROPY_THRESHOLD_BITS = 4.5
_ENTROPY_MIN_LENGTH = 32

# Runs of 13-19 digits, optionally separated by single spaces or dashes,
# not embedded in a longer digit run.
_CARD_RE = re.compile(r"(?<!\d)(?:\d[ \-]?){12,18}\d(?!\d)")

_KEY_RES = (
    re.compile(r"\bsk_live_[A-Za-z0-9]{16,}"),
    re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
)

_TOKEN_RE = re.compile(rf"[A-Za-z0-9+/=_\-]{{{_ENTROPY_MIN_LENGTH},}}")

# Module-level registry so fluffy.redact(text) and the logging filter see the
# secrets registered by any live Guard.
_stores: list[SecretStore] = []


def register_secret_store(store: SecretStore) -> None:
    if store not in _stores:
        _stores.append(store)


def unregister_secret_store(store: SecretStore) -> None:
    if store in _stores:
        _stores.remove(store)


def clear_secret_stores() -> None:
    _stores.clear()


def _luhn_valid(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _shannon_entropy_bits(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


@functools.lru_cache(maxsize=1024)
def _encoded_forms(value: str) -> tuple[str, ...]:
    """The value itself plus URL-encoded and base64 variants.

    Cached per value: this runs for every log record, and the variants of a
    given secret never change. Forms shorter than 4 characters are dropped —
    replacing them would mangle unrelated text.
    """
    forms = [value]
    quoted = urllib.parse.quote(value, safe="")
    if quoted != value:
        forms.append(quoted)
    raw = value.encode("utf-8", errors="surrogateescape")
    b64 = base64.b64encode(raw).decode("ascii")
    forms += [b64, b64.rstrip("=")]
    urlsafe = base64.urlsafe_b64encode(raw).decode("ascii")
    if urlsafe != b64:
        forms += [urlsafe, urlsafe.rstrip("=")]
    return tuple(dict.fromkeys(form for form in forms if len(form) >= 4))


def mask_known_values(text: str, items: Iterable[tuple[str, str]]) -> str:
    """Replace each secret value (raw, URL-encoded, or base64) with its handle.

    The single known-value masking policy — the logging/transcript scrub and
    the result-masking interceptor both call this. Returns ``text`` unchanged
    (same object) when nothing matches.
    """
    for name, value in items:
        if not value:
            continue
        handle = handle_for(name)
        for form in _encoded_forms(value):
            if form in text:
                text = text.replace(form, handle)
    return text


def _scrub_known_values(text: str) -> str:
    for store in _stores:
        text = mask_known_values(text, store.items())
    return text


def _scrub_cards(text: str) -> str:
    def repl(match: re.Match[str]) -> str:
        digits = match.group(0).replace(" ", "").replace("-", "")
        if 13 <= len(digits) <= 19 and _luhn_valid(digits):
            return CARD_PLACEHOLDER
        return match.group(0)

    return _CARD_RE.sub(repl, text)


def _scrub_keys(text: str) -> str:
    for pattern in _KEY_RES:
        text = pattern.sub(KEY_PLACEHOLDER, text)
    return text


def _scrub_entropy(text: str) -> str:
    if len(text) < _ENTROPY_MIN_LENGTH:  # short-circuit: nothing can match
        return text

    def repl(match: re.Match[str]) -> str:
        token = match.group(0)
        if _shannon_entropy_bits(token) >= _ENTROPY_THRESHOLD_BITS:
            return TOKEN_PLACEHOLDER
        return token

    return _TOKEN_RE.sub(repl, text)


def redact(text: str) -> str:
    """Scrub known secret values and secret-shaped patterns from ``text``."""
    text = _scrub_known_values(text)
    text = _scrub_keys(text)
    text = _scrub_cards(text)
    text = _scrub_entropy(text)
    return text


class RedactionFilter(logging.Filter):
    """Rewrites log records in place so no handler ever sees a secret.

    Attach to loggers and/or handlers; mutation happens once (the formatted
    message replaces ``msg``/``args``, and the traceback is pre-formatted into
    ``exc_text`` so :class:`logging.Formatter` reuses the scrubbed version).
    Records are stamped so a record passing through several filter attachment
    points (e.g. root logger and a root handler) is only redacted once.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if record.__dict__.get("_fluffy_redacted", False):
            return True
        record.__dict__["_fluffy_redacted"] = True
        record.msg = redact(record.getMessage())
        record.args = None
        if record.exc_info and not record.exc_text:
            exc = record.exc_info[1] if isinstance(record.exc_info, tuple) else None
            if isinstance(exc, BaseException):
                formatted = "".join(traceback.format_exception(exc))
                record.exc_text = redact(formatted).rstrip("\n")
        elif record.exc_text:
            record.exc_text = redact(record.exc_text)
        if record.stack_info:
            record.stack_info = redact(record.stack_info)
        return True
