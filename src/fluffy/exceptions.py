"""Typed guard exceptions (decision D2).

All denials inherit from :class:`Blocked` so host frameworks catch a single
type. Messages are pre-formatted plain English an agent can relay verbatim.

Subclasses set their typed attributes first, then call ``super().__init__``;
the machine-readable ``payload`` is derived from ``_payload_fields`` so each
field is declared once.
"""

from __future__ import annotations

from typing import ClassVar

__all__ = [
    "Blocked",
    "ConfirmationRequired",
    "GuardConfigError",
    "PermissionDenied",
    "SpendLimitExceeded",
    "UnknownSecret",
]


def _dollars(cents: int) -> str:
    return f"${cents / 100:.2f}"


class GuardConfigError(Exception):
    """Raised at wrap/config time for invalid guard configuration."""


class Blocked(Exception):
    """Root of all guard denials.

    Carries a human ``reason``, the ``call_id`` of the blocked call, and a
    machine-readable ``payload`` dict (derived from ``_payload_fields`` unless
    passed explicitly).
    """

    _payload_fields: ClassVar[tuple[str, ...]] = ()

    reason: str
    call_id: str
    payload: dict[str, object]

    def __init__(
        self,
        message: str,
        *,
        reason: str = "",
        call_id: str = "",
        payload: dict[str, object] | None = None,
    ) -> None:
        super().__init__(message)
        self.reason = reason or message
        self.call_id = call_id
        self.payload = (
            payload
            if payload is not None
            else {name: getattr(self, name) for name in self._payload_fields}
        )


class SpendLimitExceeded(Blocked):
    """A spend would exceed the per-use or daily cap."""

    _payload_fields = (
        "requested_cents",
        "cap_cents",
        "spent_cents",
        "remaining_cents",
        "cap_kind",
    )

    requested_cents: int
    cap_cents: int
    spent_cents: int
    remaining_cents: int
    cap_kind: str

    def __init__(
        self,
        *,
        requested_cents: int,
        cap_cents: int,
        spent_cents: int,
        remaining_cents: int,
        cap_kind: str = "daily",
        call_id: str = "",
    ) -> None:
        self.requested_cents = requested_cents
        self.cap_cents = cap_cents
        self.spent_cents = spent_cents
        self.remaining_cents = remaining_cents
        self.cap_kind = cap_kind
        super().__init__(
            f"Blocked: {_dollars(self.requested_cents)} requested, "
            f"{cap_kind} cap {_dollars(self.cap_cents)}, "
            f"{_dollars(self.spent_cents)} already spent today; "
            f"{_dollars(self.remaining_cents)} remaining.",
            reason="spend_limit_exceeded",
            call_id=call_id,
        )


class ConfirmationRequired(Blocked):
    """A destructive action needs a typed confirmation phrase."""

    _payload_fields = ("challenge_id", "summary", "phrase_format")

    challenge_id: str
    summary: str
    phrase_format: str

    def __init__(
        self,
        *,
        challenge_id: str,
        summary: str,
        phrase_format: str,
        call_id: str = "",
    ) -> None:
        self.challenge_id = challenge_id
        self.summary = summary
        self.phrase_format = phrase_format
        super().__init__(
            f"Confirmation required: {self.summary} "
            f"To proceed, the user must type the phrase (format: {self.phrase_format!r}); "
            f"then retry with fluffy_challenge_id={self.challenge_id!r}.",
            reason="confirmation_required",
            call_id=call_id,
        )


class UnknownSecret(Blocked, KeyError):
    """A ``{{secret:name}}`` handle references a secret that was never stored.

    Inherits :class:`KeyError` too, so pre-0.2 code catching ``KeyError``
    keeps working; new code should catch :class:`Blocked`.
    """

    _payload_fields = ("name",)

    name: str

    def __init__(self, *, name: str, call_id: str = "") -> None:
        self.name = name
        super().__init__(
            f"Blocked: no secret named {name!r} in the secret store; "
            f"store it first with guard.secret_store.put({name!r}, ...).",
            reason="unknown_secret",
            call_id=call_id,
        )

    # KeyError.__str__ would repr() the message (quotes around everything);
    # keep the plain, agent-relayable form.
    __str__ = Exception.__str__


class PermissionDenied(Blocked):
    """A permission request or restricted call was denied."""

    _payload_fields = ("request_id", "decider")

    request_id: str
    decider: str

    def __init__(
        self,
        *,
        request_id: str,
        decider: str,
        message: str | None = None,
        call_id: str = "",
    ) -> None:
        self.request_id = request_id
        self.decider = decider
        super().__init__(
            message or f"Blocked: permission denied by {decider} (request {request_id}).",
            reason="permission_denied",
            call_id=call_id,
        )
