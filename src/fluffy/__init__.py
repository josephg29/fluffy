"""fluffy — a drop-in guard layer for autonomous agents."""

from .context import CallContext, Decision, DestructiveSpec, SpendSpec, ToolMeta
from .exceptions import (
    Blocked,
    ConfirmationRequired,
    GuardConfigError,
    PermissionDenied,
    SpendLimitExceeded,
)
from .guard import Guard, Interceptor
from .redact import RedactionFilter, redact
from .secrets import MemorySecretStore, SecretStore
from .spend import SpendPolicy

__version__ = "0.1.0.dev0"

__all__ = [
    "Blocked",
    "CallContext",
    "ConfirmationRequired",
    "Decision",
    "DestructiveSpec",
    "Guard",
    "GuardConfigError",
    "Interceptor",
    "MemorySecretStore",
    "PermissionDenied",
    "RedactionFilter",
    "SecretStore",
    "SpendLimitExceeded",
    "SpendPolicy",
    "SpendSpec",
    "ToolMeta",
    "redact",
]
