"""fluffy — a drop-in guard layer for autonomous agents."""

from .context import CallContext, Decision, DestructiveSpec, SpendSpec, ToolMeta
from .exceptions import (
    Blocked,
    ConfirmationRequired,
    GuardConfigError,
    PermissionDenied,
    SpendLimitExceeded,
    UnknownSecret,
)
from .guard import Guard, Interceptor
from .permissions import (
    ApprovalChain,
    Approver,
    ConsoleApprover,
    GuardianBot,
    PermissionRequest,
)
from .redact import RedactionFilter, redact
from .secrets import MemorySecretStore, SecretStore
from .spend import SpendPolicy

__version__ = "0.1.1"

__all__ = [
    "ApprovalChain",
    "Approver",
    "Blocked",
    "CallContext",
    "ConfirmationRequired",
    "ConsoleApprover",
    "Decision",
    "DestructiveSpec",
    "Guard",
    "GuardConfigError",
    "GuardianBot",
    "Interceptor",
    "MemorySecretStore",
    "PermissionDenied",
    "PermissionRequest",
    "RedactionFilter",
    "SecretStore",
    "SpendLimitExceeded",
    "SpendPolicy",
    "SpendSpec",
    "ToolMeta",
    "UnknownSecret",
    "redact",
]
