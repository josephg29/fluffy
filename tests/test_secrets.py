from __future__ import annotations

import pytest

from fluffy.context import CallContext, ToolMeta
from fluffy.secrets import (
    MemorySecretStore,
    SecretRedactInterceptor,
    SecretResolveInterceptor,
    handle_for,
)


def _ctx(args: tuple[object, ...] = (), kwargs: dict[str, object] | None = None) -> CallContext:
    return CallContext(tool=ToolMeta(name="t"), args=args, kwargs=kwargs or {})


def test_put_and_resolve() -> None:
    store = MemorySecretStore()
    store.put("api_key", "hunter2")
    assert store.resolve("api_key") == "hunter2"
    assert "hunter2" in list(store.known_values())


def test_resolve_unknown_raises_keyerror() -> None:
    store = MemorySecretStore()
    with pytest.raises(KeyError):
        store.resolve("nope")


def test_invalid_secret_name_rejected() -> None:
    store = MemorySecretStore()
    with pytest.raises(ValueError):
        store.put("bad name!", "v")


def test_resolve_interceptor_deep_walks_nested_structures() -> None:
    store = MemorySecretStore()
    store.put("pw", "real-value")
    handle = handle_for("pw")
    ctx = _ctx(
        args=(f"prefix {handle} suffix", [handle, {"k": handle}], 42),
        kwargs={"nested": {"tup": (handle,), "s": {handle}}, "plain": 7},
    )
    SecretResolveInterceptor(store).before(ctx)
    assert ctx.args[0] == "prefix real-value suffix"
    assert ctx.args[1] == ["real-value", {"k": "real-value"}]
    assert ctx.args[2] == 42
    assert ctx.kwargs["nested"] == {"tup": ("real-value",), "s": {"real-value"}}
    assert ctx.kwargs["plain"] == 7


def test_resolve_unknown_handle_raises() -> None:
    store = MemorySecretStore()
    ctx = _ctx(args=("{{secret:missing}}",))
    with pytest.raises(KeyError):
        SecretResolveInterceptor(store).before(ctx)


def test_redact_interceptor_masks_result_back_to_handle() -> None:
    store = MemorySecretStore()
    store.put("pw", "real-value")
    ctx = _ctx()
    ctx.result = {"msg": "connected with real-value", "items": ["real-value", 1]}
    SecretRedactInterceptor(store).after(ctx)
    assert ctx.result == {
        "msg": "connected with {{secret:pw}}",
        "items": ["{{secret:pw}}", 1],
    }


def test_redact_interceptor_masks_error_args() -> None:
    store = MemorySecretStore()
    store.put("pw", "real-value")
    ctx = _ctx()
    ctx.error = RuntimeError("auth failed for real-value")
    SecretRedactInterceptor(store).after(ctx)
    assert "real-value" not in str(ctx.error)
    assert "{{secret:pw}}" in str(ctx.error)


def test_unknown_secret_is_blocked_and_keyerror() -> None:
    from fluffy import Blocked, UnknownSecret

    store = MemorySecretStore()
    with pytest.raises(UnknownSecret) as excinfo:
        store.resolve("missing_key")
    exc = excinfo.value
    assert isinstance(exc, Blocked)
    assert isinstance(exc, KeyError)  # pre-0.2 compat
    assert exc.name == "missing_key"
    assert exc.payload == {"name": "missing_key"}
    # plain, agent-relayable message (not KeyError's repr form)
    assert str(exc) == (
        "Blocked: no secret named 'missing_key' in the secret store; "
        "store it first with guard.secret_store.put('missing_key', ...)."
    )


def test_malformed_handle_fails_closed() -> None:
    from fluffy.exceptions import GuardConfigError

    store = MemorySecretStore()
    store.put("good", "value")
    interceptor = SecretResolveInterceptor(store)
    for bad in ("{{secret:}}", "{{secret:bad name!}}", "{{secret:unclosed"):
        ctx = _ctx(args=(bad,))
        with pytest.raises(GuardConfigError, match="malformed secret handle"):
            interceptor.before(ctx)
    # a valid handle in the same text still resolves normally
    ctx = _ctx(args=("{{secret:good}}",))
    interceptor.before(ctx)
    assert ctx.args[0] == "value"


def test_invalid_secret_name_message_explains_the_rule() -> None:
    store = MemorySecretStore()
    with pytest.raises(ValueError, match=r"names must match \[A-Za-z0-9_.-\]\+"):
        store.put("bad name!", "v")
