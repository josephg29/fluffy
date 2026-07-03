# fluffy

A drop-in guard layer for autonomous agents: secret redaction, hard spend caps,
typed confirmation for destructive actions, and in-conversation permission
changes — at under 20 ms per guarded call.

> Status: pre-release. FLUF-1 (core pipeline, secret store, redaction) is
> implemented; spend caps, confirmation gates, and the permission broker land
> in subsequent tickets.

## Quick taste

```python
import fluffy

guard = fluffy.Guard(db_path="~/.fluffy/state.db")
guard.secret_store.put("stripe_key", "sk_live_...")

safe_tool = guard.wrap(charge, meta=fluffy.ToolMeta(name="stripe.charge", tags={"spend"}))

# Agents only ever see handles like {{secret:stripe_key}} — the real value is
# substituted at the last moment before the tool executes, and scrubbed from
# results, logs, and audit rows on the way out.
```

## Development

```sh
uv venv && uv pip install -e '.[dev]'
uv run pytest
uv run ruff check . && uv run ruff format --check .
uv run mypy --strict src
```

Zero runtime dependencies — stdlib only. MIT licensed.
