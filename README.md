# fluffy

A drop-in guard layer for autonomous agents: secret redaction, hard spend
caps, typed confirmation for destructive actions, and in-conversation
permission changes — at well under 20 ms per guarded call.

fluffy is a library, not a proxy: your host framework imports it and wraps
tool callables. Untagged tools pay ~5 µs of overhead and touch no I/O; guarded
tools go through SQLite-backed, crash-safe checks. Zero runtime dependencies
(stdlib only). MIT licensed.

## Install

```sh
pip install fluffy-guard        # core, stdlib-only
pip install 'fluffy-guard[langchain]'  # + the LangChain adapter
```

The distribution is named `fluffy-guard` (the `fluffy` name on PyPI was
taken); you still `import fluffy` in code.

## 5-minute quickstart

One `Guard` per agent process. Wrap one tool of each kind and watch a block
happen:

```python
import fluffy
from fluffy import (
    DestructiveSpec, Guard, PermissionRequest, SpendPolicy, SpendSpec, ToolMeta,
)

guard = Guard(db_path="~/.fluffy/state.db")   # opens SQLite, installs redaction

# --- 1. Secrets: agents only ever see handles -------------------------------
guard.secret_store.put("stripe_key", "sk_live_...real value...")

def call_api(key: str) -> str:
    return f"authenticated with {key}"

api = guard.wrap(call_api, meta=ToolMeta(name="api.call"))
api("{{secret:stripe_key}}")
# the tool received the real value; the result, all logs, and every audit row
# only ever contain "{{secret:stripe_key}}" (plus Luhn-card / API-key /
# high-entropy pattern scrubbing via fluffy.redact()).

# --- 2. Spend caps: $25/day default, atomic reserve-then-settle -------------
guard.add_spend_policy(SpendPolicy(card_id="ops"))  # $25 per-use, $25/day

charge = guard.wrap(
    lambda *, amount_cents: f"charged {amount_cents}",
    meta=ToolMeta(
        name="stripe.charge",
        tags={"spend"},
        spend=SpendSpec(card_id="ops", amount_from=lambda a, k: k["amount_cents"]),
    ),
)
charge(amount_cents=1000)   # $10: fine
charge(amount_cents=5000)   # raises fluffy.SpendLimitExceeded:
# "Blocked: $50.00 requested, per-use cap $25.00, $10.00 already spent today;
#  $15.00 remaining."  <- relay this string to the agent verbatim

# --- 3. Destructive actions: typed confirmation over the human channel ------
delete = guard.wrap(
    lambda name: f"deleted {name}",
    meta=ToolMeta(
        name="delete_project",
        tags={"destructive"},
        destructive=DestructiveSpec(
            resource_kind="project",
            summary_from=lambda a, k: f"This deletes the project {a[0]!r}. "
                                      "This cannot be undone.",
        ),
    ),
)
try:
    delete("my-project")
except fluffy.ConfirmationRequired as exc:
    # Show exc.summary to the human. The phrase is DELIBERATELY not in the
    # exception the agent sees — the HOST fetches it out-of-band:
    phrase = guard.challenge_phrase(exc.challenge_id)      # e.g. "DELETE 42"
    # ...human types it into YOUR ui, not the agent's chat...
    assert guard.confirm(exc.challenge_id, typed_phrase_from_human)
    delete("my-project", fluffy_challenge_id=exc.challenge_id)  # runs once

# --- 4. Permissions: raise a cap mid-conversation ---------------------------
decision = guard.request_permission_sync(
    PermissionRequest(kind="budget_increase", subject="ops", value=1500,
                      duration="once", rationale="the gadget costs $40")
)
if decision.approved:
    charge(amount_cents=4000)   # succeeds exactly once; the grant is consumed
```

Every denial inherits from `fluffy.Blocked`, so a host catches one type; every
message is pre-formatted plain English the agent can relay verbatim.

## LangChain adapter

```python
from fluffy.adapters.langchain import guard_tools

tools = guard_tools(lc_tools, guard, metas={"buy_gadget": ToolMeta(...)})
# Blocked -> langchain_core.tools.ToolException(str(e)); set
# handle_tool_error=True on the tool and the agent loop sees the block as a
# normal observation it can relay to the user.
```

Tools without a `metas` entry are wrapped untagged (secret resolution +
redaction only, no I/O).

## Per-guard configuration reference

### Guard

| Parameter | Default | Meaning |
|---|---|---|
| `db_path` | `~/.fluffy/state.db` | SQLite state (WAL, `busy_timeout=5000`); migrations run at init |
| `secret_store` | `MemorySecretStore()` | anything implementing the `SecretStore` protocol (`put/resolve/known_values/items`) |
| `approvers` | `[ConsoleApprover()]` | the permission approver chain, first non-abstain wins |

`ToolMeta(name, tags, spend, destructive)` — tags in `{"spend",
"destructive", "restricted"}` route a call through the guard pipeline; any
other call takes the no-I/O fast path.

### Secrets & redaction (D4)

- Handles look like `{{secret:name}}`; values are substituted at the last
  moment before execution and masked back on the way out (raw, URL-encoded,
  and base64 forms).
- Pattern scrub: Luhn-valid 13–19-digit card numbers, `sk-…`/`sk_live_…`/
  `ghp_…`/`AKIA…` keys, and 32+-char tokens with ≥ 4.5 bits/char Shannon
  entropy.
- `fluffy.redact(text)` for transcripts; a `logging.Filter` covers the root
  logger; the audit writer redacts unconditionally.

### Spend guard (D5)

| `SpendPolicy` field | Default | Meaning |
|---|---|---|
| `card_id` | — | ledger key; referenced by `SpendSpec(card_id=...)` |
| `per_use_cap_cents` | `2500` | hard cap per call |
| `daily_cap_cents` | `2500` | hard cap per calendar day |
| `tz` | `America/Los_Angeles` | timezone that defines "day" (computed at query time; no reset job) |

Two-phase and atomic: the cap check and the reservation share one
`BEGIN IMMEDIATE` transaction, so concurrent over-cap racing is impossible.
Reservations orphaned by a crash stop counting after 15 minutes. All money is
integer cents.

### Confirmation gate (D6)

- Declared, not inferred: `tags={"destructive"}` +
  `DestructiveSpec(resource_kind, summary_from)`. Safety net: a tool name
  matching `delete|drop|destroy|remove|truncate|migrate` without a spec fails
  at `wrap()` time (`GuardConfigError`) — declare or whitelist.
- Challenges: phrase `DELETE <nn>` with a fresh 2-digit nonce, 5-minute
  expiry, single-use, voided after 3 wrong attempts.
- `guard.confirm(id, phrase, remember=True)` whitelists the
  (tool, resource_kind) pair; future matches skip the gate and audit as
  `whitelisted`.
- The phrase travels over the human channel via
  `guard.challenge_phrase(challenge_id)` — it is intentionally **not** in the
  `ConfirmationRequired` payload the agent sees (see threat model).

### Permission broker (D7)

- Two request kinds only: `budget_increase` (value = increase delta in cents;
  spend caps become base + active grants, `once` grants consumed atomically by
  the spend that uses them) and `access_grant` (tools tagged `"restricted"`
  deny with `PermissionDenied` unless a live grant for the tool name exists).
- Approvers implement one async method `decide(req) -> Decision | None`
  (`None` = abstain). Ships with `ConsoleApprover` (default) and
  `GuardianBot(auto_approve_under_cents=100)` — off unless you add it to the
  chain. A Slack/web approver is a one-method class.
- Grant lifetime is the approver's call (`Decision.expires_in_s`), never the
  requesting agent's.

### Audit

One event vocabulary across all four guards — see
[docs/events.md](docs/events.md). Inspect with `guard.audit_tail(n)` or:

```sh
fluffy audit tail -n 50
fluffy audit grep stripe.charge
```

## Performance

Budgets are CI-enforced on every PR (`tests/bench/`, D8): untagged overhead
< 1 ms, spend-guarded call < 20 ms p95, 100-step mixed job < 0.5 s total added
wall time. Measured locally (Apple Silicon, Python 3.12, WAL SQLite):

| Benchmark | Budget | Measured |
|---|---|---|
| untagged wrapped call overhead | < 1 ms | ~0.005 ms |
| spend-guarded call | < 20 ms p95 | ~0.09 ms mean, < 1.2 ms max |
| 100-step mixed job (60 untagged / 30 spend / 10 whitelisted) | < 0.5 s | ~0.003 s |

The fast path is a set intersection: a call with no guard tags never touches
SQLite.

## Threat model — what fluffy does NOT defend against

Honesty section. fluffy is a guard layer inside your process, not a sandbox:

- **A malicious or compromised host process.** fluffy shares the interpreter
  with the host; anything with code execution can call the tool functions
  directly, read the secret store's memory, or edit the SQLite state.
- **A prompt-injected agent confirming its own destructive actions.** That is
  why the confirmation phrase is *not* in the `ConfirmationRequired` exception:
  the agent cannot see it. Hosts must fetch it with
  `guard.challenge_phrase(id)` and collect the typed phrase from the human
  over a channel the agent does not write to. If you paste the phrase into the
  agent's own conversation, you have reopened the hole.
- **Side channels outside wrapped tools.** Only calls that go through
  `guard.wrap()` are guarded. An agent with raw `subprocess`, network, or
  filesystem access can spend, delete, and leak without fluffy ever seeing it.
  Wrap every tool; give the agent nothing unwrapped.
- Redaction is best-effort defense in depth: known values (and their encoded
  forms) plus common secret shapes. A secret transformed in ways fluffy cannot
  recognize (e.g. rot13) can still leak.

## Development

```sh
uv venv && uv pip install -e '.[dev]'
uv run pytest -q            # fast suite (e2e excluded)
uv run pytest tests/bench   # D8 budget gate
uv run pytest -m e2e -q     # spec acceptance against the built wheel
uv run ruff check . && uv run ruff format --check .
uv run mypy --strict src
```

See [CONTRIBUTING.md](CONTRIBUTING.md). Release notes:
[docs/RELEASE_NOTES_0.1.0.md](docs/RELEASE_NOTES_0.1.0.md).
