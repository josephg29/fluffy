# fluffy 0.1.0

First release. A drop-in guard layer for autonomous agents — a library your
host framework imports, not a proxy — with zero runtime dependencies.

Each feature below maps to the promise it fulfills from the agent-safety spec.

## Spec promises → shipped features

| Spec promise | Shipped as |
|---|---|
| Secrets never reach the agent, transcripts, or logs | Handle substitution (`{{secret:name}}`) with last-moment resolution and result re-masking; two-layer redaction (known values incl. URL-encoded/base64 forms + Luhn cards, `sk-`/`sk_live_`/`ghp_`/`AKIA` keys, high-entropy tokens); `fluffy.redact()`, a root-logger `logging.Filter`, and an audit writer that redacts unconditionally. Verified by the e2e "grep the DB bytes for the secret" acceptance. |
| Hard spend caps an agent cannot talk its way past ($50 vs $25 blocks) | `SpendPolicy(per_use_cap_cents, daily_cap_cents, tz)`, default $25/$25; atomic reserve-then-settle in one `BEGIN IMMEDIATE` transaction — concurrent over-cap racing is impossible; crash-orphaned reservations expire after 15 min; timezone-correct daily window with no reset job. |
| Destructive actions need typed human confirmation | Challenge/retry loop: `ConfirmationRequired` → human types `DELETE <nn>` (fresh nonce, 5-min expiry, single-use, 3-strike void) → retry with `fluffy_challenge_id`. Wrap-time safety net for destructive-looking names. "Override & remember" whitelisting. **Hardening beyond the spec:** the phrase is not in the agent-visible exception; hosts fetch it via `Guard.challenge_phrase()` so a prompt-injected agent cannot confirm itself. |
| Permission changes mid-conversation, no restart | `guard.request_permission()` with an approver-chain protocol (one async method), `ConsoleApprover` default, opt-in `GuardianBot(auto_approve_under_cents=100)`; `budget_increase` grants apply to the very next spend (`once` grants consumed atomically inside the spend transaction); `access_grant` gates `restricted`-tagged tools. |
| Guarding must not slow the agent (<20 ms per guarded call) | D8 budgets CI-enforced on every PR: untagged overhead < 1 ms (measured ~5 µs), guarded spend < 20 ms p95 (measured ~0.09 ms mean), 100-step mixed job < 0.5 s added (measured ~3 ms). Untagged calls touch no I/O at all. |
| Full auditability | Single `audit_log` with one closed event vocabulary across all four guards (docs/events.md); `fluffy audit tail` / `fluffy audit grep` CLI. |
| Works with real agent frameworks | LangChain adapter (`fluffy[langchain]`): `guard_tools()` wraps `_run`/`_arun`; blocks surface as `ToolException` with the plain-English message the agent relays. |
| Spec §3 acceptance table | Re-run end-to-end against the built wheel in a clean venv on every CI run (`tests/e2e/test_spec_acceptance.py`): secret grep, $50-vs-$25 block, delete confirmation loop, permission approve flow. |

## Honest limitations (see README threat model)

Not defended against: a malicious host process, confirmation phrases pasted
into the agent's own channel, or side channels outside wrapped tools. No
Vault backend yet (the `SecretStore` protocol is the seam), no dashboards, no
trash-bin/undo, LangChain is the only adapter.

## Compatibility

Python 3.11–3.13. State lives in `~/.fluffy/state.db` (configurable);
schema migrations run automatically at `Guard` init.
