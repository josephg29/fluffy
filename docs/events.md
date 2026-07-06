# Audit event vocabulary

Every guard writes to one `audit_log` table through one writer
(`fluffy.audit.write_audit_row`), which redacts the detail JSON
unconditionally — it is structurally impossible to write an unredacted audit
row. Inspect it with `guard.audit_tail(n)` or the CLI:

```sh
fluffy audit tail -n 50 [--db PATH]
fluffy audit grep <term> [--db PATH]
```

Each row is `(call_id, ts, tool, event, decision, detail_json)`; the CLI
prints the same fields time-first — `ts event decision tool call_id
detail_json` — and shows that header row when run on a terminal. `call_id`
ties every event of one tool call together (permission-broker events use the
request id). This is the complete, closed vocabulary; new events must be added
to this table in the same PR that emits them.

## Events by guard

| Guard | `event` | `decision` | Emitted when |
|---|---|---|---|
| pipeline (all calls) | `call` | `ok` / `blocked` / `error` | terminal record of every guarded call: succeeded / denied by a guard / tool raised |
| spend | `spend_reserved` | `ok` | cap check passed; amount reserved in the ledger (same transaction as the check) |
| spend | `spend_settled` | `ok` | tool succeeded; reservation flipped to settled |
| spend | `spend_released` | `released` | tool raised; reservation released, budget restored |
| spend | `spend_denied` | `blocked` | per-use or daily cap exceeded; payload carries requested/cap/spent/remaining cents |
| spend | `grant_consumed` | `ok` | this spend consumed `once` budget grant(s), atomically with the reserve |
| spend | `grant_restored` | `ok` | a released spend gave its consumed `once` grant(s) back |
| confirm | `challenge_created` | `blocked` | destructive call blocked pending the typed phrase (phrase itself is never audited) |
| confirm | `confirm_ok` | `ok` | correct phrase typed; challenge confirmed (detail notes `remembered` when whitelisting) |
| confirm | `confirm_failed` | `failed` | wrong phrase, or confirm attempted on an expired/used/voided challenge |
| confirm | `challenge_voided` | `voided` | third wrong phrase voided the challenge |
| confirm | `whitelisted` | `ok` | (tool, resource_kind) previously remembered; gate skipped |
| permissions (broker) | `permission_granted` | `ok` | approver chain approved; grant row written |
| permissions (broker) | `permission_denied` | `denied` | approver chain denied (or every approver abstained: decider `exhausted`) |
| permissions (access) | `access_allowed` | `ok` | restricted tool allowed by a live grant (detail notes whether a `once` grant was consumed) |
| permissions (access) | `access_denied` | `blocked` | restricted tool with no live access grant |

## Decision vocabulary

- `ok` — the guard allowed or completed the action.
- `blocked` — a guard stopped a tool call before execution (raised a
  `fluffy.Blocked` subclass).
- `denied` — a *permission request* (not a tool call) was turned down.
- `failed` — a confirmation attempt did not verify.
- `voided` — a challenge was permanently invalidated (3 wrong phrases).
- `released` — a spend reservation was returned because the tool errored.
- `error` — the tool itself raised a non-guard exception.

Naming rule: guard-specific events are `<noun>_<outcome>` scoped to their
guard (`spend_*`, `challenge_*`/`confirm_*`, `permission_*`, `access_*`,
`grant_*`); the pipeline's terminal record is always `call`.
