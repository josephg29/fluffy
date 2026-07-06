# fluffy-guard 0.1.1

UX-hardening release driven by a first-time-user field test (an autonomous
agent following the README cold). No schema changes; drop-in upgrade.

## Fixed

- **README quickstart now runs verbatim, top to bottom.** The permissions
  section's `$15` budget increase could not cover the `$40` charge after the
  spend section's `$10` (grant math), and the destructive section referenced
  an undefined `typed_phrase_from_human`. The listing now uses a local
  `quickstart.db`, a `$30` increase, and a real `input()` prompt — verified
  end-to-end under a pty.
- **`fluffy audit tail -n -1` no longer dumps the entire table** (a negative
  SQLite `LIMIT` means "no limit"); `-n` now rejects negatives.

## Changed

- An unknown `{{secret:name}}` handle now raises `fluffy.UnknownSecret` — a
  `Blocked` subclass with the usual relayable message — instead of a bare
  `KeyError`. It still inherits `KeyError`, so existing `except KeyError`
  code keeps working.
- A `budget_increase` request for a card with no registered spend policy now
  raises `GuardConfigError` instead of silently minting a grant nothing can
  spend against.
- `guard.wrap(fn)` no longer requires `meta` for untagged, normally-named
  functions — it defaults to `ToolMeta(name=fn.__name__)`. Lambdas/partials
  and anything tagged still need an explicit `ToolMeta`. The destructive-name
  safety net applies to defaulted names too.

## CLI

- `fluffy --version`.
- On a terminal: a column header row and friendly messages for empty results
  (`(no audit events yet)`, `(no audit events match '…')`). Piped output is
  unchanged bare lines.

## Docs

- README states the **Python 3.11+** requirement and explains pip's
  misleading `No matching distribution found` on older interpreters.
- Documented approver-chain exhaustion (all abstain / empty chain ⇒ denied),
  `confirm()` idempotency before consumption, and the CLI column order in
  `docs/events.md`.
