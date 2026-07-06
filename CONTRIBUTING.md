# Contributing to fluffy

Thanks for helping guard the robots. Ground rules first, mechanics second.

## Ground rules

- **The core stays stdlib-only.** No runtime dependencies. Framework
  integrations live in `src/fluffy/adapters/` behind optional extras
  (`pip install fluffy-guard[langchain]`).
- **Locked decisions are locked.** The architecture (pipeline order, SQLite
  persistence, exception model, cap semantics, etc.) is documented in the
  build plan's Part I. If a decision proves wrong, open an issue and flag it —
  don't silently diverge in a PR.
- **Tests first for safety behavior.** Anything that blocks, redacts, or
  confirms gets its failure cases tested before the implementation.
- **One audit vocabulary.** New audit events must be added to
  [docs/events.md](docs/events.md) in the same PR that emits them.
- **Performance is a gate, not a goal.** CI fails PRs that break the D8
  budgets — the numbers live in `tests/bench/test_benchmarks.py`. The
  no-tag fast path must never touch I/O.

## Dev setup

```sh
uv venv && uv pip install -e '.[dev]'
```

## Checks to run before pushing

```sh
uv run pytest -q                 # fast suite
uv run pytest -m bench -q        # performance budgets
uv run pytest -m e2e -q          # wheel-based spec acceptance (needs uv)
uv run ruff check . && uv run ruff format --check .
uv run mypy --strict src
```

All five must be green; CI runs the same jobs (`lint`, `typecheck`, `test` on
3.11/3.12/3.13, `bench`, `e2e`).

## Layout

```
src/fluffy/          core modules (guard, spend, confirm, permissions, secrets,
                     redact, audit, db, cli) + adapters/
migrations/          numbered SQL scripts; schema changes are additive-only
tests/               mirrors src modules; tests/bench/ = D8 gate,
                     tests/e2e/ = built-wheel spec acceptance
```

## Conventions

- Python ≥ 3.11, `ruff` for lint + format (line length 100), `mypy --strict`
  clean on `src/`.
- Money is integer cents. Timestamps are UTC ISO-8601 strings; the only
  timezone-aware computation is the daily-cap window.
- Denials are exceptions inheriting `fluffy.Blocked`, with pre-formatted
  plain-English messages an agent can relay verbatim.
- Migrations: never edit an applied migration; add a new numbered script.

## Releases

Maintainers only: bump the version, update
`docs/RELEASE_NOTES_<version>.md`, tag `v<version>`, and push the tag — the
`Publish` workflow builds and uploads to PyPI via trusted publishing (the tag
is created by a human, never by automation).
