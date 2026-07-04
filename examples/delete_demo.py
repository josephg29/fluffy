"""fluffy confirmation gate demo: the full agent-driven challenge/retry loop.

A destructive ``delete_project`` tool is wrapped with a ``DestructiveSpec``.
The first call is blocked with a challenge; the "user" types the phrase over
the human channel; the agent retries with ``fluffy_challenge_id`` and the
delete runs exactly once. Then three wrong phrases void a second challenge,
and ``remember=True`` whitelists the (tool, resource_kind) so a later delete
passes gate-free.

Run:  uv run python examples/delete_demo.py
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from fluffy import ConfirmationRequired, DestructiveSpec, Guard, ToolMeta

PROJECTS = {"my-project": {"commits": 142, "branches": 3}}


def delete_project(name: str) -> str:
    PROJECTS.pop(name, None)
    return f"project {name!r} deleted"


def summarize(args: tuple[Any, ...], kwargs: dict[str, Any]) -> str:
    name = args[0] if args else kwargs["name"]
    stats = PROJECTS.get(name, {"commits": "?", "branches": "?"})
    return (
        f"This deletes the repo `{name}` — {stats['commits']} commits, "
        f"{stats['branches']} branches. This cannot be undone."
    )


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp, Guard(db_path=Path(tmp) / "state.db") as guard:
        wrapped: Any = guard.wrap(
            delete_project,
            meta=ToolMeta(
                name="delete_project",
                tags=frozenset({"destructive"}),
                destructive=DestructiveSpec(resource_kind="repo", summary_from=summarize),
            ),
        )

        # --- 1. Agent tries the delete; the guard blocks with a challenge.
        print("agent> delete_project('my-project')")
        try:
            wrapped("my-project")
        except ConfirmationRequired as exc:
            challenge = exc
        print(f"guard> BLOCKED: {challenge.summary}")
        print(f"guard> type the phrase (format {challenge.phrase_format!r}) to proceed")

        # --- 2. The human channel. The phrase is *not* in the exception the
        # agent sees — the host reads it from the guard's state and shows it
        # to the human directly. Here we simulate the user typing it back.
        phrase = guard.challenge_phrase(challenge.challenge_id)
        assert phrase is not None
        print(f"host > (shows the user the phrase: {phrase!r})")

        wrong = "DELETE XX"  # letters can never collide with the 2-digit nonce
        print(f"user > types a wrong phrase first: {wrong!r}")
        print(f"guard> confirm -> {guard.confirm(challenge.challenge_id, wrong)}")
        print(f"user > types the real phrase {phrase!r}")
        print(f"guard> confirm -> {guard.confirm(challenge.challenge_id, phrase)}")

        # --- 3. Agent retries with the confirmed challenge id.
        result = wrapped("my-project", fluffy_challenge_id=challenge.challenge_id)
        print(f"agent> retried with fluffy_challenge_id -> {result!r}")

        # --- 4. Reuse is blocked: challenges are single-use.
        try:
            wrapped("my-project", fluffy_challenge_id=challenge.challenge_id)
        except ConfirmationRequired as exc2:
            print(f"guard> reuse blocked, fresh challenge {exc2.challenge_id[:8]}... issued")
            # This time the user confirms with remember=True.
            phrase2 = guard.challenge_phrase(exc2.challenge_id)
            assert phrase2 is not None
            guard.confirm(exc2.challenge_id, phrase2, remember=True)
            wrapped("my-project", fluffy_challenge_id=exc2.challenge_id)

        # --- 5. Whitelisted now: same (tool, resource_kind) passes gate-free.
        print(
            f"agent> delete_project('my-project') again -> {wrapped('my-project')!r}"
            " (whitelisted, no challenge)"
        )

        print("\naudit tail:")
        for row in guard.audit_tail(15):
            print(f"   {row['ts']}  {row['tool']:<15} {row['event']:<18} {row['decision']}")


if __name__ == "__main__":
    main()
