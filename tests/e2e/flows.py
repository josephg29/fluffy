"""Spec §3 acceptance flows, run against an *installed* fluffy in a clean venv.

Executed by tests/e2e/test_spec_acceptance.py via the venv's python — no
pytest, no repo imports; only the wheel under test and the stdlib. Each flow
prints ``PASS <flow>`` on success; any assertion failure exits non-zero.

Usage: python flows.py <workdir>
"""

from __future__ import annotations

import io
import logging
import sys
from collections.abc import Callable
from pathlib import Path

import fluffy
from fluffy import (
    ConfirmationRequired,
    DestructiveSpec,
    Guard,
    PermissionRequest,
    SpendLimitExceeded,
    SpendPolicy,
    SpendSpec,
    ToolMeta,
)

WORKDIR = Path(sys.argv[1])

# Built at runtime so secret scanners don't flag a key-shaped literal.
SECRET_VALUE = "sk_live_" + "e2eSuperSecretValue1234567890"


def make_charge(guard: Guard) -> Callable[..., str]:
    """The spec's canonical spend tool: a guarded ``stripe.charge`` in cents."""
    return guard.wrap(
        lambda *, amount_cents: f"charged {amount_cents}",
        meta=ToolMeta(
            name="stripe.charge",
            tags={"spend"},
            spend=SpendSpec(card_id="ops", amount_from=lambda a, k: k["amount_cents"]),
        ),
    )


def flow_1_secret_grep() -> None:
    """Secrets never appear in results, logs, or the state database bytes."""
    db = WORKDIR / "flow1.db"
    seen: list[str] = []

    def call_api(key: str) -> str:
        seen.append(key)
        return f"authenticated with {key}"

    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    logging.getLogger().addHandler(handler)
    with Guard(db_path=db) as guard:
        guard.secret_store.put("stripe_key", SECRET_VALUE)
        safe = guard.wrap(call_api, meta=ToolMeta(name="api.call"))  # untagged fast path
        result = safe("{{secret:stripe_key}}")
        assert seen == [SECRET_VALUE], "tool must receive the real value"
        assert SECRET_VALUE not in result, "result must be masked"
        assert "{{secret:stripe_key}}" in result, "result must carry the handle"
        logging.getLogger("e2e").error("key leaked into a log line: %s", SECRET_VALUE)
    logging.getLogger().removeHandler(handler)
    logged = stream.getvalue()
    assert SECRET_VALUE not in logged, "log output must be redacted"
    assert "{{secret:stripe_key}}" in logged

    # The spec's literal acceptance: grep the state DB (and WAL) for the value.
    for path in WORKDIR.glob("flow1.db*"):
        assert SECRET_VALUE.encode() not in path.read_bytes(), f"secret bytes in {path.name}"
    print("PASS secret_grep")


def flow_2_spend_block() -> None:
    """$50 request against the default $25 cap is blocked with a clear message."""
    db = WORKDIR / "flow2.db"
    with Guard(db_path=db) as guard:
        guard.add_spend_policy(SpendPolicy(card_id="ops"))  # spec default: $25/$25
        charge = make_charge(guard)
        try:
            charge(amount_cents=5000)
        except SpendLimitExceeded as exc:
            msg = str(exc)
            assert "$50.00 requested" in msg and "cap $25.00" in msg, msg
        else:
            raise AssertionError("a $50 spend must not pass a $25 cap")
        assert charge(amount_cents=1000) == "charged 1000"  # $10 still fits
    print("PASS spend_block")


def flow_3_delete_confirmation() -> None:
    """Destructive call -> challenge -> phrase via Guard.challenge_phrase -> retry."""
    db = WORKDIR / "flow3.db"
    ran: list[str] = []

    def delete_project(name: str) -> str:
        ran.append(name)
        return f"deleted {name}"

    with Guard(db_path=db) as guard:
        safe_delete = guard.wrap(
            delete_project,
            meta=ToolMeta(
                name="delete_project",
                tags={"destructive"},
                destructive=DestructiveSpec(
                    resource_kind="project",
                    summary_from=lambda a, k: (
                        f"This deletes the project {a[0]!r}. This cannot be undone."
                    ),
                ),
            ),
        )
        try:
            safe_delete("my-project")
        except ConfirmationRequired as exc:
            challenge = exc
        else:
            raise AssertionError("first destructive call must raise ConfirmationRequired")
        assert ran == [], "tool must not run before confirmation"
        assert "my-project" in challenge.summary
        assert challenge.phrase_format == "DELETE <nn>"
        # The phrase is deliberately NOT in the exception payload — the host
        # reads it over the human channel:
        phrase = guard.challenge_phrase(challenge.challenge_id)
        assert phrase is not None and phrase.startswith("DELETE ")
        wrong = "DELETE 00" if phrase != "DELETE 00" else "DELETE 01"
        assert guard.confirm(challenge.challenge_id, wrong) is False  # wrong phrase rejected
        assert guard.confirm(challenge.challenge_id, phrase) is True
        assert safe_delete("my-project", fluffy_challenge_id=challenge.challenge_id) == (
            "deleted my-project"
        )
        assert ran == ["my-project"], "tool must run exactly once"
    print("PASS delete_confirmation")


def flow_4_permission_approve() -> None:
    """Blocked $40 spend -> budget_increase approved -> same spend succeeds once."""
    db = WORKDIR / "flow4.db"

    class ApproveAll:
        async def decide(self, req: PermissionRequest) -> fluffy.Decision:
            return fluffy.Decision(approved=True, decider="e2e-script", message="Approved.")

    with Guard(db_path=db, approvers=[ApproveAll()]) as guard:
        guard.add_spend_policy(SpendPolicy(card_id="ops"))
        charge = make_charge(guard)
        try:
            charge(amount_cents=4000)
            raise AssertionError("$40 must be blocked at the $25 cap")
        except SpendLimitExceeded:
            pass
        decision = guard.request_permission_sync(
            PermissionRequest(
                kind="budget_increase",
                subject="ops",
                value=1500,
                duration="once",
                rationale="the gadget costs $40",
            )
        )
        assert decision.approved and decision.decider == "e2e-script"
        assert charge(amount_cents=4000) == "charged 4000"  # effect is immediate
        try:
            charge(amount_cents=4000)
            raise AssertionError("second $40 spend must fail: the once-grant is consumed")
        except SpendLimitExceeded:
            pass
    print("PASS permission_approve")


if __name__ == "__main__":
    flow_1_secret_grep()
    flow_2_spend_block()
    flow_3_delete_confirmation()
    flow_4_permission_approve()
    print("ALL FLOWS PASSED")
