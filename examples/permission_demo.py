"""fluffy permission broker demo: raising a spend cap mid-conversation.

A stripe.charge tool sits under the default $25 cap. The agent tries a $40
charge (blocked), files a ``budget_increase`` permission request for the
missing $15, the console approver approves it, and the *same* $40 charge
succeeds in-process — no restart, no config edit. A second $40 charge is
blocked again because the ``once`` grant was consumed.

The console approver is scripted (``input_fn``) so the demo runs
non-interactively; drop the ``input_fn`` argument to approve by typing
``approve`` at a real terminal.

Run:  uv run python examples/permission_demo.py
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from fluffy import (
    ConsoleApprover,
    Guard,
    PermissionRequest,
    SpendLimitExceeded,
    SpendPolicy,
    SpendSpec,
    ToolMeta,
)


def charge_stub(*, amount_cents: int, currency: str = "usd") -> dict[str, Any]:
    return {"id": "ch_stub_demo", "amount": amount_cents, "currency": currency}


def main() -> None:
    # Scripted console: answers "approve" once. At a real TTY, use
    # approvers=[ConsoleApprover()] (the default) and type the answer.
    scripted_console = ConsoleApprover(input_fn=iter(["approve"]).__next__)

    with (
        tempfile.TemporaryDirectory() as tmp,
        Guard(db_path=Path(tmp) / "state.db", approvers=[scripted_console]) as guard,
    ):
        guard.add_spend_policy(SpendPolicy(card_id="demo"))  # $25 per-use / daily
        charge = guard.wrap(
            charge_stub,
            meta=ToolMeta(
                name="stripe.charge",
                tags=frozenset({"spend"}),
                spend=SpendSpec(
                    card_id="demo",
                    amount_from=lambda args, kwargs: kwargs["amount_cents"],
                ),
            ),
        )

        print("-> charging $40.00 under a $25.00 cap ...")
        try:
            charge(amount_cents=4000)
        except SpendLimitExceeded as exc:
            print(f"   BLOCKED: {exc}")

        print("\n-> agent files a budget_increase request for the missing $15.00 ...")
        decision = guard.request_permission_sync(
            PermissionRequest(
                kind="budget_increase",
                subject="demo",
                value=1500,  # increase delta in cents, on top of the base caps
                duration="once",
                rationale="the $40.00 vendor invoice exceeds the $25.00 daily cap",
            )
        )
        print(f"   decision: approved={decision.approved} by {decision.decider!r}")
        print(f"   message:  {decision.message}")

        print("\n-> retrying the same $40.00 charge ...")
        result = charge(amount_cents=4000)
        print(f"   ok: {result}")

        print("\n-> a second $40.00 charge (the once-grant is spent) ...")
        try:
            charge(amount_cents=4000)
        except SpendLimitExceeded as exc:
            print(f"   BLOCKED: {exc}")

        print("\naudit tail:")
        for row in guard.audit_tail(12):
            print(f"   {row['ts']}  {row['tool']:<19} {row['event']:<19} {row['decision']}")


if __name__ == "__main__":
    main()
