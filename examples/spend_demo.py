"""fluffy spend guard demo: a stripe.charge tool under a $25 cap.

Runs a $10 charge (succeeds, settled in the ledger) then a $50 charge
(blocked by the guard before the tool ever runs), and prints the audit tail.

If ``STRIPE_API_KEY`` is set (it must be a ``sk_test_`` key — the demo refuses
live keys), charges go to Stripe in test mode via the raw HTTPS API (stdlib
only, no SDK). Otherwise a local stub stands in for Stripe.

Run:  uv run python examples/spend_demo.py
"""

from __future__ import annotations

import json
import os
import tempfile
import urllib.parse
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

from fluffy import Guard, SpendLimitExceeded, SpendPolicy, SpendSpec, ToolMeta


def make_stripe_charge() -> Callable[..., dict[str, Any]]:
    """Real Stripe test-mode charge if STRIPE_API_KEY is set, else a stub."""
    api_key = os.environ.get("STRIPE_API_KEY")
    if api_key:
        if not api_key.startswith("sk_test_"):
            raise SystemExit("refusing to run the demo with a non-test Stripe key")

        def charge(*, amount_cents: int, currency: str = "usd") -> dict[str, Any]:
            data = urllib.parse.urlencode(
                {
                    "amount": amount_cents,
                    "currency": currency,
                    "source": "tok_visa",
                    "description": "fluffy spend demo",
                }
            ).encode()
            request = urllib.request.Request("https://api.stripe.com/v1/charges", data=data)
            request.add_header("Authorization", f"Bearer {api_key}")
            with urllib.request.urlopen(request) as response:
                result: dict[str, Any] = json.load(response)
            return result

        return charge

    def charge_stub(*, amount_cents: int, currency: str = "usd") -> dict[str, Any]:
        return {
            "id": "ch_stub_demo",
            "amount": amount_cents,
            "currency": currency,
            "status": "succeeded",
        }

    return charge_stub


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp, Guard(db_path=Path(tmp) / "state.db") as guard:
        guard.add_spend_policy(SpendPolicy(card_id="demo"))  # $25 per-use / daily defaults
        charge = guard.wrap(
            make_stripe_charge(),
            meta=ToolMeta(
                name="stripe.charge",
                tags=frozenset({"spend"}),
                spend=SpendSpec(
                    card_id="demo",
                    amount_from=lambda args, kwargs: kwargs["amount_cents"],
                ),
            ),
        )

        print("-> charging $10.00 ...")
        result = charge(amount_cents=1000)
        print(f"   ok: {result}")

        print("-> charging $50.00 ...")
        try:
            charge(amount_cents=5000)
        except SpendLimitExceeded as exc:
            print(f"   BLOCKED: {exc}")
            print(f"   payload: {exc.payload}")

        print("\naudit tail:")
        for row in guard.audit_tail(10):
            print(f"   {row['ts']}  {row['tool']:<14} {row['event']:<15} {row['decision']}")


if __name__ == "__main__":
    main()
