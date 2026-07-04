"""D8 performance-budget gate (FLUF-5).

Budgets, CI-enforced:

- untagged wrapped call overhead      < 1 ms   (mean, vs the bare call)
- tagged spend call                   < 20 ms  p95
- 100-step mixed job (60 untagged / 30 spend / 10 confirm-whitelisted)
                                      < 0.5 s  total added wall time

``FLUFFY_BENCH_MARGIN`` multiplies the per-call budgets. It defaults to ``2``
on CI runners (the ``CI`` env var is set) for headroom against noisy
neighbours and ``1`` locally; setting it explicitly overrides either default.
The 0.5 s spec number for the 100-step job is an absolute ceiling and is
never widened.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, cast

import pytest
from pytest_benchmark.fixture import BenchmarkFixture

from conftest import destructive_meta, seed_whitelist, spend_meta
from fluffy import Guard, SpendPolicy, ToolMeta

pytestmark = pytest.mark.bench

MARGIN = float(os.environ.get("FLUFFY_BENCH_MARGIN") or ("2" if os.environ.get("CI") else "1"))

UNTAGGED_BUDGET_S = 0.001 * MARGIN
TAGGED_P95_BUDGET_S = 0.020 * MARGIN
MIXED_JOB_BUDGET_S = 0.5  # hard spec ceiling — no margin, ever

#: Effectively-unlimited caps so thousands of bench iterations never trip them.
HUGE_CAP = 10**15


def _echo(x: int) -> int:
    return x


def _bare_call_cost(fn: Callable[[int], int], iterations: int = 2000) -> float:
    """Best-of-5 mean cost of one bare call, in seconds."""
    best = float("inf")
    for _ in range(5):
        start = time.perf_counter()
        for _ in range(iterations):
            fn(1)
        best = min(best, (time.perf_counter() - start) / iterations)
    return best


@pytest.fixture()
def bench_guard(tmp_path: Path) -> Iterator[Guard]:
    with Guard(db_path=tmp_path / "bench.db") as g:
        g.add_spend_policy(
            SpendPolicy(card_id="bench", per_use_cap_cents=HUGE_CAP, daily_cap_cents=HUGE_CAP)
        )
        yield g


def _spend_meta() -> ToolMeta:
    return spend_meta(card_id="bench", name="bench.charge", amount_from=lambda args, kwargs: 1)


def _whitelisted_cleanup(guard: Guard) -> Callable[..., int]:
    """A destructive-tagged tool pre-whitelisted so the gate passes silently."""
    meta = destructive_meta(name="bench.remove_temp", resource_kind="temp_files")
    seed_whitelist(guard.connection, "bench.remove_temp", "temp_files")
    return cast(Callable[..., int], guard.wrap(_echo, meta=meta))


def test_untagged_overhead_under_1ms(benchmark: BenchmarkFixture, bench_guard: Guard) -> None:
    """An untagged wrapped call adds < 1 ms over the bare call (D8 fast path)."""
    wrapped = cast(Callable[[int], int], bench_guard.wrap(_echo, meta=ToolMeta(name="bench.echo")))
    bare = _bare_call_cost(_echo)
    benchmark(wrapped, 1)
    overhead = benchmark.stats.stats.mean - bare
    assert overhead < UNTAGGED_BUDGET_S, (
        f"untagged overhead {overhead * 1000:.3f} ms >= budget {UNTAGGED_BUDGET_S * 1000:.1f} ms"
    )


def test_tagged_spend_p95_under_20ms(benchmark: BenchmarkFixture, bench_guard: Guard) -> None:
    """A spend-tagged call (reserve + settle, two commits) stays < 20 ms p95."""
    wrapped = cast(Callable[[int], int], bench_guard.wrap(_echo, meta=_spend_meta()))
    benchmark.pedantic(wrapped, args=(1,), rounds=200, iterations=1, warmup_rounds=10)
    data = sorted(benchmark.stats.stats.data)
    p95 = data[min(int(len(data) * 0.95), len(data) - 1)]
    assert p95 < TAGGED_P95_BUDGET_S, (
        f"tagged spend p95 {p95 * 1000:.2f} ms >= budget {TAGGED_P95_BUDGET_S * 1000:.1f} ms"
    )


def test_100_step_mixed_job_under_half_second(
    benchmark: BenchmarkFixture, bench_guard: Guard
) -> None:
    """60 untagged + 30 spend + 10 confirm-whitelisted steps add < 0.5 s total."""
    untagged = cast(Callable[[int], int], bench_guard.wrap(_echo, meta=ToolMeta(name="bench.echo")))
    spend = cast(Callable[[int], int], bench_guard.wrap(_echo, meta=_spend_meta()))
    cleanup = _whitelisted_cleanup(bench_guard)

    # 60/30/10 interleaved the way a real job would mix them.
    steps: list[Callable[..., Any]] = []
    for i in range(100):
        if i % 10 == 9:
            steps.append(cleanup)
        elif i % 10 in (3, 6, 8):
            steps.append(spend)
        else:
            steps.append(untagged)
    assert steps.count(spend) == 30

    bare_total = _bare_call_cost(_echo) * 100

    def job() -> None:
        for step in steps:
            step(1)

    benchmark.pedantic(job, rounds=10, iterations=1, warmup_rounds=2)
    added = benchmark.stats.stats.mean - bare_total
    assert added < MIXED_JOB_BUDGET_S, (
        f"100-step mixed job added {added:.3f} s >= hard ceiling {MIXED_JOB_BUDGET_S} s"
    )
