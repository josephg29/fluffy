"""LangChain adapter integration tests (D9).

Skipped gracefully when langchain isn't installed (`pip install fluffy-guard[langchain]`
plus the `langchain` package for the agent test). The headline test drives a
FakeListLLM ReAct agent into a $50 spend against a $25 cap and asserts the
block surfaces as a normal tool observation the agent loop can relay.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("langchain_core", reason="langchain extra not installed")

from langchain_core.language_models.fake import FakeListLLM
from langchain_core.tools import StructuredTool, Tool, ToolException

from conftest import ledger_rows, spend_meta
from fluffy import Guard, SpendPolicy, ToolMeta
from fluffy.adapters.langchain import guard_tools


def _buy_gadget(amount: str) -> str:
    return f"bought a gadget for {int(str(amount).strip())} cents"


def _spend_meta() -> ToolMeta:
    return spend_meta(name="buy_gadget", amount_from=lambda args, kwargs: int(str(args[0]).strip()))


@pytest.fixture()
def guard(tmp_path: Path) -> Any:
    with Guard(db_path=tmp_path / "state.db") as g:
        # Per-use above daily so a $50 ask is blocked by the daily cap — the
        # spec's canonical message shape.
        g.add_spend_policy(
            SpendPolicy(card_id="ops", per_use_cap_cents=10_000, daily_cap_cents=2500)
        )
        yield g


def _make_tool() -> Tool:
    return Tool(
        name="buy_gadget",
        func=_buy_gadget,
        description="Buy a gadget. Input: the price in integer cents.",
    )


def test_blocked_spend_becomes_tool_exception(guard: Guard) -> None:
    (tool,) = guard_tools([_make_tool()], guard, metas={"buy_gadget": _spend_meta()})
    with pytest.raises(ToolException) as excinfo:
        tool.run("5000")
    msg = str(excinfo.value)
    assert "Blocked: $50.00 requested" in msg
    assert "daily cap $25.00" in msg


def test_allowed_spend_runs_normally(guard: Guard) -> None:
    (tool,) = guard_tools([_make_tool()], guard, metas={"buy_gadget": _spend_meta()})
    assert tool.run("1000") == "bought a gadget for 1000 cents"
    rows = ledger_rows(guard.connection)
    assert rows and rows[-1]["state"] == "settled"


def test_unlisted_tool_wrapped_untagged_with_secret_resolution(guard: Guard) -> None:
    guard.secret_store.put("api_key", "sk-abc123def456ghi789jkl")
    seen: list[str] = []

    def probe(text: str) -> str:
        seen.append(text)
        return "ok " + text

    (tool,) = guard_tools([Tool(name="probe", func=probe, description="probe")], guard)
    result = tool.run("{{secret:api_key}}")
    assert seen == ["sk-abc123def456ghi789jkl"]  # tool saw the real value
    assert result == "ok {{secret:api_key}}"  # caller only ever sees the handle


async def test_async_structured_tool_guarded(guard: Guard) -> None:
    async def buy(amount: int) -> str:
        return f"bought for {amount}"

    tool = StructuredTool.from_function(
        coroutine=buy, name="buy_gadget", description="Buy. Input: cents."
    )
    meta = spend_meta(name="buy_gadget", amount_from=lambda args, kwargs: kwargs["amount"])
    guard_tools([tool], guard, metas={"buy_gadget": meta})
    assert await tool.arun({"amount": 1000}) == "bought for 1000"
    with pytest.raises(ToolException, match=r"Blocked: \$50\.00 requested"):
        await tool.arun({"amount": 5000})


def test_fake_llm_agent_relays_spend_block(guard: Guard) -> None:
    """A FakeListLLM-driven ReAct agent hits the $25 cap and relays the block."""
    langchain = pytest.importorskip("langchain", reason="agent test needs langchain")
    del langchain
    from langchain.agents import AgentExecutor, create_react_agent
    from langchain_core.prompts import PromptTemplate

    tool = _make_tool()
    tool.handle_tool_error = True  # ToolException -> observation, not a crash
    tools = guard_tools([tool], guard, metas={"buy_gadget": _spend_meta()})

    llm = FakeListLLM(
        responses=[
            "Thought: I should buy the gadget.\nAction: buy_gadget\nAction Input: 5000",
            (
                "Thought: The spend guard blocked the purchase; I must tell the user.\n"
                "Final Answer: I could not buy the gadget — the spend guard blocked it: "
                "the $50.00 purchase exceeds the $25.00 daily cap."
            ),
        ]
    )
    prompt = PromptTemplate.from_template(
        "Answer the following questions as best you can. You have access to the "
        "following tools:\n\n{tools}\n\nUse the following format:\n\n"
        "Question: the input question you must answer\n"
        "Thought: you should always think about what to do\n"
        "Action: the action to take, should be one of [{tool_names}]\n"
        "Action Input: the input to the action\n"
        "Observation: the result of the action\n"
        "... (this Thought/Action/Action Input/Observation can repeat N times)\n"
        "Thought: I now know the final answer\n"
        "Final Answer: the final answer to the original input question\n\n"
        "Begin!\n\nQuestion: {input}\nThought:{agent_scratchpad}"
    )
    executor = AgentExecutor(
        agent=create_react_agent(llm, tools, prompt),
        tools=tools,
        return_intermediate_steps=True,
        max_iterations=3,
    )

    out = executor.invoke({"input": "Buy me the $50 gadget."})

    # The block surfaced into the agent loop as a normal tool observation,
    # carrying the pre-formatted plain-English message verbatim...
    (action, observation), *_ = out["intermediate_steps"]
    assert action.tool == "buy_gadget"
    assert "Blocked: $50.00 requested" in observation
    assert "daily cap $25.00" in observation
    # ...and the agent completed its turn by relaying the block to the user.
    assert "blocked" in out["output"].lower()
    assert "$50.00" in out["output"] and "$25.00" in out["output"]

    # No ledger residue: the denied spend reserved nothing.
    assert ledger_rows(guard.connection) == []
