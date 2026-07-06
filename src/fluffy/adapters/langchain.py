"""LangChain adapter (decision D9). Requires ``pip install fluffy-guard[langchain]``.

``guard_tools(tools, guard, metas=...)`` wraps each tool's ``_run``/``_arun``
in the guard pipeline. :class:`fluffy.Blocked` denials are converted to
``langchain_core.tools.ToolException`` carrying the pre-formatted plain-English
message, so the agent loop sees a normal tool error it can relay and react to
(set ``handle_tool_error=True`` on the tool — or let the ``ToolException``
propagate — per standard LangChain error handling).

Tools without an entry in ``metas`` are wrapped untagged: they take the D8
fast path (secret handle resolution in, redaction out, no I/O). The D6
wrap-time safety net still applies — a destructive-looking tool name with no
``DestructiveSpec`` raises ``GuardConfigError`` here, at wiring time.
"""

from __future__ import annotations

import functools
from collections.abc import Awaitable, Callable, Mapping, Sequence
from typing import Any, cast

from langchain_core.tools import BaseTool, StructuredTool, Tool, ToolException

from ..context import ToolMeta
from ..exceptions import Blocked
from ..guard import Guard

__all__ = ["guard_tools"]


def guard_tools(
    tools: Sequence[BaseTool],
    guard: Guard,
    metas: Mapping[str, ToolMeta] | None = None,
) -> list[BaseTool]:
    """Wrap every tool's ``_run``/``_arun`` in ``guard``'s pipeline, in place.

    ``metas`` maps tool names to :class:`fluffy.ToolMeta` (tags, spend spec,
    destructive spec). Unlisted tools are wrapped untagged. Returns the same
    tool objects for drop-in use::

        tools = guard_tools(tools, guard, metas={"buy_gadget": ToolMeta(...)})
        agent = AgentExecutor(agent=..., tools=tools)
    """
    metas = metas or {}
    for tool in tools:
        meta = metas.get(tool.name, ToolMeta(name=tool.name))
        _guard_one(tool, guard, meta)
    return list(tools)


def _guard_one(tool: BaseTool, guard: Guard, meta: ToolMeta) -> None:
    wrapped_run = cast(Callable[..., Any], guard.wrap(tool._run, meta=meta))

    # functools.wraps makes the shim report the original _run's signature, so
    # LangChain's signature inspection passes exactly the ``config``/
    # ``run_manager`` keywords the original expects — no more, no fewer.
    @functools.wraps(tool._run)
    def _run_shim(*args: Any, **kwargs: Any) -> Any:
        try:
            return wrapped_run(*args, **kwargs)
        except Blocked as exc:
            raise ToolException(str(exc)) from exc

    # Instance attribute shadows the class method; object.__setattr__ bypasses
    # pydantic's field validation on BaseTool.
    object.__setattr__(tool, "_run", _run_shim)

    # Only wrap _arun when it is a real async implementation. The BaseTool
    # default — and Tool/StructuredTool with no ``coroutine`` — delegate the
    # async path to ``self._run`` (already the guarded shim above); wrapping
    # both would run the pipeline twice per call (double spend-reserve).
    delegates_to_run = isinstance(tool, (Tool, StructuredTool)) and tool.coroutine is None
    if type(tool)._arun is not BaseTool._arun and not delegates_to_run:
        wrapped_arun = cast(Callable[..., Awaitable[Any]], guard.wrap(tool._arun, meta=meta))

        @functools.wraps(tool._arun)
        async def _arun_shim(*args: Any, **kwargs: Any) -> Any:
            try:
                return await wrapped_arun(*args, **kwargs)
            except Blocked as exc:
                raise ToolException(str(exc)) from exc

        object.__setattr__(tool, "_arun", _arun_shim)
