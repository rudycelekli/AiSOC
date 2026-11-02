"""A response that asks for tool calls is not replayed from the response cache.

The cache stores text and replays it as a bare ``AIMessage``. A model reply
carrying both text and ``tool_calls`` used to be cached, so an identical second
investigation got the preamble back with no tool calls: the tool loop ran no
tool and returned "I'll extract the indicators first." as its answer.
"""

from __future__ import annotations

from typing import Any

import pytest
from app.llm.tool_loop import run_with_tools
from app.security.agent_identity import issue_identity
from app.tools.registry import default_registry
from langchain_core.messages import AIMessage


class _ToolCallingModel:
    """Shaped like a bound chat model: it has a ``model`` name, as ChatOpenAI does."""

    model = "gpt-4o-mini"

    def __init__(self) -> None:
        self.calls = 0

    def bind_tools(self, _tools: Any) -> _ToolCallingModel:
        return self

    async def ainvoke(self, messages: list[Any], **_: Any) -> AIMessage:
        self.calls += 1
        if not any(getattr(m, "type", "") == "tool" for m in messages):
            return AIMessage(
                content="I'll extract the indicators first.",
                tool_calls=[{"name": "extract_iocs", "args": {"text": "beacon to 45.9.148.99"}, "id": f"call-{self.calls}"}],
            )
        return AIMessage(content="45.9.148.99 is the beacon destination.")


async def _investigate(run_id: str) -> tuple[dict[str, Any], _ToolCallingModel]:
    model = _ToolCallingModel()
    out = await run_with_tools(
        model,
        system="You are a SOC analyst.",
        user="Investigate alert A-1: beacon to 45.9.148.99",
        registry=default_registry(),
        identity=issue_identity("investigation", run_id=run_id),
    )
    return out, model


@pytest.mark.asyncio
async def test_identical_second_investigation_still_runs_its_tools() -> None:
    first, _ = await _investigate("run-1")
    second, _ = await _investigate("run-2")

    assert [t["tool"] for t in first["tool_trace"]] == ["extract_iocs"]
    assert [t["tool"] for t in second["tool_trace"]] == ["extract_iocs"]
    assert second["content"] == "45.9.148.99 is the beacon destination."
