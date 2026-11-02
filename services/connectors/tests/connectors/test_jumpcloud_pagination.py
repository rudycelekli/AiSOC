"""JumpCloud Directory Insights polling follows the X-Search_after cursor."""

from __future__ import annotations

import json

import httpx
import pytest
from app.connectors import jumpcloud
from app.connectors.jumpcloud import JumpCloudConnector


def _event(i: int) -> dict:
    return {"id": f"e{i}", "event_type": "user_login_attempt", "success": True, "timestamp": "2099-01-01T00:00:00Z"}


def _patch_client(monkeypatch: pytest.MonkeyPatch, handler) -> None:  # noqa: ANN001
    real_client = httpx.AsyncClient

    def factory(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(jumpcloud.httpx, "AsyncClient", factory)


@pytest.mark.asyncio
async def test_fetch_alerts_follows_search_after(monkeypatch: pytest.MonkeyPatch) -> None:
    pages = [
        ([_event(i) for i in range(200)], [4070908800000, "e199"]),
        ([_event(i) for i in range(200, 400)], [4070908700000, "e399"]),
        ([_event(i) for i in range(400, 450)], [4070908600000, "e449"]),
    ]
    seen_search_after: list[object] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent = json.loads(request.content)
        seen_search_after.append(sent.get("search_after"))
        data, token = pages[len(seen_search_after) - 1]
        return httpx.Response(200, json=data, headers={"X-Search_after": json.dumps(token), "X-Limit": "200"})

    _patch_client(monkeypatch, handler)
    out = await JumpCloudConnector(api_key="k").fetch_alerts()

    assert seen_search_after == [None, [4070908800000, "e199"], [4070908700000, "e399"]]
    assert len(out) == 450
