"""Slack audit log polling follows the API's cursor pagination."""

from __future__ import annotations

import httpx
import pytest
from app.connectors import slack_audit
from app.connectors.slack_audit import SlackAuditConnector


def _entry(i: int) -> dict:
    return {
        "id": f"entry-{i}",
        "date_create": 4070908800,
        "action": "user_login",
        "actor": {"type": "user", "user": {"id": f"U{i}", "email": f"user{i}@example.com"}},
        "entity": {"type": "user", "user": {"id": f"U{i}"}},
        "context": {"ip_address": "203.0.113.5"},
    }


def _patch_client(monkeypatch: pytest.MonkeyPatch, handler) -> None:  # noqa: ANN001
    real_client = httpx.AsyncClient

    def factory(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(slack_audit.httpx, "AsyncClient", factory)


@pytest.mark.asyncio
async def test_fetch_alerts_follows_next_cursor(monkeypatch: pytest.MonkeyPatch) -> None:
    pages = {
        None: ([_entry(i) for i in range(200)], "dXNlcjpVMDYxTkZUVDI="),
        "dXNlcjpVMDYxTkZUVDI=": ([_entry(i) for i in range(200, 400)], "dXNlcjpVMEc5V0ZYTlo="),
        "dXNlcjpVMEc5V0ZYTlo=": ([_entry(i) for i in range(400, 470)], ""),
    }
    seen_cursors: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        cursor = request.url.params.get("cursor")
        seen_cursors.append(cursor)
        entries, next_cursor = pages[cursor]
        return httpx.Response(200, json={"entries": entries, "response_metadata": {"next_cursor": next_cursor}})

    _patch_client(monkeypatch, handler)
    out = await SlackAuditConnector(access_token="xoxp-test").fetch_alerts()  # noqa: S106 — test

    assert seen_cursors == [None, "dXNlcjpVMDYxTkZUVDI=", "dXNlcjpVMEc5V0ZYTlo="]
    assert len(out) == 470
