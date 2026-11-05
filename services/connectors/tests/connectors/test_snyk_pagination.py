"""Snyk issue polling follows the REST API's links.next cursor."""

from __future__ import annotations

import httpx
import pytest
from app.connectors import snyk
from app.connectors.snyk import SnykConnector


def _issue(i: int) -> dict:
    return {"id": f"issue-{i}", "type": "issue", "attributes": {"title": f"Issue {i}", "effective_severity_level": "high"}}


@pytest.mark.asyncio
async def test_fetch_alerts_follows_links_next(monkeypatch: pytest.MonkeyPatch) -> None:
    issues = [_issue(i) for i in range(230)]
    cursors_seen: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        cursor = request.url.params.get("starting_after")
        cursors_seen.append(cursor)
        start = 0 if cursor is None else int(cursor) + 1
        limit = int(request.url.params["limit"])
        page = issues[start : start + limit]
        body: dict = {"data": page, "links": {"self": request.url.raw_path.decode()}}
        if start + limit < len(issues):
            # Snyk's next link repeats the query and adds an opaque cursor.
            body["links"]["next"] = request.url.copy_merge_params({"starting_after": str(start + limit - 1)}).raw_path.decode()
        return httpx.Response(200, json=body)

    real_client = httpx.AsyncClient

    def factory(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(snyk.httpx, "AsyncClient", factory)

    out = await SnykConnector(api_token="tok", org_id="org-1").fetch_alerts()  # noqa: S106 — test

    assert cursors_seen == [None, "99", "199"]
    assert [a["external_id"] for a in out] == [i["id"] for i in issues]
