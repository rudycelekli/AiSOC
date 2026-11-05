"""Duo authentication-log polling follows ``metadata.next_offset``."""

from __future__ import annotations

import base64
import hashlib
import hmac
import urllib.parse

import httpx
import pytest
from app.connectors import duo_security
from app.connectors.duo_security import DuoSecurityConnector

_IKEY, _SKEY, _HOST = "DIXXXXXXXXXXXXXXXXXX", "secret", "api-x.duosecurity.com"


def _entry(i: int) -> dict:
    return {"txid": f"tx-{i}", "timestamp": 1_700_000_000 + i, "result": "success", "user": {"name": f"user{i}"}}


def _signature_is_valid(request: httpx.Request) -> bool:
    # Duo signs the request parameters, so every page has to be signed for the
    # parameters it is actually sent with, next_offset included.
    params = sorted(urllib.parse.parse_qsl(request.url.query.decode()))
    canon = "\n".join([request.headers["Date"], "GET", _HOST, request.url.path, urllib.parse.urlencode(params)])
    sig = hmac.new(_SKEY.encode(), canon.encode(), hashlib.sha1).hexdigest()
    return request.headers["Authorization"] == "Basic " + base64.b64encode(f"{_IKEY}:{sig}".encode()).decode()


@pytest.mark.asyncio
async def test_fetch_alerts_follows_next_offset(monkeypatch: pytest.MonkeyPatch) -> None:
    entries = [_entry(i) for i in range(2300)]
    offsets_seen: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert _signature_is_valid(request)
        offset = request.url.params.get("next_offset")
        offsets_seen.append(offset)
        limit = int(request.url.params.get("limit", "100"))
        start = 0 if offset is None else int(offset.split(",")[1].removeprefix("tx-")) + 1
        page = entries[start : start + limit]
        metadata: dict = {"total_objects": len(entries)}
        if start + limit < len(entries):
            last = page[-1]
            metadata["next_offset"] = [str(last["timestamp"] * 1000), last["txid"]]
        return httpx.Response(200, json={"stat": "OK", "response": {"authlogs": page, "metadata": metadata}})

    real_client = httpx.AsyncClient

    def factory(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(duo_security.httpx, "AsyncClient", factory)

    out = await DuoSecurityConnector(integration_key=_IKEY, secret_key=_SKEY, api_hostname=_HOST).fetch_alerts()

    assert [e["external_id"] for e in out] == [e["txid"] for e in entries]
    assert offsets_seen[0] is None
    assert offsets_seen[1] == f"{entries[999]['timestamp'] * 1000},tx-999"
