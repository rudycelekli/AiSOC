"""``GET /api/v1/alerts?search=`` must narrow the list, or not be accepted.

The defect
----------
``list_alerts`` has declared ``search`` since the first release and never
read it, so ``?search=mimikatz`` answered 200 with every alert in the tenant.
That is worse than a 422: the caller cannot tell the filter was dropped.
The MCP server's ``aisoc_list_alerts`` tool forwards ``search`` and
describes it to the model as "Substring match on title/description", so an
agent asking for one kind of alert was handed all of them as the result.

Runs through the shipped app against real PostgreSQL, like the sibling
``test_alert_list_limit_is_not_silently_ignored.py``, because what is under
test is the query the route builds from the query string.
"""

from __future__ import annotations

import os
import socket
import uuid
from urllib.parse import urlparse

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

_DSN = os.environ.get("DATABASE_MIGRATION_URL", "").strip() or os.environ.get("DATABASE_URL", "")
_REQUIRED = os.environ.get("ALERT_AUDIT_PROOF_REQUIRED", "").strip() not in ("", "0", "false")


def _postgres_is_listening() -> bool:
    parsed = urlparse(_DSN.replace("postgresql+asyncpg://", "postgresql://"))
    if not parsed.hostname:
        return False
    try:
        with socket.create_connection((parsed.hostname, parsed.port or 5432), timeout=2):
            return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(
    not ("postgres" in _DSN and _postgres_is_listening()) and not _REQUIRED,
    reason="needs a live PostgreSQL with the migration chain applied",
)

_UNUSABLE_PASSWORD_HASH = "x"  # noqa: S105 - not a credential; no plaintext maps to it

ALERTS = (
    ("Mimikatz credential dump on HOST-1", "lsass read by an unsigned binary"),
    ("Benign interactive login", "user signed in from the office"),
    ("Port scan from 203.0.113.9", "1,024 ports in 30 seconds; tool looked like mimikatz_helper"),
    ("Disk 100% full on build-agent", "not a security event"),
)


@pytest_asyncio.fixture(autouse=True)
async def _release_the_app_pool():
    yield
    from app.db.database import engine

    await engine.dispose()


@pytest_asyncio.fixture
async def token():
    from app.core.security import create_access_token

    engine = create_async_engine(_DSN)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    tenant_id = uuid.uuid4()
    user_id = uuid.uuid4()
    suffix = tenant_id.hex[:8]
    async with maker() as db:
        await db.execute(
            text("INSERT INTO tenants (id, name, slug) VALUES (:i, :n, :s)"),
            {"i": tenant_id, "n": f"search-{suffix}", "s": f"search-{suffix}"},
        )
        await db.execute(
            text(
                """
                INSERT INTO users (id, tenant_id, email, username, hashed_password,
                                   role, is_active, is_verified)
                VALUES (:i, :t, :e, :u, :h, 'admin', TRUE, TRUE)
                """
            ),
            {"i": user_id, "t": tenant_id, "e": f"analyst-{suffix}@example.com", "u": f"analyst-{suffix}", "h": _UNUSABLE_PASSWORD_HASH},
        )
        for title, description in ALERTS:
            await db.execute(
                text("INSERT INTO alerts (id, tenant_id, title, description, severity, status) VALUES (:i, :t, :ti, :d, 'high', 'new')"),
                {"i": uuid.uuid4(), "t": tenant_id, "ti": title, "d": description},
            )
        await db.commit()
    yield create_access_token({"sub": str(user_id)})
    await engine.dispose()


async def _titles(token: str, search: str) -> tuple[int, list[str]]:
    from app.main import app

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        response = await client.get("/api/v1/alerts", params={"search": search}, headers={"Authorization": f"Bearer {token}"})
    body = response.json()
    return body["total"], sorted(item["title"] for item in body["items"])


async def test_search_narrows_to_the_matching_alerts(token) -> None:
    total, titles = await _titles(token, "MIMIKATZ")
    assert titles == ["Mimikatz credential dump on HOST-1", "Port scan from 203.0.113.9"]
    assert total == 2, "`total` must count the filtered set, not the tenant"


async def test_a_term_matching_nothing_returns_nothing(token) -> None:
    assert await _titles(token, "no-such-alert") == (0, [])


async def test_like_metacharacters_are_matched_literally(token) -> None:
    """`%` and `_` are LIKE wildcards. Unescaped, `100%` would match any
    title containing "100" and `_` would match every character."""
    assert await _titles(token, "100%") == (1, ["Disk 100% full on build-agent"])
    assert await _titles(token, "z_h") == (1, ["Port scan from 203.0.113.9"])
