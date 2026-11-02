"""Paging through alerts must visit every alert exactly once.

The defect
----------
``GET /api/v1/alerts`` orders by ``created_at`` (after severity, for
``sort=priority``) and ``GET /api/v1/alerts/queue`` by ``(bucket, sla due,
severity)``. Neither key is unique. ``alerts.created_at`` defaults to
``NOW()``, which is the *transaction* start, so every alert one fusion batch
writes shares it exactly, and a connector batch shares one ``first_seen``.

PostgreSQL does not keep tied rows in a stable order across different
``OFFSET``/``LIMIT`` windows: a top-N sort returns the ties in whatever order
its heap leaves them. So page 2 can repeat a row from page 1 and some other
row is served on no page at all. For a queue of criticals that is an alert
the analyst is never shown.

What is asserted here
---------------------
That walking every page of each listing yields every seeded alert once. It
runs through the shipped app against real PostgreSQL, because the defect is
the database's tie order and SQLite does not exhibit it.
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

#: Several pages' worth, all tied on every sort key the listings use.
SEEDED_ALERTS = 300
PAGE_SIZE = 25


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


@pytest_asyncio.fixture(autouse=True)
async def _release_the_app_pool():
    yield
    from app.db.database import engine

    await engine.dispose()


@pytest_asyncio.fixture
async def tied_batch():
    """A scratch tenant holding one batch of tied criticals. Yields ``(token, alert_ids)``."""
    from app.core.security import create_access_token

    engine = create_async_engine(_DSN)
    maker = async_sessionmaker(engine, expire_on_commit=False)

    tenant_id = uuid.uuid4()
    user_id = uuid.uuid4()
    suffix = tenant_id.hex[:8]
    alert_ids: set[str] = set()

    async with maker() as db:
        await db.execute(
            text("INSERT INTO tenants (id, name, slug) VALUES (:i, :n, :s)"),
            {"i": tenant_id, "n": f"ties-{suffix}", "s": f"ties-{suffix}"},
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
        # One transaction, as one fusion batch is: `created_at` defaults to
        # NOW(), the transaction start, so every row gets the same value.
        for n in range(SEEDED_ALERTS):
            alert_id = uuid.uuid4()
            alert_ids.add(str(alert_id))
            await db.execute(
                text(
                    """
                    INSERT INTO alerts (id, tenant_id, title, severity, status, first_seen)
                    VALUES (:i, :t, :ti, 'critical', 'new', TIMESTAMPTZ '2026-11-01 10:00:00+00')
                    """
                ),
                {"i": alert_id, "t": tenant_id, "ti": f"alert {n:03d}"},
            )
        await db.commit()

    yield create_access_token({"sub": str(user_id)}), alert_ids
    await engine.dispose()


async def _walk(token: str, path: str, params: dict) -> list[str]:
    from app.main import app

    seen: list[str] = []
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        page, pages = 1, 1
        while page <= pages:
            response = await client.get(
                path,
                params={**params, "page": page, "page_size": PAGE_SIZE},
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 200, response.text
            body = response.json()
            pages = body["pages"]
            seen += [item["id"] for item in body["items"]]
            page += 1
    return seen


def _assert_partition(seen: list[str], expected: set[str]) -> None:
    repeated = len(seen) - len(set(seen))
    missing = expected - set(seen)
    assert not repeated and not missing, f"{repeated} alert(s) served twice and {len(missing)} never served across the pages"


@pytest.mark.parametrize("sort", ["newest", "priority"])
async def test_the_alert_list_pages_visit_every_alert_once(tied_batch, sort: str) -> None:
    token, alert_ids = tied_batch
    _assert_partition(await _walk(token, "/api/v1/alerts", {"sort": sort}), alert_ids)


async def test_the_queue_pages_visit_every_alert_once(tied_batch) -> None:
    token, alert_ids = tied_batch
    _assert_partition(await _walk(token, "/api/v1/alerts/queue", {}), alert_ids)
