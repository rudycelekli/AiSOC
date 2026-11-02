"""A tenant's first ``PUT /api/v1/data-lifecycle/retention`` may set one window.

Every field of ``RetentionUpdate`` is optional, so ``{"alerts_days": 30}`` is
a valid body. On a tenant that has never saved a policy, ``put_retention``
creates the row and reads the omitted windows from it -- but a new ORM row
has no column defaults applied yet, so they were None, and
``resolve_policy`` passed that None to ``int()``. The request answered 500.

Runs through the shipped app against real PostgreSQL, because the defect is
the interaction between a not-yet-flushed row and the server-side column
defaults, which a fake session cannot reproduce.
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
    not ("postgres" in _DSN and _postgres_is_listening()),
    reason="needs a live PostgreSQL with the migration chain applied",
)

_UNUSABLE_PASSWORD_HASH = "x"  # noqa: S105 - not a credential; no plaintext maps to it


@pytest_asyncio.fixture(autouse=True)
async def _release_the_app_pool():
    yield
    from app.db.database import engine

    await engine.dispose()


@pytest_asyncio.fixture
async def token():
    """An admin of a tenant that has never saved a retention policy."""
    from app.core.security import create_access_token

    engine = create_async_engine(_DSN)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    tenant_id = uuid.uuid4()
    user_id = uuid.uuid4()
    suffix = tenant_id.hex[:8]
    async with maker() as db:
        await db.execute(
            text("INSERT INTO tenants (id, name, slug) VALUES (:i, :n, :s)"),
            {"i": tenant_id, "n": f"retention-{suffix}", "s": f"retention-{suffix}"},
        )
        await db.execute(
            text(
                """
                INSERT INTO users (id, tenant_id, email, username, hashed_password,
                                   role, is_active, is_verified)
                VALUES (:i, :t, :e, :u, :h, 'admin', TRUE, TRUE)
                """
            ),
            {"i": user_id, "t": tenant_id, "e": f"admin-{suffix}@example.com", "u": f"admin-{suffix}", "h": _UNUSABLE_PASSWORD_HASH},
        )
        await db.commit()
    yield create_access_token({"sub": str(user_id)})
    await engine.dispose()


async def _put(token: str, body: dict) -> tuple[int, dict]:
    from app.main import app

    async with AsyncClient(transport=ASGITransport(app=app, raise_app_exceptions=False), base_url="http://testserver") as client:
        response = await client.put("/api/v1/data-lifecycle/retention", json=body, headers={"Authorization": f"Bearer {token}"})
    return response.status_code, (response.json() if response.headers.get("content-type", "").startswith("application/json") else {})


async def test_a_first_put_may_set_one_window(token) -> None:
    from app.services.retention import resolve_policy

    defaults = resolve_policy(None)

    code, body = await _put(token, {"alerts_days": 30})

    assert code == 200, f"a first PUT naming one window answered {code}"
    assert body["alerts_days"] == 30
    assert body["raw_events_days"] == defaults.raw_events_days
    assert body["audit_days"] == defaults.audit_days
