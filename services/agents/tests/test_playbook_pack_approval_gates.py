"""Shipped packs that gate a destructive ``http`` step behind a human approve it.

Three packs gated their release / reset step on a ``condition`` reading
``context.approved_by_oncall``, which nothing in the product writes. The
condition was always false, the step was skipped, and the engine advanced to
the next step: the action the "Wait for human approval" step existed to hold
back. In the BEC pack that released the payment the run had just frozen.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from app.playbook import engine as playbook_engine
from app.playbook.engine import PlaybookEngine, RunStatus, StepStatus
from app.playbook.models import Playbook, StepType

_PACKS = Path(__file__).resolve().parent.parent / "app" / "playbook" / "packs" / "v1"

# pack file -> the step the approval holds back
_GATED = {
    "bec/bec-vendor-payment-redirect.playbook.json": "release",
    "account-takeover/ato-impossible-travel-block.playbook.json": "reset",
    "account-takeover/ato-mfa-fatigue-response.playbook.json": "reset-mfa",
}

_ALERT = {
    "alert": {"payment_id": "PAY-1", "user": "j.doe@example.com", "source_ip": "203.0.113.7", "case_id": "C-1", "severity": "high"},
    "tenant_id": "00000000-0000-0000-0000-000000000001",
}


def _pack(rel: str) -> Playbook:
    return Playbook.model_validate(json.loads((_PACKS / rel).read_text()))


def _dispatch_succeeds(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Every action step dispatches, as in a deployment with its integrations
    configured. Approval steps keep the engine's own handling, which is the
    thing under test. Returns the ids of the steps that were dispatched."""
    real_invoke = playbook_engine._invoke_step
    dispatched: list[str] = []

    async def _invoke(step, pr, http, *, dry_run):  # noqa: ANN001, ANN202
        if step.type == StepType.APPROVAL:
            return await real_invoke(step, pr, http, dry_run=dry_run)
        dispatched.append(step.id)
        return StepStatus.SUCCESS, {"executed": True}

    monkeypatch.setattr(playbook_engine, "_invoke_step", _invoke)
    return dispatched


@pytest.mark.asyncio
@pytest.mark.parametrize(("rel", "gated"), sorted(_GATED.items()))
async def test_the_run_pauses_for_approval_before_the_gated_step(monkeypatch: pytest.MonkeyPatch, rel: str, gated: str) -> None:
    async def _suspend(pr, step, step_idx, http):  # noqa: ANN001, ANN202
        return SimpleNamespace(id="pause-1", approval_id="appr-1", expires_at=datetime.now(UTC) + timedelta(hours=1))

    monkeypatch.setattr(playbook_engine, "_suspend_for_approval", _suspend)
    dispatched = _dispatch_succeeds(monkeypatch)
    run = await PlaybookEngine().run(_pack(rel), json.loads(json.dumps(_ALERT)))

    assert run.status == RunStatus.PAUSED
    assert run.step_results[-1]["step_id"] == "approve"
    assert gated not in dispatched


@pytest.mark.asyncio
@pytest.mark.parametrize(("rel", "gated"), sorted(_GATED.items()))
async def test_an_approval_that_cannot_be_opened_stops_the_run(monkeypatch: pytest.MonkeyPatch, rel: str, gated: str) -> None:
    # No service token, so the engine cannot open the approval.
    monkeypatch.delenv("AISOC_AGENTS_SERVICE_TOKEN", raising=False)
    dispatched = _dispatch_succeeds(monkeypatch)
    run = await PlaybookEngine().run(_pack(rel), json.loads(json.dumps(_ALERT)))

    assert run.status == RunStatus.FAILED
    assert run.step_results[-1]["step_id"] == "approve"
    assert gated not in dispatched
