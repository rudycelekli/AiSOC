"""An approved step's outcome reaches the conditions that read it.

Shipped packs guard the action an approval protects with
``steps.<approval id>.outcome == 'approved'``, and later steps read
``steps.<id>.outcome == 'success'``. Nothing wrote ``steps``, so those
conditions read None: an analyst approved the isolation and the run skipped
it, every time.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from app.playbook import engine as playbook_engine
from app.playbook import pause as playbook_pause
from app.playbook.engine import PlaybookEngine, StepStatus
from app.playbook.models import Playbook, PlaybookStep, StepType
from app.playbook.store import PlaybookStore

_TENANT = "00000000-0000-0000-0000-0000000000a1"


@pytest.mark.asyncio
async def test_an_approved_isolation_in_the_shipped_malware_pack_runs(monkeypatch: pytest.MonkeyPatch) -> None:
    playbook = PlaybookStore.default().get("malware-execution-response-v1", tenant_id=_TENANT)
    assert playbook is not None
    gate_index = next(i for i, s in enumerate(playbook.steps) if s.id == "approval_isolate")

    waiting = playbook_pause.Pause(
        id="pause-1",
        tenant_id=_TENANT,
        run_id="run-1",
        playbook_id=playbook.id,
        step_index=gate_index,
        step_id="approval_isolate",
        run_context={"tenant_id": _TENANT, "alert": {"hostname": "ws-17"}},
        step_results=[],
        approval_id="appr-1",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )

    async def find_waiting(*, approval_id: str, tenant_id: str):  # noqa: ANN202
        return waiting if approval_id == "appr-1" and tenant_id == _TENANT else None

    async def resolve(**_kwargs) -> bool:  # noqa: ANN003
        return True

    dispatched: list[str] = []

    async def invoke(step: PlaybookStep, pr, http, *, dry_run: bool, path=()):  # noqa: ANN001, ANN202
        dispatched.append(step.id)
        return StepStatus.SUCCESS, {}

    monkeypatch.setattr(playbook_pause, "find_waiting", find_waiting)
    monkeypatch.setattr(playbook_pause, "resolve", resolve)
    monkeypatch.setattr(playbook_engine, "_invoke_step", invoke)

    run = await playbook_engine.resume_after_approval(approval_id="appr-1", tenant_id=_TENANT, approved=True, decided_by="analyst")

    assert run is not None
    statuses = {r["step_id"]: r["status"] for r in run.step_results}
    assert statuses.get("isolate_host") != StepStatus.SKIPPED, "the analyst approved the isolation and the run skipped it"
    assert "isolate_host" in dispatched


@pytest.mark.asyncio
async def test_a_later_step_can_read_an_earlier_steps_outcome(monkeypatch: pytest.MonkeyPatch) -> None:
    async def invoke(step: PlaybookStep, pr, http, *, dry_run: bool, path=()):  # noqa: ANN001, ANN202
        return StepStatus.SUCCESS, {}

    monkeypatch.setattr(playbook_engine, "_invoke_step", invoke)
    playbook = Playbook(
        id="pb-outcomes",
        name="outcome chain",
        description="",
        trigger={"on": "alert.created"},
        enabled=True,
        steps=[
            PlaybookStep(id="isolate_host", name="isolate", type=StepType.NOTIFY),
            PlaybookStep(id="scan", name="scan", type=StepType.NOTIFY, condition="steps.isolate_host.outcome == 'success'"),
        ],
    )

    run = await PlaybookEngine().run(playbook, {"tenant_id": _TENANT})

    statuses = {r["step_id"]: r["status"] for r in run.step_results}
    assert statuses["scan"] == StepStatus.SUCCESS
