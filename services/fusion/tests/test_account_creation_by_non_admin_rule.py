"""`det-identity-026` must not call every Okta user creation "by a non-admin".

The rule read `actor_role_not_in: [admin, user_admin]`. No connector emits
`actor_role`, and the matcher's `not_in` is true on a missing field (the
Sigma compiler relies on that, so the operator is not the thing to change).
The clause was therefore satisfied by every event, and the rule fired on
every `user.lifecycle.create` — including the ones an administrator
performed — as a high-severity "User Account Creation by Non-Admin
Principal".

The rule now reads `actor_is_admin`, which the tenant overlay resolves from
the tenant's imported privileged principals and leaves absent for an actor
it does not know.

These tests drive the real engine over the real shipped ruleset, with the
event in the shape `OktaConnector.normalize()` emits.
"""

from __future__ import annotations

import json
from typing import Any

from app.services.detection_engine import DetectionEngine
from app.services.tenant_overlay import TenantOverlay

RULE_ID = "det-identity-026"
TENANT = "00000000-0000-4000-8000-000000000026"

#: An Okta System Log `user.lifecycle.create` row, trimmed.
OKTA_USER_CREATED_BY = {
    "uuid": "6c1f8a2e-0000-4000-8000-000000000026",
    "published": "2026-10-10T09:15:00.000Z",
    "eventType": "user.lifecycle.create",
    "displayMessage": "Create Okta user",
    "outcome": {"result": "SUCCESS"},
    "client": {"ipAddress": "203.0.113.7"},
}


def _okta_event(actor_email: str) -> dict[str, Any]:
    """The engine message for an Okta user creation performed by `actor_email`.

    The normalized keys are the ones `OktaConnector.normalize()` sets for
    this row (see `test_okta_identity_rules_are_reachable.py` for the full
    transcription); none of them is `actor_role`.
    """
    display_name = actor_email.split("@")[0]
    raw = {**OKTA_USER_CREATED_BY, "actor": {"displayName": display_name, "alternateId": actor_email}}
    normalised = {
        "source": "okta",
        "external_id": OKTA_USER_CREATED_BY["uuid"],
        "title": OKTA_USER_CREATED_BY["displayMessage"],
        "description": "user.lifecycle.create - SUCCESS",
        "severity": "info",
        "src_ip": "203.0.113.7",
        "actor": display_name,
        "actor_email": actor_email,
        "event_type": OKTA_USER_CREATED_BY["eventType"],
        "outcome": "SUCCESS",
        "raw_event": raw,
        "created_at": OKTA_USER_CREATED_BY["published"],
    }
    return {"tenant_id": TENANT, "ocsf_event": {"raw_data": json.dumps(normalised)}}


def _fired(message: dict[str, Any], overlay: TenantOverlay | None = None) -> bool:
    return RULE_ID in {hit.rule_id for hit in DetectionEngine().evaluate(message, overlay)}


def _overlay(*admins: str) -> TenantOverlay:
    return TenantOverlay(tenant_id=TENANT, privileged_principals=frozenset(a.lower() for a in admins))


def test_an_administrator_creating_a_user_is_not_reported_as_a_non_admin() -> None:
    overlay = _overlay("okta-admin@example.com")
    assert not _fired(_okta_event("okta-admin@example.com"), overlay)


def test_an_unknown_actor_is_not_reported_as_a_non_admin() -> None:
    """No identities imported: nobody knows the actor's privilege, so the
    rule has nothing to say. It used to fire here on every creation."""
    assert not _fired(_okta_event("okta-admin@example.com"))


def test_a_known_non_admin_creating_a_user_still_fires() -> None:
    overlay = _overlay("okta-admin@example.com")
    assert _fired(_okta_event("intern@example.com"), overlay)
