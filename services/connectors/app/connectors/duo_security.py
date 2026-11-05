"""
Duo Security connector.
Fetches authentication logs from the Duo Admin API using HMAC-SHA1 signed requests.
"""

from __future__ import annotations

import base64
import email.utils
import hashlib
import hmac
import urllib.parse
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

# The v2 authentication-log endpoint's documented maximum page size.
_PAGE_LIMIT = 1000
# Bounds a single poll; a window that needs more pages logs the cap.
_MAX_PAGES = 50


class DuoSecurityConnector(BaseConnector):
    connector_id = "duo_security"
    connector_name = "Duo Security"
    connector_category = "iam"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description="Duo Security authentication logs via the Admin API (HMAC-SHA1 signed).",
            docs_url="/docs/connectors/duo-security",
            fields=[
                Field("integration_key", "string", "Integration Key"),
                Field("secret_key", "secret", "Secret Key"),
                Field(
                    "api_hostname",
                    "string",
                    "API Hostname",
                    placeholder="api-XXXXXXXX.duosecurity.com",
                ),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        # Duo authentication logs are an audit feed (who logged in from where).
        return (Capability.PULL_AUDIT,)

    def __init__(self, integration_key: str, secret_key: str, api_hostname: str):
        self._ikey = integration_key
        self._skey = secret_key
        self._host = api_hostname.lower()

    def _sign(self, method: str, path: str, params: dict[str, str]) -> tuple[str, str]:
        now = email.utils.formatdate()
        canon_params = urllib.parse.urlencode(sorted(params.items()))
        canon = "\n".join([now, method.upper(), self._host, path, canon_params])
        sig = hmac.new(self._skey.encode(), canon.encode(), hashlib.sha1).hexdigest()
        auth = base64.b64encode(f"{self._ikey}:{sig}".encode()).decode()
        return now, f"Basic {auth}"

    async def test_connection(self) -> dict[str, Any]:
        try:
            path = "/admin/v1/info/summary"
            date_str, auth = self._sign("GET", path, {})
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"https://{self._host}{path}",
                    headers={"Date": date_str, "Authorization": auth},
                )
                resp.raise_for_status()
                return {"success": True, "connector": self.connector_id}
        except Exception as exc:
            logger.warning("duo_security.test_connection.failed", error=str(exc))
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        mintime = str(int((datetime.now(UTC) - timedelta(seconds=since_seconds)).timestamp()) * 1000)
        path = "/admin/v2/logs/authentication"
        params = {
            "mintime": mintime,
            "maxtime": str(int(datetime.now(UTC).timestamp()) * 1000),
            "limit": str(_PAGE_LIMIT),
        }

        logs: list[dict[str, Any]] = []
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Duo returns one page (100 entries by default) and documents
            # fetching the rest by sending back `metadata.next_offset` for as
            # long as a response carries one. Reading only the first page kept
            # one page of the window and dropped the remainder for good.
            for _ in range(_MAX_PAGES):
                date_str, auth = self._sign("GET", path, params)
                resp = await client.get(
                    f"https://{self._host}{path}",
                    headers={"Date": date_str, "Authorization": auth},
                    params=params,
                )
                resp.raise_for_status()
                body = resp.json().get("response", {})
                logs.extend(body.get("authlogs", []))
                next_offset = (body.get("metadata") or {}).get("next_offset")
                if not next_offset:
                    break
                params = {**params, "next_offset": ",".join(str(part) for part in next_offset)}
            else:
                logger.warning("duo_security.fetch_page_cap_reached", pages=_MAX_PAGES, logs=len(logs))

        return [self.normalize(entry) for entry in logs]

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        result = str(raw.get("result", "")).upper()
        reason = str(raw.get("reason", "")).lower()

        if "fraud" in reason:
            severity = "high"
        elif result == "FAILURE":
            severity = "medium"
        elif raw.get("access_device", {}).get("is_encryption_enabled") == "false":
            severity = "low"
        elif result == "SUCCESS" and "new" in reason:
            severity = "low"
        else:
            severity = "info"

        user = raw.get("user", {}).get("name", "unknown")
        auth_device = raw.get("auth_device", {})

        return {
            "source": self.connector_id,
            "external_id": raw.get("txid", ""),
            "title": f"Duo auth: {result.lower()} for {user}",
            "description": f"Result: {result}, Reason: {raw.get('reason', 'N/A')}, User: {user}",
            "severity": severity,
            "src_ip": raw.get("access_device", {}).get("ip"),
            "actor": user,
            "hostname": auth_device.get("name"),
            "raw_event": raw,
            "created_at": raw.get("isotimestamp"),
        }
