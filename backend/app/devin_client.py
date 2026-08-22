"""Thin typed client for the Devin external API (v3).

v3 is org-scoped and PAT-authenticated (Bearer cog_...). Endpoints:
  GET  /self                                        -> {org_id, user_id, ...}
  POST /organizations/{org}/sessions                {prompt, structured_output_*} -> session
  GET  /organizations/{org}/sessions/{session_id}   -> session (with structured_output)
  POST /organizations/{org}/sessions/{session_id}/messages  {message}

`status` ∈ {new, claimed, running, exit, error, suspended, resuming}; when running,
`status_detail` ∈ {working, waiting_for_user, waiting_for_approval, finished}.
`structured_output` is only populated on GET once the agent has produced it.

A custom httpx transport can be injected for tests and offline mock runs.
"""

from __future__ import annotations

from typing import Any

import httpx
from pydantic import BaseModel

from .config import settings

# status values that mean the session has stopped for good.
DEAD_STATUSES = {"exit", "error", "suspended"}


class DevinSession(BaseModel):
    session_id: str
    url: str | None = None
    status: str | None = None
    status_detail: str | None = None
    structured_output: Any = None
    acus_consumed: float | None = None

    @property
    def has_output(self) -> bool:
        return self.structured_output is not None

    @property
    def is_dead(self) -> bool:
        return self.status in DEAD_STATUSES


class DevinClient:
    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        org_id: str | None = None,
        transport: httpx.BaseTransport | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.api_key = api_key if api_key is not None else settings.devin_api_key
        self.base_url = (base_url or settings.devin_base_url).rstrip("/")
        self._org_id = org_id if org_id is not None else settings.devin_org_id
        self._client = httpx.Client(
            base_url=self.base_url,
            headers={"Authorization": f"Bearer {self.api_key}"},
            timeout=timeout,
            transport=transport,
        )

    @property
    def org_id(self) -> str:
        if not self._org_id:
            resp = self._client.get("/self")
            resp.raise_for_status()
            self._org_id = resp.json()["org_id"]
        return self._org_id

    def _sessions_base(self) -> str:
        return f"/organizations/{self.org_id}/sessions"

    def create_session(
        self,
        prompt: str,
        structured_output_schema: dict[str, Any] | None = None,
    ) -> DevinSession:
        body: dict[str, Any] = {
            "prompt": prompt,
            "resumable": settings.devin_resumable,
        }
        if settings.devin_max_acu_limit:
            body["max_acu_limit"] = settings.devin_max_acu_limit
        if structured_output_schema:
            body["structured_output_required"] = True
            body["structured_output_schema"] = structured_output_schema
        resp = self._client.post(self._sessions_base(), json=body)
        resp.raise_for_status()
        return DevinSession.model_validate(resp.json())

    def get_session(self, session_id: str) -> DevinSession:
        resp = self._client.get(f"{self._sessions_base()}/{session_id}")
        resp.raise_for_status()
        data = resp.json()
        data.setdefault("session_id", session_id)
        return DevinSession.model_validate(data)

    def send_message(self, session_id: str, message: str) -> None:
        resp = self._client.post(
            f"{self._sessions_base()}/{session_id}/messages", json={"message": message}
        )
        resp.raise_for_status()

    def terminate(self, session_id: str) -> None:
        """Tear down the session's VM immediately (stops any idle billing)."""
        resp = self._client.delete(f"{self._sessions_base()}/{session_id}")
        resp.raise_for_status()

    def close(self) -> None:
        self._client.close()
