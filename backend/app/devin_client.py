"""Thin typed client for the Devin external API (v1).

Endpoints (base https://api.devin.ai/v1, Bearer auth):
  POST /sessions                 {prompt, structured_output?} -> {session_id, url}
  GET  /session/{session_id}     -> {status_enum, structured_output, ...}
  POST /session/{session_id}/message  {message}

A custom httpx transport can be injected for tests and offline mock runs.
"""

from __future__ import annotations

from typing import Any

import httpx
from pydantic import BaseModel, Field

from .config import settings

# status_enum values that mean "done, stop polling".
TERMINAL_STATUSES = {"finished", "blocked", "expired"}


class DevinSession(BaseModel):
    session_id: str
    url: str | None = None
    status_enum: str | None = None
    # Devin returns this as an object (or a JSON string); keep it loose here and
    # parse in the agent.
    structured_output: Any = None
    title: str | None = Field(default=None)

    @property
    def is_terminal(self) -> bool:
        return self.status_enum in TERMINAL_STATUSES


class DevinClient:
    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        transport: httpx.BaseTransport | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.api_key = api_key if api_key is not None else settings.devin_api_key
        self.base_url = (base_url or settings.devin_base_url).rstrip("/")
        self._client = httpx.Client(
            base_url=self.base_url,
            headers={"Authorization": f"Bearer {self.api_key}"},
            timeout=timeout,
            transport=transport,
        )

    def create_session(self, prompt: str, structured_output: str | None = None) -> DevinSession:
        body: dict[str, Any] = {"prompt": prompt}
        if structured_output:
            body["structured_output"] = structured_output
        resp = self._client.post("/sessions", json=body)
        resp.raise_for_status()
        return DevinSession.model_validate(resp.json())

    def get_session(self, session_id: str) -> DevinSession:
        resp = self._client.get(f"/session/{session_id}")
        resp.raise_for_status()
        data = resp.json()
        data.setdefault("session_id", session_id)
        return DevinSession.model_validate(data)

    def send_message(self, session_id: str, message: str) -> None:
        resp = self._client.post(f"/session/{session_id}/message", json={"message": message})
        resp.raise_for_status()

    def close(self) -> None:
        self._client.close()
