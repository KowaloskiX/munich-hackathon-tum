"""HMI status adapter — the aggregate SOC view the ESP32 display consumes.

The display firmware (firmware/esp32-display) polls GET /v1/hmi/status and
expects a single overall security level (SAFE / ATTACK / UNKNOWN) plus incident,
sensor, and metric fields — a different shape from the per-node /nodes snapshot
the web dashboard uses. This module derives that aggregate from AppState so the
firmware runs against the real backend unchanged.

Contract (schema_version 1), matching firmware/esp32-display expectations:
    {
      "schema_version": 1,
      "stream_id": str, "stream_generation": int, "seq": int,
      "status": "SAFE" | "ATTACK" | "UNKNOWN",
      "valid_for_ms": int,
      "active_alerts": int,
      "sensors": {"online": int, "expected": int},
      "metrics": {"attack_frames_detected": int},
      "incident": {"id": str, "node_id": str, "attack_class": str} | null
    }
"""

from __future__ import annotations

import time
from typing import Literal

from pydantic import BaseModel

from .models import NodeState
from .state import AppState

VALID_FOR_MS = 10_000
_ALERT_STATES = {NodeState.ALERT, NodeState.UPDATING}
_ATTACK_CLASS_EVENTS = {"FILTER_GENERATED", "DEPLOYED", "ANOMALY_DETECTED"}


class Incident(BaseModel):
    id: str
    node_id: str
    attack_class: str


class HmiStatus(BaseModel):
    schema_version: int = 1
    stream_id: str
    stream_generation: int
    seq: int
    status: str
    valid_for_ms: int = VALID_FOR_MS
    active_alerts: int
    sensors: dict[str, int]
    metrics: dict[str, int]
    incident: Incident | None = None


class HmiEvent(BaseModel):
    schema_version: int = 1
    event_id: str
    stream_id: str
    stream_generation: int
    seq: int
    type: Literal["SYSTEM_STATUS"] = "SYSTEM_STATUS"
    node_id: str
    ts: float
    payload: HmiStatus


def _latest_incident(state: AppState) -> Incident | None:
    """Most recent event that names an attack, if any node is still alerting."""
    alerting = [n for n in state.nodes.values() if n.state in _ALERT_STATES]
    if not alerting:
        return None
    for event in reversed(state.events):
        attack_class = str(event.payload.get("attack_class") or "")
        if event.type in _ATTACK_CLASS_EVENTS and event.node_id:
            return Incident(
                id=f"{event.node_id}:{int(event.ts)}",
                node_id=event.node_id,
                attack_class=attack_class or "unknown",
            )
    node = alerting[0]
    return Incident(id=f"{node.node_id}:0", node_id=node.node_id, attack_class="unknown")


def _level(incident: Incident | None) -> str:
    if incident is None:
        return "SAFE"
    return "UNKNOWN" if incident.attack_class == "unknown" else "ATTACK"


class HmiStream:
    """Holds stream identity and a monotonic seq that bumps on state change."""

    def __init__(self) -> None:
        self.stream_id = f"backend-{int(time.time())}"
        self.stream_generation = int(time.time() * 1000)
        self.seq = 1
        self._signature: tuple[object, ...] | None = None

    def build(self, state: AppState) -> HmiStatus:
        incident = _latest_incident(state)
        level = _level(incident)
        online = sum(1 for n in state.nodes.values() if n.state is not NodeState.OFFLINE)
        active_alerts = sum(1 for n in state.nodes.values() if n.state in _ALERT_STATES)
        signature = (
            level,
            incident.id if incident else "",
            incident.node_id if incident else "",
            incident.attack_class if incident else "",
            active_alerts,
            online,
            len(state.nodes),
            state.counters.frames_blocked,
        )
        if signature != self._signature:
            self._signature = signature
            self.seq += 1

        return HmiStatus(
            stream_id=self.stream_id,
            stream_generation=self.stream_generation,
            seq=self.seq,
            status=level,
            active_alerts=active_alerts,
            sensors={"online": online, "expected": len(state.nodes)},
            metrics={"attack_frames_detected": state.counters.frames_blocked},
            incident=incident,
        )

    def event(self, state: AppState, node_id: str) -> HmiEvent:
        """Wrap the current aggregate in the ordered event consumed by the HMI."""
        status = self.build(state)
        return HmiEvent(
            event_id=f"hmi-{status.stream_generation}-{status.seq}",
            stream_id=status.stream_id,
            stream_generation=status.stream_generation,
            seq=status.seq,
            node_id=node_id,
            ts=time.time(),
            payload=status,
        )
