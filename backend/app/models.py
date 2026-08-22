"""Frozen data contracts (see ARCHITECTURE.md §4).

Do NOT change a contract without updating both sides + the mock.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class NodeState(StrEnum):
    NORMAL = "NORMAL"
    ALERT = "ALERT"
    PROTECTED = "PROTECTED"
    UPDATING = "UPDATING"
    OFFLINE = "OFFLINE"


class EventType(StrEnum):
    NODE_UP = "NODE_UP"
    NODE_DOWN = "NODE_DOWN"
    ANOMALY_DETECTED = "ANOMALY_DETECTED"
    AGENT_ANALYZING = "AGENT_ANALYZING"
    FILTER_GENERATED = "FILTER_GENERATED"
    VERIFYING = "VERIFYING"
    VERIFY_FAILED = "VERIFY_FAILED"
    VERIFY_PASSED = "VERIFY_PASSED"
    OTA_DEPLOYING = "OTA_DEPLOYING"
    DEPLOYED = "DEPLOYED"
    FRAME_BLOCKED = "FRAME_BLOCKED"


# --- Contract 1: ESP -> POST /ingest -------------------------------------
class AnomalyStats(BaseModel):
    frame_type: str = "mgmt"
    subtype: int | None = None
    count_in_window: int = 0
    window_ms: int = 1000


class AnomalyIn(BaseModel):
    node_id: str
    timestamp: float
    frame_hex: list[str] = Field(default_factory=list)
    rssi: int | None = None
    anomaly_stats: AnomalyStats = Field(default_factory=AnomalyStats)
    guessed_type: str | None = None


# --- Contract 2: ESP -> POST /heartbeat ----------------------------------
class HeartbeatStats(BaseModel):
    frames_seen: int = 0
    blocked: int = 0
    fw_version: str = "v1"


class Heartbeat(BaseModel):
    node_id: str
    timestamp: float
    state: NodeState = NodeState.NORMAL
    stats: HeartbeatStats = Field(default_factory=HeartbeatStats)


# --- Contract 3: Backend <-> Agent ---------------------------------------
class AgentIn(BaseModel):
    frame_hex: list[str]
    anomaly_stats: AnomalyStats = Field(default_factory=AnomalyStats)
    prev_filter: str | None = None
    failure_log: str | None = None


class AgentOut(BaseModel):
    attack_class: str
    confidence: float
    filter_c_code: str
    explanation: str = ""


# --- Contract 4: Backend <-> Oracle --------------------------------------
class OracleIn(BaseModel):
    filter_c_code: str


class OracleOut(BaseModel):
    passed: bool
    tpr: float
    fpr: float
    tests_total: int
    tests_passed: int
    log: str = ""


# --- WebSocket /live event (drives the dashboard) ------------------------
class LiveEvent(BaseModel):
    type: EventType
    node_id: str | None = None
    ts: float
    payload: dict[str, Any] = Field(default_factory=dict)


# --- Dashboard bootstrap snapshot ----------------------------------------
class NodeView(BaseModel):
    node_id: str
    state: NodeState
    last_seen: float
    fw_version: str
    label: str
    blocked: int = 0


class Counters(BaseModel):
    active_nodes: int = 0
    threats_detected: int = 0
    filters_deployed: int = 0
    frames_blocked: int = 0


class FleetSnapshot(BaseModel):
    nodes: list[NodeView]
    counters: Counters
