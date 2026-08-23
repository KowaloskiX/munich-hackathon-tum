"""Frozen data contracts (see ARCHITECTURE.md §4).

Do NOT change a contract without updating both sides + the mock.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

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
    AGENT_STEP = "AGENT_STEP"
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
    # Evidence the agent actually worked in its VM (write->compile->test->fix).
    iterations: int = 0
    compiled: bool | None = None
    self_tpr: float | None = None
    self_fpr: float | None = None
    session_url: str | None = None  # Devin session, for the incident report


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


class DemoResetResult(BaseModel):
    status: Literal["reset"] = "reset"
    nodes_preserved: int


# --- Contract 5: real OTA + software enforcement + incident reports -------
# REST-only (not WS-crossing), so these are not part of the mirrored contract
# checked by test_contract_sync — the dashboard reads the report as markdown.
class DeployedFilter(BaseModel):
    """The filter the backend has published for a node to pull over OTA."""

    fw_version: str
    filter_c_code: str
    attack_class: str
    sample_frames: list[str] = Field(default_factory=list)  # replay capture


class FirmwarePayload(BaseModel):
    """GET /firmware/{node_id}: the real compiled-elsewhere filter to load."""

    node_id: str
    fw_version: str
    filter_c_code: str = ""
    attack_class: str = ""
    sample_frames: list[str] = Field(default_factory=list)


class EnforcementResult(BaseModel):
    """What a loaded filter actually did to frames in the traffic path.

    `blocked`/`passed` are always known. The attack/benign breakdown is only
    known when the caller labelled the stream (the oracle-style sample run); the
    edge gateway drops by filter alone and leaves them None.
    """

    blocked: int  # frames the loaded filter dropped
    passed: int  # frames it let through
    attack_total: int | None = None  # attack frames replayed (if labelled)
    benign_total: int | None = None  # benign baseline frames replayed
    false_positives: int | None = None  # benign frames the filter wrongly dropped


class EnforcementReport(BaseModel):
    """POST /enforcement: a standalone software node reports real counts."""

    node_id: str
    fw_version: str = "v1"
    blocked: int
    passed: int


class IncidentReport(BaseModel):
    id: str
    node_id: str
    started_ts: float
    attack_class: str = "unknown"
    confidence: float = 0.0
    frames: int = 0
    filter_c_code: str = ""
    iterations: int = 0
    self_tpr: float | None = None
    self_fpr: float | None = None
    oracle: OracleOut | None = None
    enforcement: EnforcementResult | None = None
    deployed: bool = False
    deployed_ts: float | None = None
    session_url: str | None = None
    events: list[LiveEvent] = Field(default_factory=list)


class IncidentSummary(BaseModel):
    id: str
    node_id: str
    started_ts: float
    attack_class: str
    deployed: bool
    blocked: int
    oracle_passed: bool | None = None
