"""Frozen data contracts (see ARCHITECTURE.md §4).

Do NOT change a contract without updating both sides + the mock.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Any

from pydantic import BaseModel, Field, model_validator


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
    # --- web/link-detection domain (2nd domain, same skeleton) ---
    LINK_SUBMITTED = "LINK_SUBMITTED"
    LINK_BROWSING = "LINK_BROWSING"
    LINK_RESEARCHING = "LINK_RESEARCHING"
    LINK_VERDICT = "LINK_VERDICT"
    # --- unified cross-domain feed (email + link + esp land here) ---
    INCIDENT_CREATED = "INCIDENT_CREATED"


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


# --- Contract 5: Extension/Scout <-> Backend (web/link domain) -----------
class LinkScanIn(BaseModel):
    url: str
    source: str = "manual"


class LinkVerdict(BaseModel):
    url: str
    verdict: str  # legit | suspicious | malicious
    legit_score: float  # 0..1, 1 = clearly legit
    impersonated_brand: str = ""
    top_signals: list[str] = Field(default_factory=list)
    reasoning: str = ""
    browse_score: float | None = None
    research_score: float | None = None


# --- Unified cross-domain feed (email + link + esp land in one list) ----
class IncidentSource(StrEnum):
    EMAIL = "EMAIL"
    LINK = "LINK"
    ESP = "ESP"


class IncidentSeverity(StrEnum):
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


class Incident(BaseModel):
    id: int
    ts: float
    source: IncidentSource
    severity: IncidentSeverity
    title: str
    summary: str = ""
    verdict: str = ""
    risk_score: int | None = None
    status: str = "OPEN"
    ref: str = ""  # domain ref: url / node_id / gmail_message_id
    url: str = ""


class IncidentList(BaseModel):
    items: list[Incident]
    next_cursor: int | None = None


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


# --- Gmail threat review -------------------------------------------------
class EmailMonitoringMode(StrEnum):
    ALL = "ALL"
    SELECTED = "SELECTED"


class EmailAnalysisStatus(StrEnum):
    QUEUED = "QUEUED"
    ANALYZING = "ANALYZING"
    CLEAR = "CLEAR"
    PENDING_REVIEW = "PENDING_REVIEW"
    FAILED = "FAILED"
    REVIEWED = "REVIEWED"


class EmailVerdict(StrEnum):
    CLEAR = "CLEAR"
    FLAGGED = "FLAGGED"
    INCONCLUSIVE = "INCONCLUSIVE"


class EmailReviewDecision(StrEnum):
    CONFIRMED_DANGEROUS = "CONFIRMED_DANGEROUS"
    NOT_DANGEROUS = "NOT_DANGEROUS"


class EmailEventType(StrEnum):
    RECEIVED = "EMAIL_RECEIVED"
    ANALYSIS_STARTED = "EMAIL_ANALYSIS_STARTED"
    ANALYSIS_COMPLETED = "EMAIL_ANALYSIS_COMPLETED"
    FLAGGED = "EMAIL_FLAGGED"
    FAILED = "EMAIL_ANALYSIS_FAILED"
    REVIEWED = "EMAIL_REVIEWED"
    CONNECTION_CHANGED = "GMAIL_CONNECTION_CHANGED"


class EmailLabels(BaseModel):
    scan: str = ""
    pending_review: str = ""
    confirmed_dangerous: str = ""
    not_dangerous: str = ""


class EmailConnectionStatus(BaseModel):
    connected: bool
    email: str | None = None
    mode: EmailMonitoringMode = EmailMonitoringMode.ALL
    watch_expiration: float | None = None
    last_sync: float | None = None
    labels: EmailLabels = Field(default_factory=EmailLabels)
    csrf_token: str | None = None


class EmailSettingsUpdate(BaseModel):
    mode: EmailMonitoringMode


class ThreatReason(BaseModel):
    category: str
    severity: str
    evidence: str
    artifact_ref: str | None = None


class ThreatCheck(BaseModel):
    artifact: str
    action: str
    result: str
    why: str


class ThreatReport(BaseModel):
    verdict: EmailVerdict
    risk_score: int = Field(ge=0, le=100)
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str
    reasons: list[ThreatReason] = Field(default_factory=list)
    checks: list[ThreatCheck] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)


class EmailTriagePlan(BaseModel):
    complete: bool
    requested_link_ids: list[str] = Field(default_factory=list)
    requested_attachment_ids: list[str] = Field(default_factory=list)
    report: ThreatReport | None = None


class EmailAttachment(BaseModel):
    id: str
    filename: str
    mime_type: str
    size: int
    sha256: str = ""


class EmailLink(BaseModel):
    id: str
    url: str
    host: str
    display: str = ""


class EmailPayload(BaseModel):
    gmail_message_id: str
    gmail_thread_id: str
    from_address: str
    reply_to: str = ""
    return_path: str = ""
    to_addresses: list[str] = Field(default_factory=list)
    cc_addresses: list[str] = Field(default_factory=list)
    subject: str
    received_at: float
    snippet: str
    body: str
    authentication_results: str = ""
    links: list[EmailLink] = Field(default_factory=list)
    attachments: list[EmailAttachment] = Field(default_factory=list)
    truncated: bool = False


class EmailAnalysisSummary(BaseModel):
    id: int
    gmail_message_id: str
    from_address: str
    subject: str
    snippet: str
    received_at: float
    status: EmailAnalysisStatus
    verdict: EmailVerdict | None = None
    risk_score: int | None = None
    review_decision: EmailReviewDecision | None = None


class EmailAnalysisDetail(EmailAnalysisSummary):
    report: ThreatReport | None = None
    devin_session_url: str | None = None
    error: str | None = None


class EmailAnalysisList(BaseModel):
    items: list[EmailAnalysisSummary]
    next_cursor: int | None = None


GmailMessageId = Annotated[str, Field(min_length=1, max_length=256, pattern=r"^[A-Za-z0-9_-]+$")]


class EmailMessagePreview(BaseModel):
    gmail_message_id: str
    from_address: str
    subject: str
    snippet: str
    received_at: float
    already_imported: bool


class EmailMessagePreviewList(BaseModel):
    items: list[EmailMessagePreview]
    next_page_token: str | None = None


class EmailImportRequest(BaseModel):
    message_ids: list[GmailMessageId] = Field(default_factory=list, max_length=50)
    limit: int | None = Field(default=None, ge=1, le=50)

    @model_validator(mode="after")
    def exactly_one_import_source(self) -> EmailImportRequest:
        if bool(self.message_ids) == (self.limit is not None):
            raise ValueError("provide exactly one of message_ids or limit")
        return self


class EmailImportResult(BaseModel):
    scanned: int
    imported: int
    duplicates: int


class EmailReviewRequest(BaseModel):
    decision: EmailReviewDecision


class EmailLiveEvent(BaseModel):
    type: EmailEventType
    analysis_id: int | None = None
    ts: float
    message: str


class GmailNotification(BaseModel):
    emailAddress: str
    historyId: str


class GmailWatchResponse(BaseModel):
    historyId: str
    expiration: str


class GmailTokenResponse(BaseModel):
    access_token: str
    expires_in: int
    refresh_token: str | None = None


class GmailProfile(BaseModel):
    emailAddress: str


class GmailLabel(BaseModel):
    id: str
    name: str


class GmailLabelList(BaseModel):
    labels: list[GmailLabel] = Field(default_factory=list)


class GmailMessageRef(BaseModel):
    id: str
    threadId: str = ""


class GmailMessageAdded(BaseModel):
    message: GmailMessageRef


class GmailMessageList(BaseModel):
    messages: list[GmailMessageRef] = Field(default_factory=list)
    nextPageToken: str | None = None


class GmailHistoryRecord(BaseModel):
    id: str
    messagesAdded: list[GmailMessageAdded] = Field(default_factory=list)


class GmailHistoryResponse(BaseModel):
    history: list[GmailHistoryRecord] = Field(default_factory=list)
    nextPageToken: str | None = None
    historyId: str | None = None


class GmailHeader(BaseModel):
    name: str
    value: str


class GmailBody(BaseModel):
    attachmentId: str | None = None
    size: int = 0
    data: str | None = None


class GmailPart(BaseModel):
    partId: str = ""
    mimeType: str = ""
    filename: str = ""
    headers: list[GmailHeader] = Field(default_factory=list)
    body: GmailBody = Field(default_factory=GmailBody)
    parts: list[GmailPart] = Field(default_factory=list)


class GmailMessage(BaseModel):
    id: str
    threadId: str
    labelIds: list[str] = Field(default_factory=list)
    snippet: str = ""
    internalDate: str = "0"
    payload: GmailPart


class GmailAttachmentData(BaseModel):
    data: str
    size: int = 0


# --- Durable attack-response analytics / agent memory -------------------
class PatchAttemptOutcome(StrEnum):
    AGENT_FAILED = "agent_failed"
    ORACLE_FAILED = "oracle_failed"
    ORACLE_PASSED = "oracle_passed"


class AttackResponseOutcome(StrEnum):
    AGENT_FAILED = "agent_failed"
    VERIFICATION_FAILED = "verification_failed"
    DEPLOYED = "deployed"


class DeploymentStatus(StrEnum):
    NOT_ATTEMPTED = "not_attempted"
    PUBLISHED = "published"


class AgentConnectionFailure(BaseModel):
    try_number: int
    ts: float
    error_type: str
    message: str


class AttackCaptureSummary(BaseModel):
    frame_count: int
    sha256: str
    rssi: int | None = None
    stats: AnomalyStats


class PatchAttemptLog(BaseModel):
    attempt_number: int
    started_ts: float
    completed_ts: float | None = None
    duration_ms: int | None = None
    outcome: PatchAttemptOutcome | None = None
    approach_summary: str = ""
    attack_class: str | None = None
    confidence: float | None = None
    agent_iterations: int = 0
    compiled: bool | None = None
    self_tpr: float | None = None
    self_fpr: float | None = None
    session_url: str | None = None
    filter_sha256: str | None = None
    filter_c_code: str | None = None
    oracle: OracleOut | None = None
    failure_reason: str | None = None
    connection_errors: list[AgentConnectionFailure] = Field(default_factory=list)


class AttackResponseSummary(BaseModel):
    attack_type: str
    successful_attempt: int | None = None
    successful_approach: str | None = None
    failed_approaches: list[str] = Field(default_factory=list)
    final_failure_reason: str | None = None


class DeploymentLog(BaseModel):
    status: DeploymentStatus = DeploymentStatus.NOT_ATTEMPTED
    started_ts: float | None = None
    completed_ts: float | None = None
    duration_ms: int | None = None
    firmware_version: str | None = None
    filter_sha256: str | None = None


class AttackResponseLog(BaseModel):
    schema_version: int = 1
    response_id: str
    incident_id: str
    node_id: str
    detected_ts: float
    response_started_ts: float
    completed_ts: float | None = None
    total_response_ms: int | None = None
    agent_backend: str = "unknown"
    initial_attack_guess: str
    capture: AttackCaptureSummary
    outcome: AttackResponseOutcome | None = None
    summary: AttackResponseSummary
    attempts: list[PatchAttemptLog] = Field(default_factory=list)
    deployment: DeploymentLog = Field(default_factory=DeploymentLog)
