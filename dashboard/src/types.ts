// Mirror of backend contracts (ARCHITECTURE.md §4). Keep in sync with
// backend/app/models.py - do not diverge without updating both sides.

export type NodeState = "NORMAL" | "ALERT" | "PROTECTED" | "UPDATING" | "OFFLINE";

export type EventType =
  | "NODE_UP"
  | "NODE_DOWN"
  | "ANOMALY_DETECTED"
  | "AGENT_ANALYZING"
  | "AGENT_STEP"
  | "FILTER_GENERATED"
  | "VERIFYING"
  | "VERIFY_FAILED"
  | "VERIFY_PASSED"
  | "OTA_DEPLOYING"
  | "DEPLOYED"
  | "FRAME_BLOCKED";

export interface NodeView {
  node_id: string;
  state: NodeState;
  last_seen: number;
  fw_version: string;
  label: string;
  blocked: number;
}

export interface Counters {
  active_nodes: number;
  threats_detected: number;
  filters_deployed: number;
  frames_blocked: number;
}

export interface FleetSnapshot {
  nodes: NodeView[];
  counters: Counters;
}

export interface LiveEvent {
  type: EventType;
  node_id: string | null;
  ts: number;
  payload: Record<string, unknown>;
}

// The bootstrap frame the server sends first on /live.
export interface SnapshotMessage {
  type: "SNAPSHOT";
  payload: FleetSnapshot;
}

export type WsMessage = LiveEvent | SnapshotMessage;

// Pipeline stages for the loop animation.
export type Stage = "idle" | "trigger" | "agent" | "verify" | "ota" | "done";

export interface TimelineLine {
  id: number;
  ts: number;
  node_id: string | null;
  type: EventType;
  text: string;
  tone: "info" | "warn" | "ok" | "bad";
  incidentId: string | null; // server incident id, for the report download
}

export interface AgentInfo {
  iterations: number | null;
  self_tpr: number | null;
  self_fpr: number | null;
}

export interface DashState {
  nodes: Record<string, NodeView>;
  counters: Counters;
  timeline: TimelineLine[];
  stage: Stage;
  activeNode: string | null;
  activeAttack: string | null;
  agent: AgentInfo;
  agentStatus: string | null; // live heartbeat while the agent works
  error: string | null; // set when the agent is unreachable
  seq: number;
}

export type EmailMonitoringMode = "ALL" | "SELECTED";
export type EmailAnalysisStatus = "QUEUED" | "ANALYZING" | "CLEAR" | "PENDING_REVIEW" | "FAILED" | "REVIEWED";
export type EmailVerdict = "CLEAR" | "FLAGGED" | "INCONCLUSIVE";
export type EmailReviewDecision = "CONFIRMED_DANGEROUS" | "NOT_DANGEROUS";
export type EmailEventType =
  | "EMAIL_RECEIVED"
  | "EMAIL_ANALYSIS_STARTED"
  | "EMAIL_ANALYSIS_COMPLETED"
  | "EMAIL_FLAGGED"
  | "EMAIL_ANALYSIS_FAILED"
  | "EMAIL_REVIEWED"
  | "GMAIL_CONNECTION_CHANGED";

export interface EmailLabels {
  scan: string;
  pending_review: string;
  confirmed_dangerous: string;
  not_dangerous: string;
}

export interface EmailConnectionStatus {
  connected: boolean;
  email: string | null;
  mode: EmailMonitoringMode;
  watch_expiration: number | null;
  last_sync: number | null;
  labels: EmailLabels;
  csrf_token: string | null;
}

export interface EmailSettingsUpdate {
  mode: EmailMonitoringMode;
}

export interface ThreatReason {
  category: string;
  severity: string;
  evidence: string;
  artifact_ref: string | null;
}

export interface ThreatCheck {
  artifact: string;
  action: string;
  result: string;
  why: string;
}

export interface ThreatReport {
  verdict: EmailVerdict;
  risk_score: number;
  confidence: number;
  summary: string;
  reasons: ThreatReason[];
  checks: ThreatCheck[];
  recommended_actions: string[];
}

export interface EmailAnalysisSummary {
  id: number;
  gmail_message_id: string;
  from_address: string;
  subject: string;
  snippet: string;
  received_at: number;
  status: EmailAnalysisStatus;
  verdict: EmailVerdict | null;
  risk_score: number | null;
  review_decision: EmailReviewDecision | null;
}

export interface EmailAnalysisDetail {
  id: number;
  gmail_message_id: string;
  from_address: string;
  subject: string;
  snippet: string;
  received_at: number;
  status: EmailAnalysisStatus;
  verdict: EmailVerdict | null;
  risk_score: number | null;
  review_decision: EmailReviewDecision | null;
  report: ThreatReport | null;
  devin_session_url: string | null;
  error: string | null;
}

export interface EmailAnalysisList {
  items: EmailAnalysisSummary[];
  next_cursor: number | null;
}

export interface EmailMessagePreview {
  gmail_message_id: string;
  from_address: string;
  subject: string;
  snippet: string;
  received_at: number;
  already_imported: boolean;
}

export interface EmailMessagePreviewList {
  items: EmailMessagePreview[];
  next_page_token: string | null;
}

export interface EmailImportRequest {
  message_ids: string[];
  limit: number | null;
}

export interface EmailImportResult {
  scanned: number;
  imported: number;
  duplicates: number;
}

export interface EmailReviewRequest {
  decision: EmailReviewDecision;
}

export interface EmailLiveEvent {
  type: EmailEventType;
  analysis_id: number | null;
  ts: number;
  message: string;
}

export interface LinkScanIn {
  url: string;
  source: string;
}

export type LinkVerdictName = "legit" | "suspicious" | "malicious";

export interface LinkVerdict {
  url: string;
  verdict: LinkVerdictName;
  legit_score: number;
  impersonated_brand: string;
  top_signals: string[];
  reasoning: string;
  browse_score: number | null;
  research_score: number | null;
}
