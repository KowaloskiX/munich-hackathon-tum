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
  | "FRAME_BLOCKED"
  | "LINK_SUBMITTED"
  | "LINK_BROWSING"
  | "LINK_RESEARCHING"
  | "LINK_VERDICT"
  | "INCIDENT_CREATED";

export type IncidentSource = "EMAIL" | "LINK" | "ESP";
export type IncidentSeverity = "INFO" | "WARNING" | "CRITICAL";

export interface Incident {
  id: number;
  ts: number;
  source: IncidentSource;
  severity: IncidentSeverity;
  title: string;
  summary: string;
  verdict: string;
  risk_score: number | null;
  status: string;
  ref: string;
  url: string;
}

export interface IncidentList {
  items: Incident[];
  next_cursor: number | null;
}

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

export interface AnomalyStats {
  frame_type: string;
  subtype: number | null;
  channel: number | null;
  count_in_window: number;
  window_ms: number;
}

export interface AnomalyIn {
  node_id: string;
  timestamp: number;
  frame_hex: string[];
  rssi: number | null;
  bssid: string | null;
  sender_mac: string | null;
  anomaly_stats: AnomalyStats;
  guessed_type: string | null;
}

export interface DemoResetResult {
  status: "reset";
  nodes_preserved: number;
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
  feed: Incident[]; // unified cross-domain feed (email + link + esp)
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

export type EvidenceSource = "SIGNAL" | "INBOX" | "SCOPE";
export type EvidenceProvenance = "LIVE" | "DEMO";

export interface EvidenceEntities {
  domains: string[];
  urls: string[];
  ips: string[];
  macs: string[];
  emails: string[];
  brands: string[];
}

export interface IntelligenceObservation {
  id: number;
  occurred_ts: number;
  recorded_ts: number;
  source: EvidenceSource;
  event_type: string;
  severity: IncidentSeverity;
  title: string;
  summary: string;
  verdict: string;
  risk_score: number | null;
  entities: EvidenceEntities;
  source_ref: string;
  provenance: EvidenceProvenance;
  evidence: Record<string, unknown>;
}

export interface CommandMetrics {
  window_end_ts: number;
  email_current_total: number;
  email_current_flagged: number;
  email_baseline_total: number;
  email_baseline_flagged: number;
  current_flagged_rate: number;
  baseline_flagged_rate: number;
  phishing_spike: boolean;
  signal_incidents: number;
  malicious_scope_checks: number;
  shared_entities: string[];
}

export interface CommandCorrelation {
  claim: string;
  confidence: number;
  evidence_ids: number[];
  explanation: string;
}

export interface AttackerContextFinding {
  entity: string;
  finding: string;
  confidence: number;
  evidence_ids: number[];
  sources: string[];
}

export interface EmployeeAdvisory {
  needed: boolean;
  subject: string;
  body: string;
}

export interface CommandAssessmentSummary {
  id: number;
  created_ts: number;
  completed_ts: number | null;
  status: string;
  decision: string;
  reason: string;
  report_id: string | null;
  session_url: string | null;
  error: string | null;
}

export interface CommandReportSummary {
  id: string;
  created_ts: number;
  title: string;
  urgency: string;
  executive_summary: string;
  confidence: number;
  provenance: EvidenceProvenance;
}

export interface CommandReport {
  id: string;
  created_ts: number;
  title: string;
  urgency: string;
  executive_summary: string;
  confidence: number;
  provenance: EvidenceProvenance;
  trigger_reason: string;
  what_happened: string[];
  cause_analysis: string[];
  correlations: CommandCorrelation[];
  attacker_context: AttackerContextFinding[];
  actions_taken: string[];
  recommendations: string[];
  evidence_ids: number[];
  metrics: CommandMetrics;
  employee_advisory: EmployeeAdvisory;
  devin_session_url: string | null;
  evidence_sha256: string;
}

export interface CommandOverview {
  assessing: boolean;
  metrics: CommandMetrics;
  observations: IntelligenceObservation[];
  assessments: CommandAssessmentSummary[];
  reports: CommandReportSummary[];
}

export interface CommandDemoSeedResult {
  inserted: number;
  trigger_observation_id: number;
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
  browse_session_url: string | null;
  research_session_url: string | null;
  browse_result: Record<string, unknown>;
  research_result: Record<string, unknown>;
}
