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
