// Pure reducer: folds WS messages into dashboard state. No React, no I/O -
// so it is unit-testable in isolation (see reducer.test.ts).

import type { DashState, LiveEvent, NodeState, TimelineLine, WsMessage } from "./types";

export const initialState: DashState = {
  nodes: {},
  counters: { active_nodes: 0, threats_detected: 0, filters_deployed: 0, frames_blocked: 0 },
  timeline: [],
  stage: "idle",
  activeNode: null,
  activeAttack: null,
  agent: { iterations: null, self_tpr: null, self_fpr: null },
  agentStatus: null,
  error: null,
  seq: 0,
};

const PROGRESS_PREFIX = "⏳";

const STAGE_BY_TYPE: Partial<Record<LiveEvent["type"], DashState["stage"]>> = {
  ANOMALY_DETECTED: "trigger",
  AGENT_ANALYZING: "agent",
  VERIFYING: "verify",
  OTA_DEPLOYING: "ota",
  DEPLOYED: "done",
};

function describe(e: LiveEvent): { text: string; tone: TimelineLine["tone"] } {
  const p = e.payload;
  const node = e.node_id ?? "system";
  switch (e.type) {
    case "NODE_UP":
      return { text: `${node} online`, tone: "info" };
    case "NODE_DOWN":
      return { text: `${node} went offline`, tone: "bad" };
    case "ANOMALY_DETECTED":
      return { text: `${node} anomaly: ${p.count ?? "?"} frames in window`, tone: "warn" };
    case "AGENT_ANALYZING":
      return { text: `${node} agent analyzing (attempt ${p.attempt ?? 1})`, tone: "info" };
    case "AGENT_STEP":
      return { text: `${node} sandbox: ${p.text ?? ""}`, tone: "info" };
    case "FILTER_GENERATED": {
      const iters = p.iterations ? ` (${p.iterations} sandbox iters)` : "";
      return { text: `${node} filter generated: ${p.attack_class ?? "?"}${iters}`, tone: "info" };
    }
    case "VERIFYING":
      return { text: `${node} verifying filter (replay test)`, tone: "info" };
    case "VERIFY_FAILED":
      return { text: `${node} verify FAILED ${p.tests ?? ""} (fpr=${p.fpr ?? "?"})`, tone: "bad" };
    case "VERIFY_PASSED":
      return { text: `${node} verify PASSED ${p.tests ?? ""}`, tone: "ok" };
    case "OTA_DEPLOYING":
      return { text: `${node} deploying filter OTA`, tone: "info" };
    case "DEPLOYED":
      return { text: `${node} PROTECTED: ${p.attack_class ?? "filter"} deployed`, tone: "ok" };
    case "FRAME_BLOCKED":
      return { text: `${node} blocked ${p.count ?? 1} attack frames`, tone: "ok" };
    default:
      return { text: e.type, tone: "info" };
  }
}

function setNodeState(state: DashState, nodeId: string | null, ns: NodeState): DashState["nodes"] {
  if (!nodeId || !state.nodes[nodeId]) return state.nodes;
  return { ...state.nodes, [nodeId]: { ...state.nodes[nodeId], state: ns } };
}

export function reduce(state: DashState, msg: WsMessage): DashState {
  if (msg.type === "SNAPSHOT") {
    const nodes: DashState["nodes"] = {};
    for (const n of msg.payload.nodes) nodes[n.node_id] = n;
    return { ...state, nodes, counters: msg.payload.counters };
  }

  const e = msg;
  let nodes = state.nodes;
  const counters = { ...state.counters };
  let activeNode = state.activeNode;
  let activeAttack = state.activeAttack;
  let agent = state.agent;
  let agentStatus = state.agentStatus;
  let error = state.error;
  let appendLine = true;

  switch (e.type) {
    case "NODE_UP":
      if (e.node_id && !nodes[e.node_id]) {
        nodes = {
          ...nodes,
          [e.node_id]: {
            node_id: e.node_id,
            state: "NORMAL",
            last_seen: e.ts,
            fw_version: "v1",
            label: e.node_id,
            blocked: 0,
          },
        };
      }
      break;
    case "NODE_DOWN":
      nodes = setNodeState(state, e.node_id, "OFFLINE");
      break;
    case "ANOMALY_DETECTED":
      nodes = setNodeState(state, e.node_id, "ALERT");
      counters.threats_detected += 1;
      activeNode = e.node_id;
      agent = { iterations: null, self_tpr: null, self_fpr: null };
      agentStatus = null;
      error = null;
      break;
    case "AGENT_STEP": {
      const text = String(e.payload.text ?? "");
      if (text.startsWith(PROGRESS_PREFIX)) {
        agentStatus = text; // live status — do not spam the timeline
        appendLine = false;
      } else if (text.toLowerCase().includes("unavailable")) {
        error = text; // agent unreachable — surface loudly
      }
      break;
    }
    case "FILTER_GENERATED":
      activeAttack = (e.payload.attack_class as string) ?? activeAttack;
      agent = {
        iterations: (e.payload.iterations as number) ?? null,
        self_tpr: (e.payload.self_tpr as number) ?? null,
        self_fpr: (e.payload.self_fpr as number) ?? null,
      };
      break;
    case "OTA_DEPLOYING":
      nodes = setNodeState(state, e.node_id, "UPDATING");
      break;
    case "DEPLOYED":
      nodes = setNodeState(state, e.node_id, "PROTECTED");
      counters.filters_deployed += 1;
      agentStatus = null; // done working
      break;
    case "FRAME_BLOCKED": {
      const c = Number(e.payload.count ?? 1);
      counters.frames_blocked += c;
      if (e.node_id && nodes[e.node_id]) {
        nodes = {
          ...nodes,
          [e.node_id]: { ...nodes[e.node_id], blocked: nodes[e.node_id].blocked + c },
        };
      }
      break;
    }
    default:
      break;
  }

  counters.active_nodes = Object.values(nodes).filter((n) => n.state !== "OFFLINE").length;

  const stage = STAGE_BY_TYPE[e.type] ?? state.stage;
  let timeline = state.timeline;
  if (appendLine) {
    const { text, tone } = describe(e);
    const line: TimelineLine = { id: state.seq, ts: e.ts, node_id: e.node_id, type: e.type, text, tone };
    timeline = [line, ...state.timeline].slice(0, 60);
  }

  return {
    ...state,
    nodes,
    counters,
    timeline,
    stage,
    activeNode,
    activeAttack,
    agent,
    agentStatus,
    error,
    seq: state.seq + 1,
  };
}
