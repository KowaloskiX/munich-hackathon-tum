// Pure reducer: folds WS messages into dashboard state. No React, no I/O —
// so it is unit-testable in isolation (see reducer.test.ts).

import type { DashState, LiveEvent, NodeState, TimelineLine, WsMessage } from "./types";

export const initialState: DashState = {
  nodes: {},
  counters: { active_nodes: 0, threats_detected: 0, filters_deployed: 0, frames_blocked: 0 },
  timeline: [],
  stage: "idle",
  activeNode: null,
  activeAttack: null,
  seq: 0,
};

const STAGE_BY_TYPE: Partial<Record<LiveEvent["type"], DashState["stage"]>> = {
  ANOMALY_DETECTED: "trigger",
  AGENT_ANALYZING: "agent",
  VERIFYING: "verify",
  OTA_DEPLOYING: "ota",
  DEPLOYED: "done",
};

function describe(e: LiveEvent): { text: string; tone: TimelineLine["tone"] } {
  const p = e.payload;
  const node = e.node_id ?? "—";
  switch (e.type) {
    case "NODE_UP":
      return { text: `${node} online`, tone: "info" };
    case "NODE_DOWN":
      return { text: `${node} went offline`, tone: "bad" };
    case "ANOMALY_DETECTED":
      return { text: `${node} anomaly — ${p.count ?? "?"} frames in window`, tone: "warn" };
    case "AGENT_ANALYZING":
      return { text: `${node} agent analyzing (attempt ${p.attempt ?? 1})`, tone: "info" };
    case "FILTER_GENERATED":
      return { text: `${node} filter generated — ${p.attack_class ?? "?"}`, tone: "info" };
    case "VERIFYING":
      return { text: `${node} verifying filter (replay test)`, tone: "info" };
    case "VERIFY_FAILED":
      return { text: `${node} verify FAILED ${p.tests ?? ""} (fpr=${p.fpr ?? "?"})`, tone: "bad" };
    case "VERIFY_PASSED":
      return { text: `${node} verify PASSED ${p.tests ?? ""}`, tone: "ok" };
    case "OTA_DEPLOYING":
      return { text: `${node} deploying filter OTA`, tone: "info" };
    case "DEPLOYED":
      return { text: `${node} PROTECTED — ${p.attack_class ?? "filter"} deployed`, tone: "ok" };
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
      break;
    case "FILTER_GENERATED":
      activeAttack = (e.payload.attack_class as string) ?? activeAttack;
      break;
    case "OTA_DEPLOYING":
      nodes = setNodeState(state, e.node_id, "UPDATING");
      break;
    case "DEPLOYED":
      nodes = setNodeState(state, e.node_id, "PROTECTED");
      counters.filters_deployed += 1;
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
  const { text, tone } = describe(e);
  const line: TimelineLine = { id: state.seq, ts: e.ts, node_id: e.node_id, type: e.type, text, tone };
  const timeline = [line, ...state.timeline].slice(0, 60);

  return { ...state, nodes, counters, timeline, stage, activeNode, activeAttack, seq: state.seq + 1 };
}
