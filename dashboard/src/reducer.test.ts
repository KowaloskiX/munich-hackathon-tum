import { describe, expect, it } from "vitest";

import { initialState, reduce } from "./reducer";
import type { LiveEvent, SnapshotMessage } from "./types";

function ev(type: LiveEvent["type"], node_id: string | null, payload: Record<string, unknown> = {}): LiveEvent {
  return { type, node_id, ts: 1, payload };
}

const snapshot: SnapshotMessage = {
  type: "SNAPSHOT",
  payload: {
    nodes: [
      { node_id: "esp-01", state: "NORMAL", last_seen: 0, fw_version: "v1", label: "esp-01", blocked: 0 },
    ],
    counters: { active_nodes: 1, threats_detected: 0, filters_deployed: 0, frames_blocked: 0 },
  },
};

describe("reducer", () => {
  it("folds the full loop into node state + counters", () => {
    let s = reduce(initialState, snapshot);
    s = reduce(s, ev("ANOMALY_DETECTED", "esp-01", { count: 200 }));
    expect(s.nodes["esp-01"].state).toBe("ALERT");
    expect(s.counters.threats_detected).toBe(1);

    s = reduce(s, ev("OTA_DEPLOYING", "esp-01"));
    expect(s.nodes["esp-01"].state).toBe("UPDATING");

    s = reduce(s, ev("DEPLOYED", "esp-01", { attack_class: "deauth_flood" }));
    expect(s.nodes["esp-01"].state).toBe("PROTECTED");
    expect(s.counters.filters_deployed).toBe(1);
    expect(s.stage).toBe("done");

    s = reduce(s, ev("FRAME_BLOCKED", "esp-01", { count: 42 }));
    expect(s.counters.frames_blocked).toBe(42);
    expect(s.nodes["esp-01"].blocked).toBe(42);
  });

  it("greys a node on NODE_DOWN and drops active count", () => {
    let s = reduce(initialState, snapshot);
    expect(s.counters.active_nodes).toBe(1);
    s = reduce(s, ev("NODE_DOWN", "esp-01"));
    expect(s.nodes["esp-01"].state).toBe("OFFLINE");
    expect(s.counters.active_nodes).toBe(0);
  });

  it("streams AGENT_STEP into the timeline as sandbox activity", () => {
    let s = reduce(initialState, snapshot);
    s = reduce(s, ev("AGENT_STEP", "esp-01", { text: "compiled filter.c with gcc" }));
    expect(s.timeline[0].text).toContain("sandbox");
    expect(s.timeline[0].text).toContain("compiled filter.c");
  });

  it("shows progress as a live status without spamming the timeline", () => {
    let s = reduce(initialState, snapshot);
    const before = s.timeline.length;
    s = reduce(s, ev("AGENT_STEP", "esp-01", { text: "⏳ Devin working 20s (working)" }));
    expect(s.agentStatus).toContain("Devin working 20s");
    expect(s.timeline.length).toBe(before); // not appended
  });

  it("surfaces an unreachable agent as a loud error", () => {
    let s = reduce(initialState, snapshot);
    s = reduce(s, ev("AGENT_STEP", "esp-01", { text: "agent unavailable: could not resolve host" }));
    expect(s.error).toContain("unavailable");
    // cleared when a fresh anomaly starts
    s = reduce(s, ev("ANOMALY_DETECTED", "esp-01", { count: 1 }));
    expect(s.error).toBeNull();
  });

  it("captures Devin sandbox self-test from FILTER_GENERATED", () => {
    let s = reduce(initialState, snapshot);
    s = reduce(s, ev("ANOMALY_DETECTED", "esp-01", { count: 5 }));
    expect(s.agent.iterations).toBeNull(); // reset when a new anomaly starts
    s = reduce(
      s,
      ev("FILTER_GENERATED", "esp-01", {
        attack_class: "deauth_flood",
        iterations: 3,
        self_tpr: 1.0,
        self_fpr: 0.0,
      }),
    );
    expect(s.agent.iterations).toBe(3);
    expect(s.agent.self_tpr).toBe(1.0);
    expect(s.activeAttack).toBe("deauth_flood");
  });
});
