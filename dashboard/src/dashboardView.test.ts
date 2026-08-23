import { describe, expect, it } from "vitest";

import { selectAttackHistory, selectAttackPackets, selectFrameFeed } from "./dashboardView";
import type { TimelineLine } from "./types";

const timeline: TimelineLine[] = [
  {
    id: 4,
    ts: 5,
    node_id: "esp-01",
    type: "VERIFYING",
    text: "esp-01 verifying filter",
    tone: "info",
    incidentId: "inc-0001",
  },
  {
    id: 3,
    ts: 4,
    node_id: "esp-01",
    type: "FILTER_GENERATED",
    text: "esp-01 filter generated: deauth_flood",
    tone: "info",
    incidentId: "inc-0001",
  },
  {
    id: 2,
    ts: 3,
    node_id: "esp-01",
    type: "ANOMALY_DETECTED",
    text: "esp-01 anomaly: 400 frames in window",
    tone: "warn",
    incidentId: "inc-0001",
  },
  {
    id: 1,
    ts: 2,
    node_id: "esp-02",
    type: "ANOMALY_DETECTED",
    text: "esp-02 anomaly: 21 frames in window",
    tone: "warn",
    incidentId: "inc-0002",
  },
];

describe("dashboard attack views", () => {
  it("shows the most recent frames oldest-first without mutating the source", () => {
    // newest two are ids 4,3 (timeline is newest-first) -> displayed 3 then 4
    expect(selectFrameFeed(timeline, 2).map((line) => line.id)).toEqual([3, 4]);
    expect(timeline).toHaveLength(4);
    expect(timeline[0].id).toBe(4); // source order untouched
  });

  it("groups an anomaly with its packet count, identity, and latest Devin status", () => {
    const record = selectAttackHistory(timeline, null)[0];
    expect(record).toMatchObject({
      id: 2,
      incidentId: "inc-0001",
      ts: 3,
      nodeId: "esp-01",
      name: "Deauth flood",
      packetCount: 400,
      status: "Signal verifying",
    });
    // its own thread, oldest -> newest, scoped to this incident's node
    expect(record.events.map((e) => e.id)).toEqual([2, 3, 4]);
  });

  it("does not reuse the previous attack label while Devin analyzes a new incident", () => {
    const next: TimelineLine = {
      id: 5,
      ts: 6,
      node_id: "esp-01",
      type: "ANOMALY_DETECTED",
      text: "esp-01 anomaly: 50 frames in window",
      tone: "warn",
      incidentId: "inc-0003",
    };

    const record = selectAttackHistory([next, ...timeline], "deauth_flood")[0];
    expect(record.name).toBe("Analyzing frame flow");
    expect(record.events.map((event) => event.incidentId)).toEqual(["inc-0003"]);
  });

  it("builds a bounded packet sample linked to an attack", () => {
    const attack = selectAttackHistory(timeline, null)[0];
    expect(selectAttackPackets(attack, 2)).toEqual([
      {
        id: "PKT-0002-001",
        nodeId: "esp-01",
        frameType: "Deauthentication",
        match: "Linked signature",
      },
      {
        id: "PKT-0002-002",
        nodeId: "esp-01",
        frameType: "Deauthentication",
        match: "Linked signature",
      },
    ]);
  });
});
