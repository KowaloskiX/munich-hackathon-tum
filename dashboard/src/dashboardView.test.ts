import { describe, expect, it } from "vitest";

import { selectAttackHistory, selectAttackPackets, selectFrameFeed } from "./dashboardView";
import type { TimelineLine } from "./types";

const timeline: TimelineLine[] = [
  { id: 4, ts: 5, node_id: "esp-01", type: "VERIFYING", text: "esp-01 verifying filter", tone: "info" },
  {
    id: 3,
    ts: 4,
    node_id: "esp-01",
    type: "FILTER_GENERATED",
    text: "esp-01 filter generated: deauth_flood",
    tone: "info",
  },
  {
    id: 2,
    ts: 3,
    node_id: "esp-01",
    type: "ANOMALY_DETECTED",
    text: "esp-01 anomaly: 400 frames in window",
    tone: "warn",
  },
  {
    id: 1,
    ts: 2,
    node_id: "esp-02",
    type: "ANOMALY_DETECTED",
    text: "esp-02 anomaly: 21 frames in window",
    tone: "warn",
  },
];

describe("dashboard attack views", () => {
  it("caps the live feed without mutating its order", () => {
    expect(selectFrameFeed(timeline, 2).map((line) => line.id)).toEqual([4, 3]);
    expect(timeline).toHaveLength(4);
  });

  it("groups an anomaly with its packet count, identity, and latest Devin status", () => {
    const record = selectAttackHistory(timeline, null)[0];
    expect(record).toMatchObject({
      id: 2,
      ts: 3,
      nodeId: "esp-01",
      name: "Deauth flood",
      packetCount: 400,
      status: "Devin verifying",
    });
    // its own thread, oldest -> newest, scoped to this incident's node
    expect(record.events.map((e) => e.id)).toEqual([2, 3, 4]);
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
