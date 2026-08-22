import { describe, expect, it } from "vitest";

import { getWorkflowView, selectFrameFeed, selectLatestAnomaly } from "./dashboardView";
import type { TimelineLine } from "./types";

const timeline: TimelineLine[] = [
  {
    id: 2,
    ts: 3,
    node_id: "esp-01",
    type: "FRAME_BLOCKED",
    text: "esp-01 blocked 1,240 attack frames",
    tone: "ok",
  },
  {
    id: 1,
    ts: 2,
    node_id: "esp-01",
    type: "ANOMALY_DETECTED",
    text: "esp-01 anomaly — 400 frames in window",
    tone: "warn",
  },
  {
    id: 0,
    ts: 1,
    node_id: "esp-02",
    type: "FRAME_BLOCKED",
    text: "esp-02 blocked 4 attack frames",
    tone: "ok",
  },
];

describe("dashboard frame views", () => {
  it("caps the unfiltered feed without mutating its order", () => {
    expect(selectFrameFeed(timeline, 2).map((line) => line.id)).toEqual([2, 1]);
    expect(timeline).toHaveLength(3);
  });

  it("selects one latest anomaly for the demo focus", () => {
    expect(selectLatestAnomaly(timeline)).toMatchObject({ id: 1, node_id: "esp-01", type: "ANOMALY_DETECTED" });
  });

  it("assigns detection and Devin activity to the live workflow stage", () => {
    expect(getWorkflowView("trigger", null)).toMatchObject({ detectorActive: true, devinActive: false });
    expect(getWorkflowView("agent", "deauth_flood")).toMatchObject({
      devinActive: true,
      retryActive: true,
      devinStatus: "Generating deauth_flood",
    });
    expect(getWorkflowView("verify", "deauth_flood")).toMatchObject({
      devinActive: true,
      retryActive: true,
      devinStatus: "Running oracle replay",
    });
    expect(getWorkflowView("ota", "deauth_flood")).toMatchObject({
      devinActive: true,
      retryActive: false,
      devinStatus: "Deploying verified policy",
    });
  });
});
