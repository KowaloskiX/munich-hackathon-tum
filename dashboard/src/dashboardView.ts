import type { Stage, TimelineLine } from "./types";

export function selectFrameFeed(timeline: TimelineLine[], limit: number): TimelineLine[] {
  return timeline.slice(0, Math.max(0, limit));
}

export function selectLatestAnomaly(timeline: TimelineLine[]): TimelineLine | undefined {
  return timeline.find((line) => line.type === "ANOMALY_DETECTED");
}

export interface WorkflowView {
  detectorActive: boolean;
  devinActive: boolean;
  retryActive: boolean;
  devinStatus: string;
}

export function getWorkflowView(stage: Stage, attack: string | null): WorkflowView {
  return {
    detectorActive: stage === "trigger",
    devinActive: stage === "agent" || stage === "verify" || stage === "ota",
    retryActive: Boolean(attack) && (stage === "agent" || stage === "verify"),
    devinStatus:
      stage === "verify"
        ? "Running oracle replay"
        : stage === "ota"
          ? "Deploying verified policy"
          : stage === "agent"
            ? `Generating ${attack ?? "new filter"}`
            : "Ready for anomaly context",
  };
}
