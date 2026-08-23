import type { EventType, TimelineLine } from "./types";

export type AttackStatus =
  | "Signal processing"
  | "Signal fixing"
  | "Signal verifying"
  | "Signal deploying"
  | "Fix deployed";

export interface AttackRecord {
  id: number;
  ts: number;
  nodeId: string;
  name: string;
  packetCount: number;
  status: AttackStatus;
}

export interface AttackPacket {
  id: string;
  nodeId: string;
  frameType: string;
  match: string;
}

const STATUS_BY_EVENT: Partial<Record<EventType, AttackStatus>> = {
  ANOMALY_DETECTED: "Signal processing",
  AGENT_ANALYZING: "Signal processing",
  FILTER_GENERATED: "Signal fixing",
  VERIFYING: "Signal verifying",
  VERIFY_FAILED: "Signal verifying",
  VERIFY_PASSED: "Signal verifying",
  OTA_DEPLOYING: "Signal deploying",
  DEPLOYED: "Fix deployed",
  FRAME_BLOCKED: "Fix deployed",
};

export function selectFrameFeed(timeline: TimelineLine[], limit: number): TimelineLine[] {
  return timeline.slice(0, Math.max(0, limit));
}

function parsePacketCount(text: string): number {
  const match = text.match(/([\d,]+)\s+(?:attack\s+)?frames?/i);
  return match ? Number(match[1].replaceAll(",", "")) : 1;
}

function parseAttackClass(lines: TimelineLine[]): string | undefined {
  const generated = lines.find((line) => line.type === "FILTER_GENERATED");
  return generated?.text.match(/generated:\s*([a-z\d_ -]+)/i)?.[1]?.trim();
}

function formatAttackName(value?: string | null): string {
  if (!value) return "Frame flood";
  const words = value.replaceAll("_", " ").trim();
  return words.charAt(0).toUpperCase() + words.slice(1);
}

export function selectAttackHistory(timeline: TimelineLine[], activeAttack: string | null): AttackRecord[] {
  const anomalyIndexes = timeline.flatMap((line, index) => (line.type === "ANOMALY_DETECTED" ? [index] : []));

  return anomalyIndexes.map((index, attackIndex) => {
    const segmentStart = attackIndex === 0 ? 0 : anomalyIndexes[attackIndex - 1] + 1;
    const anomaly = timeline[index];
    const related = timeline
      .slice(segmentStart, index + 1)
      .filter((line) => line.node_id === anomaly.node_id);
    const status = related.map((line) => STATUS_BY_EVENT[line.type]).find(Boolean) ?? "Signal processing";
    const attackClass = parseAttackClass(related) ?? (attackIndex === 0 ? activeAttack : null);

    return {
      id: anomaly.id,
      ts: anomaly.ts,
      nodeId: anomaly.node_id ?? "system",
      name: formatAttackName(attackClass),
      packetCount: parsePacketCount(anomaly.text),
      status,
    };
  });
}

export function selectAttackPackets(attack: AttackRecord, limit = 6): AttackPacket[] {
  const count = Math.min(Math.max(0, limit), attack.packetCount);
  const frameType = /deauth/i.test(attack.name) ? "Deauthentication" : "Matched frame";

  return Array.from({ length: count }, (_, index) => ({
    id: `PKT-${String(attack.id).padStart(4, "0")}-${String(index + 1).padStart(3, "0")}`,
    nodeId: attack.nodeId,
    frameType,
    match: "Linked signature",
  }));
}
