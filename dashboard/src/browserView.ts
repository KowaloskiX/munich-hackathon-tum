import type { LinkVerdict, LinkVerdictName } from "./types";

export const LINK_PHASES = ["LINK_SUBMITTED", "LINK_BROWSING", "LINK_RESEARCHING", "LINK_VERDICT"] as const;
export type LinkPhase = (typeof LINK_PHASES)[number];

export interface LinkLiveEvent {
  type: LinkPhase;
  node_id: string | null;
  ts: number;
  payload: Record<string, unknown>;
}

export function isLinkEvent(type: string): type is LinkPhase {
  return LINK_PHASES.includes(type as LinkPhase);
}

export function linkPhaseIndex(type: string | null): number {
  return type === null ? -1 : LINK_PHASES.indexOf(type as LinkPhase);
}

export function linkVerdictFromEvent(event: LinkLiveEvent): LinkVerdict | null {
  if (event.type !== "LINK_VERDICT") return null;
  const verdict = event.payload.verdict;
  const score = Number(event.payload.legit_score);
  if ((verdict !== "legit" && verdict !== "suspicious" && verdict !== "malicious") || !Number.isFinite(score)) {
    return null;
  }
  const signals = Array.isArray(event.payload.signals)
    ? event.payload.signals.filter((signal): signal is string => typeof signal === "string")
    : [];
  return {
    url: String(event.payload.url ?? ""),
    verdict: verdict as LinkVerdictName,
    legit_score: Math.min(1, Math.max(0, score)),
    impersonated_brand: String(event.payload.brand ?? ""),
    top_signals: signals,
    reasoning: signals.join(" · "),
    browse_score: null,
    research_score: null,
    browse_session_url: null,
    research_session_url: null,
    browse_result: {},
    research_result: {},
  };
}
