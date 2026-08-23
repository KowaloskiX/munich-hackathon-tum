import type { EmailAnalysisSummary } from "./types";

export function emailVerdictLabel(item: EmailAnalysisSummary): string {
  if (item.review_decision === "CONFIRMED_DANGEROUS") return "Confirmed dangerous";
  if (item.review_decision === "NOT_DANGEROUS") return "Not dangerous";
  if (item.status === "PENDING_REVIEW" || item.status === "FAILED") return "Needs review";
  if (item.status === "ANALYZING") return "INBOX analyzing";
  if (item.status === "QUEUED") return "Queued";
  return item.verdict === "CLEAR" ? "Clear" : item.status.toLowerCase();
}

export function pendingEmailCount(items: EmailAnalysisSummary[]): number {
  return items.filter((item) => item.status === "PENDING_REVIEW" || item.status === "FAILED").length;
}

export function formatRiskScore(score: number | null): string {
  return score === null ? "—" : `${score}/100`;
}

export function newestEmailsFirst<T extends { received_at: number }>(items: readonly T[]): T[] {
  return [...items].sort((left, right) => right.received_at - left.received_at);
}
