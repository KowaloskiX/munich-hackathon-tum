import { describe, expect, it } from "vitest";

import { emailVerdictLabel, formatRiskScore, newestEmailsFirst, pendingEmailCount } from "./emailView";
import type { EmailAnalysisSummary } from "./types";

function item(status: EmailAnalysisSummary["status"]): EmailAnalysisSummary {
  return {
    id: 1,
    gmail_message_id: "m1",
    from_address: "sender@example.com",
    subject: "subject",
    snippet: "snippet",
    received_at: 1,
    status,
    verdict: status === "CLEAR" ? "CLEAR" : "FLAGGED",
    risk_score: 80,
    review_decision: null,
  };
}

describe("email review view", () => {
  it("counts pending and failed analyses as requiring review", () => {
    expect(pendingEmailCount([item("PENDING_REVIEW"), item("FAILED"), item("CLEAR")])).toBe(2);
  });

  it("uses the human decision as the authoritative label", () => {
    const reviewed = { ...item("REVIEWED"), review_decision: "NOT_DANGEROUS" as const };
    expect(emailVerdictLabel(reviewed)).toBe("Not dangerous");
  });

  it("formats risk as an explicit score out of 100", () => {
    expect(formatRiskScore(80)).toBe("80/100");
    expect(formatRiskScore(null)).toBe("—");
  });

  it("orders emails newest to oldest without mutating the source", () => {
    const source = [item("CLEAR"), { ...item("QUEUED"), id: 2, received_at: 3 }];
    const ordered = newestEmailsFirst(source);
    expect(ordered.map((email) => email.id)).toEqual([2, 1]);
    expect(source.map((email) => email.id)).toEqual([1, 2]);
  });
});
