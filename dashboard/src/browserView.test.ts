import { describe, expect, it } from "vitest";

import { linkPhaseIndex, linkVerdictFromEvent } from "./browserView";
import type { LinkLiveEvent } from "./browserView";

describe("browser security view", () => {
  it("tracks the autonomous scan phases in order", () => {
    expect(linkPhaseIndex("LINK_SUBMITTED")).toBe(0);
    expect(linkPhaseIndex("LINK_RESEARCHING")).toBe(2);
    expect(linkPhaseIndex("LINK_VERDICT")).toBe(3);
  });

  it("creates a bounded verdict from a live event", () => {
    const event: LinkLiveEvent = {
      type: "LINK_VERDICT",
      node_id: null,
      ts: 1,
      payload: { url: "https://paypal-login.pages.dev", verdict: "malicious", legit_score: -1, brand: "paypal.com", signals: ["throwaway host"] },
    };
    expect(linkVerdictFromEvent(event)).toMatchObject({
      verdict: "malicious",
      legit_score: 0,
      impersonated_brand: "paypal.com",
      top_signals: ["throwaway host"],
    });
  });
});
