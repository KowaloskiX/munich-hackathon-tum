import { describe, expect, it } from "vitest";

import { hashForRoute, routeFromHash } from "./routes";

describe("app routes", () => {
  it("maps agent hashes to their product surfaces", () => {
    expect(routeFromHash("#/network")).toBe("network");
    expect(routeFromHash("#/phishing")).toBe("phishing");
    expect(routeFromHash("#/mail")).toBe("mail");
    expect(routeFromHash("#/command")).toBe("command");
  });

  it("falls back to the landing page for unknown routes", () => {
    expect(routeFromHash("#/not-real")).toBe("home");
    expect(routeFromHash("")).toBe("home");
    expect(hashForRoute("home")).toBe("#/");
  });
});
