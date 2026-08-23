import { afterEach, describe, expect, it, vi } from "vitest";

import { apiBase, emailLiveUrl, liveUrl } from "./api";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("local backend URLs", () => {
  it("uses the page hostname for REST and WebSocket calls", () => {
    vi.stubGlobal("window", { location: { hostname: "127.0.0.1" } });

    expect(apiBase()).toBe("http://127.0.0.1:8000");
    expect(liveUrl()).toBe("ws://127.0.0.1:8000/live");
    expect(emailLiveUrl()).toBe("ws://127.0.0.1:8000/v1/email/live");
  });
});
