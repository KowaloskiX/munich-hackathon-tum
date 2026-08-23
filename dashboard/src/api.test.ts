import { afterEach, describe, expect, it, vi } from "vitest";

import { apiBase, emailLiveUrl, flushFixes, liveUrl } from "./api";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("local backend URLs", () => {
  it("uses the page hostname for REST and WebSocket calls", () => {
    vi.stubGlobal("window", { location: { hostname: "127.0.0.1" } });

    expect(apiBase()).toBe("http://127.0.0.1:8000");
    expect(liveUrl()).toBe("ws://127.0.0.1:8000/live");
    expect(emailLiveUrl()).toBe("ws://127.0.0.1:8000/v1/email/live");
  });
});

describe("flushFixes", () => {
  it("posts to the demo reset endpoint", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ status: "reset", nodes_preserved: 1 }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    await expect(flushFixes()).resolves.toEqual({ status: "reset", nodes_preserved: 1 });
    expect(fetchMock).toHaveBeenCalledWith("http://localhost:8000/demo/reset", { method: "POST" });
  });

  it("rejects when the reset endpoint fails", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(null, { status: 502 }));

    await expect(flushFixes()).rejects.toThrow("Reset failed (502)");
  });
});
