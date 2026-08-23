import { afterEach, describe, expect, it, vi } from "vitest";

import { flushFixes } from "./api";

afterEach(() => {
  vi.restoreAllMocks();
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
