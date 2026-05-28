import { describe, it, expect, vi } from "vitest";
import { CompanionClient } from "../src/companionClient.js";
import type { CapturePayload } from "../src/types.js";

const payload: CapturePayload = {
  caseId: "c1", timestamp: "2026-05-28T10:00:00.000Z", url: "u", tabTitle: "t",
  triggerType: "timer", imageBase64: "AAAA",
};

describe("CompanionClient", () => {
  it("postCapture returns true on 201", async () => {
    const fetchFn = vi.fn(async () => new Response("{}", { status: 201 }));
    const client = new CompanionClient("http://127.0.0.1:4773", fetchFn);
    expect(await client.postCapture(payload)).toBe(true);
    const [url, init] = fetchFn.mock.calls[0];
    expect(url).toBe("http://127.0.0.1:4773/captures");
    expect((init as RequestInit).method).toBe("POST");
  });

  it("postCapture returns false when fetch throws (offline)", async () => {
    const fetchFn = vi.fn(async () => { throw new Error("ECONNREFUSED"); });
    const client = new CompanionClient("http://127.0.0.1:4773", fetchFn);
    expect(await client.postCapture(payload)).toBe(false);
  });

  it("ping returns false on non-OK", async () => {
    const fetchFn = vi.fn(async () => new Response("", { status: 500 }));
    const client = new CompanionClient("http://127.0.0.1:4773", fetchFn);
    expect(await client.ping()).toBe(false);
  });
});
