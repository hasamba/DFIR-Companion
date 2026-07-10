import { describe, it, expect, vi } from "vitest";
import { CompanionClient } from "../src/companionClient.js";
import type { CapturePayload } from "../src/types.js";

const payload: CapturePayload = {
  caseId: "c1", timestamp: "2026-05-28T10:00:00.000Z", url: "u", tabTitle: "t",
  triggerType: "timer", imageBase64: "AAAA",
};

describe("CompanionClient", () => {
  it("postCapture reports ok + status 201 on success", async () => {
    const fetchFn = vi.fn(async () => new Response("{}", { status: 201 }));
    const client = new CompanionClient("http://127.0.0.1:4773", fetchFn);
    expect(await client.postCapture(payload)).toEqual({ ok: true, status: 201 });
    const [url, init] = fetchFn.mock.calls[0];
    expect(url).toBe("http://127.0.0.1:4773/captures");
    expect((init as RequestInit).method).toBe("POST");
  });

  it("postCapture reports the 404 status when the case does not exist", async () => {
    const fetchFn = vi.fn(async () => new Response("{}", { status: 404 }));
    const client = new CompanionClient("http://127.0.0.1:4773", fetchFn);
    expect(await client.postCapture(payload)).toEqual({ ok: false, status: 404 });
  });

  it("postCapture reports status 0 when fetch throws (offline)", async () => {
    const fetchFn = vi.fn(async () => { throw new Error("ECONNREFUSED"); });
    const client = new CompanionClient("http://127.0.0.1:4773", fetchFn);
    expect(await client.postCapture(payload)).toEqual({ ok: false, status: 0 });
  });

  it("ping returns false on non-OK", async () => {
    const fetchFn = vi.fn(async () => new Response("", { status: 500 }));
    const client = new CompanionClient("http://127.0.0.1:4773", fetchFn);
    expect(await client.ping()).toBe(false);
  });

  it("postImport posts to /cases/:id/import and reports ok on 202", async () => {
    const fetchFn = vi.fn(async () => new Response("{}", { status: 202 }));
    const client = new CompanionClient("http://127.0.0.1:4773", fetchFn);
    const payload = { json: "[{\"a\":1}]", filename: "splunk-2026.json" };
    expect(await client.postImport("c1", payload)).toEqual({ ok: true, status: 202 });
    const [url, init] = fetchFn.mock.calls[0];
    expect(url).toBe("http://127.0.0.1:4773/cases/c1/import");
    expect((init as RequestInit).method).toBe("POST");
    expect(JSON.parse((init as RequestInit).body as string)).toEqual(payload);
  });

  it("postImport URL-encodes the case id", async () => {
    const fetchFn = vi.fn(async () => new Response("{}", { status: 202 }));
    const client = new CompanionClient("http://127.0.0.1:4773", fetchFn);
    await client.postImport("a/b", { json: "[]", filename: "f.json" });
    expect(fetchFn.mock.calls[0][0]).toBe("http://127.0.0.1:4773/cases/a%2Fb/import");
  });

  it("postImport reports the non-202 status (e.g. 404 case not found)", async () => {
    const fetchFn = vi.fn(async () => new Response("{}", { status: 404 }));
    const client = new CompanionClient("http://127.0.0.1:4773", fetchFn);
    expect(await client.postImport("c1", { json: "[]", filename: "f.json" })).toEqual({ ok: false, status: 404 });
  });

  it("postImport reports status 0 when fetch throws (offline)", async () => {
    const fetchFn = vi.fn(async () => { throw new Error("ECONNREFUSED"); });
    const client = new CompanionClient("http://127.0.0.1:4773", fetchFn);
    expect(await client.postImport("c1", { json: "[]", filename: "f.json" })).toEqual({ ok: false, status: 0 });
  });

  it("postImport posts a text payload (context-menu push) without a json field", async () => {
    const fetchFn = vi.fn(async () => new Response("{}", { status: 202 }));
    const client = new CompanionClient("http://127.0.0.1:4773", fetchFn);
    const payload = { text: "https://evil.example/payload", filename: "context-menu-link-2026.json" };
    expect(await client.postImport("c1", payload)).toEqual({ ok: true, status: 202 });
    const [, init] = fetchFn.mock.calls[0];
    expect(JSON.parse((init as RequestInit).body as string)).toEqual(payload);
  });
});
