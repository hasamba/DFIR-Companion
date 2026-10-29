import { describe, it, expect, vi } from "vitest";
import { CompanionClient } from "../src/companionClient.js";
import type { CapturePayload } from "../src/types.js";

const payload: CapturePayload = {
  caseId: "c1", timestamp: "2026-05-28T10:00:00.000Z", url: "u", tabTitle: "t",
  triggerType: "timer", imageBase64: "AAAA",
};

describe("CompanionClient", () => {
  it("postCapture reports ok + status 201 on success", async () => {
    const fetchFn = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => new Response("{}", { status: 201 }));
    const client = new CompanionClient("http://127.0.0.1:4773", fetchFn);
    expect(await client.postCapture(payload)).toEqual({ ok: true, status: 201 });
    const [url, init] = fetchFn.mock.calls[0];
    expect(url).toBe("http://127.0.0.1:4773/captures");
    expect((init as RequestInit).method).toBe("POST");
  });

  it("authenticates capture and import requests with the configured service identity", async () => {
    const fetchFn = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) =>
      new Response("{}", { status: 201 }));
    const client = new CompanionClient("http://127.0.0.1:4773", fetchFn, "case-service-token");
    await client.postCapture(payload);
    expect((fetchFn.mock.calls[0][1]?.headers as Record<string, string>).Authorization)
      .toBe("Bearer case-service-token");
  });

  it("postCapture reports the 404 status when the case does not exist", async () => {
    const fetchFn = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => new Response("{}", { status: 404 }));
    const client = new CompanionClient("http://127.0.0.1:4773", fetchFn);
    expect(await client.postCapture(payload)).toEqual({ ok: false, status: 404 });
  });

  it("postCapture reports status 0 when fetch throws (offline)", async () => {
    const fetchFn = vi.fn(async () => { throw new Error("ECONNREFUSED"); });
    const client = new CompanionClient("http://127.0.0.1:4773", fetchFn);
    expect(await client.postCapture(payload)).toEqual({ ok: false, status: 0 });
  });

  it("ping returns false on non-OK", async () => {
    const fetchFn = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => new Response("", { status: 500 }));
    const client = new CompanionClient("http://127.0.0.1:4773", fetchFn);
    expect(await client.ping()).toBe(false);
  });

  it("postImport posts to /cases/:id/import and reports ok on 202", async () => {
    const fetchFn = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => new Response("{}", { status: 202 }));
    const client = new CompanionClient("http://127.0.0.1:4773", fetchFn);
    const payload = { json: "[{\"a\":1}]", filename: "splunk-2026.json" };
    expect(await client.postImport("c1", payload)).toEqual({ ok: true, status: 202 });
    const [url, init] = fetchFn.mock.calls[0];
    expect(url).toBe("http://127.0.0.1:4773/cases/c1/import");
    expect((init as RequestInit).method).toBe("POST");
    expect(JSON.parse((init as RequestInit).body as string)).toEqual(payload);
  });

  it("postImport URL-encodes the case id", async () => {
    const fetchFn = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => new Response("{}", { status: 202 }));
    const client = new CompanionClient("http://127.0.0.1:4773", fetchFn);
    await client.postImport("a/b", { json: "[]", filename: "f.json" });
    expect(fetchFn.mock.calls[0][0]).toBe("http://127.0.0.1:4773/cases/a%2Fb/import");
  });

  it("postImport reports the non-202 status (e.g. 404 case not found)", async () => {
    const fetchFn = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => new Response("{}", { status: 404 }));
    const client = new CompanionClient("http://127.0.0.1:4773", fetchFn);
    expect(await client.postImport("c1", { json: "[]", filename: "f.json" })).toEqual({ ok: false, status: 404 });
  });

  it("postImport reports status 0 when fetch throws (offline)", async () => {
    const fetchFn = vi.fn(async () => { throw new Error("ECONNREFUSED"); });
    const client = new CompanionClient("http://127.0.0.1:4773", fetchFn);
    expect(await client.postImport("c1", { json: "[]", filename: "f.json" })).toEqual({ ok: false, status: 0 });
  });

  it("postImport posts a text payload (context-menu push) without a json field", async () => {
    const fetchFn = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => new Response("{}", { status: 202 }));
    const client = new CompanionClient("http://127.0.0.1:4773", fetchFn);
    const payload = { text: "https://evil.example/payload", filename: "context-menu-link-2026.json" };
    expect(await client.postImport("c1", payload)).toEqual({ ok: true, status: 202 });
    const [, init] = fetchFn.mock.calls[0];
    expect(JSON.parse((init as RequestInit).body as string)).toEqual(payload);
  });
});

// #2135: a locked case needs its password on every evidence write. The extension holds it in
// session memory and adds it at SEND time — it is never part of a queued payload.
describe("CompanionClient — case password for locked cases (#2135)", () => {
  const ok201 = () =>
    vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => new Response("{}", { status: 201 }));
  const bodyOf = (fetchFn: ReturnType<typeof ok201>) =>
    JSON.parse((fetchFn.mock.calls[0][1] as RequestInit).body as string) as Record<string, unknown>;

  it("adds casePassword to a capture for the case the password belongs to", async () => {
    const fetchFn = ok201();
    const client = new CompanionClient("http://x", fetchFn, "", { caseId: "c1", companionUrl: "http://x", password: "pw-123456" });
    await client.postCapture(payload);
    expect(bodyOf(fetchFn).casePassword).toBe("pw-123456");
    expect(payload).not.toHaveProperty("casePassword"); // the caller's payload is not mutated
  });

  it("does not send the password with a capture for a different case", async () => {
    const fetchFn = ok201();
    const client = new CompanionClient("http://x", fetchFn, "", { caseId: "other", companionUrl: "http://x", password: "pw-123456" });
    await client.postCapture(payload);
    expect(bodyOf(fetchFn)).not.toHaveProperty("casePassword");
  });

  it("adds casePassword to an artifact import for the matching case", async () => {
    const fetchFn = ok201();
    const client = new CompanionClient("http://x", fetchFn, "", { caseId: "c1", companionUrl: "http://x", password: "pw-123456" });
    await client.postImport("c1", { json: "[]", filename: "f.json" });
    expect(bodyOf(fetchFn).casePassword).toBe("pw-123456");
  });

  it("postImport returns the companion's error field", async () => {
    const fetchFn = vi.fn(async () => new Response(JSON.stringify({ error: "locked", caseId: "c1" }), { status: 401 }));
    const client = new CompanionClient("http://x", fetchFn);
    expect(await client.postImport("c1", { json: "[]", filename: "f.json" }))
      .toEqual({ ok: false, status: 401, errorMessage: "locked" });
  });

  // Codex review of #2135: the password was keyed by case id alone, so pointing the extension at a
  // different companion while keeping the selected case sent server A's case password to server B.
  it("does not send the password to a different companion that has a case with the same id", async () => {
    const fetchFn = ok201();
    const cred = { caseId: "c1", companionUrl: "http://server-a:4773", password: "pw-123456" };
    const client = new CompanionClient("http://server-b:4773", fetchFn, "", cred);
    await client.postCapture(payload);
    await client.postImport("c1", { json: "[]", filename: "f.json" });
    expect(bodyOf(fetchFn)).not.toHaveProperty("casePassword");
    const importBody = JSON.parse((fetchFn.mock.calls[1][1] as RequestInit).body as string);
    expect(importBody).not.toHaveProperty("casePassword");
  });

  it("does not send the password to another port on the same host", async () => {
    const fetchFn = ok201();
    const cred = { caseId: "c1", companionUrl: "http://127.0.0.1:4773", password: "pw-123456" };
    await new CompanionClient("http://127.0.0.1:4774", fetchFn, "", cred).postCapture(payload);
    expect(bodyOf(fetchFn)).not.toHaveProperty("casePassword");
  });

  it("still sends the password to the same companion written differently (case, trailing slash)", async () => {
    const fetchFn = ok201();
    const cred = { caseId: "c1", companionUrl: "http://127.0.0.1:4773", password: "pw-123456" };
    await new CompanionClient("HTTP://127.0.0.1:4773/", fetchFn, "", cred).postCapture(payload);
    expect(bodyOf(fetchFn).casePassword).toBe("pw-123456");
  });

  it("never sends a password whose companion is missing or unparseable", async () => {
    const fetchFn = ok201();
    const cred = { caseId: "c1", companionUrl: "", password: "pw-123456" };
    await new CompanionClient("http://x", fetchFn, "", cred).postCapture(payload);
    expect(bodyOf(fetchFn)).not.toHaveProperty("casePassword");
  });
});

// #2258: a 202/201 can still mean "saved as evidence but NOT analyzed" (the case's AI is off). The
// body carries `analyzed:false, reason:"ai-off"`; the client must hand that to the caller.
describe("CompanionClient — analyzed/reason on success (#2258)", () => {
  const reply = (status: number, body: unknown) =>
    vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => new Response(JSON.stringify(body), { status }));

  it("postImport carries analyzed:false + reason from a 202 body", async () => {
    const client = new CompanionClient("http://x", reply(202, { accepted: true, kind: "csv", analyzed: false, reason: "ai-off" }));
    expect(await client.postImport("c1", { json: "[]", filename: "f.json" }))
      .toEqual({ ok: true, status: 202, analyzed: false, reason: "ai-off" });
  });

  it("postCapture carries analyzed:false + reason from a 201 body", async () => {
    const client = new CompanionClient("http://x", reply(201, { sequenceNumber: 3, analyzed: false, reason: "ai-off" }));
    expect(await client.postCapture(payload)).toEqual({ ok: true, status: 201, analyzed: false, reason: "ai-off" });
  });

  it("adds nothing for a normal 202 and ignores non-boolean/non-string fields", async () => {
    const client = new CompanionClient("http://x", reply(202, { accepted: true, analyzed: "no", reason: 5 }));
    expect(await client.postImport("c1", { json: "[]", filename: "f.json" })).toEqual({ ok: true, status: 202 });
  });

  it("still reports success when the 202 body is not JSON", async () => {
    const fetchFn = vi.fn(async () => new Response("not json", { status: 202 }));
    const client = new CompanionClient("http://x", fetchFn);
    expect(await client.postImport("c1", { json: "[]", filename: "f.json" })).toEqual({ ok: true, status: 202 });
  });
});
