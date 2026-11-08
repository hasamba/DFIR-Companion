// #2397: each capture carries a stable id, and a locked case no longer holds up every queued
// capture for every other case.
import { describe, it, expect, beforeEach, vi } from "vitest";
import "fake-indexeddb/auto";
import { CaptureController } from "../src/captureController.js";
import { CaptureQueue } from "../src/captureQueue.js";
import { CompanionClient } from "../src/companionClient.js";
import { companionServerKey } from "../src/casePasswordSession.js";
import { describeCaptureOutcome, describeQueueDrain } from "../src/captureOutcome.js";
import type { CapturePayload } from "../src/types.js";

let now = 1_000_000;
let queue: CaptureQueue;
beforeEach(async () => {
  now = 1_000_000;
  queue = new CaptureQueue(`dfir-lk-${Math.random().toString(36).slice(2)}`, () => now);
  await queue.clear();
});

const URL_ = "http://x";
const snapshot = { url: "https://console.example.com", tabTitle: "VR", imageBase64: "AAAA" };
const row = (caseId: string, ts: string): CapturePayload => ({
  caseId, timestamp: ts, url: "u", tabTitle: "t", triggerType: "timer", imageBase64: "AAAA", captureId: `id-${caseId}-${ts}`,
});
const created = () => new Response("{}", { status: 201 });
const locked = () => new Response(JSON.stringify({ error: "locked" }), { status: 401 });
const lockout = () =>
  new Response(JSON.stringify({ error: "too many failed attempts", code: "case-password-lockout" }), { status: 429 });
const ceiling = () =>
  new Response(JSON.stringify({ error: "too many failed attempts", code: "client-attempt-ceiling" }), { status: 429 });

/** A companion that answers per case, and records every capture it was sent. */
function companion(answer: (p: CapturePayload) => Response) {
  const seen: CapturePayload[] = [];
  const fetchFn = vi.fn(async (_u: RequestInfo | URL, init?: RequestInit) => {
    const p = JSON.parse(String(init?.body)) as CapturePayload;
    seen.push(p);
    return answer(p);
  });
  return { seen, fetchFn: fetchFn as unknown as typeof fetch };
}

const credentialFor = (caseId: string) => ({ caseId, companionUrl: companionServerKey(URL_), password: "pw" });

describe("capture id (#2397)", () => {
  it("gives each capture an id and re-sends the queued capture with the same id", async () => {
    let up = false;
    const c = companion(() => { if (!up) throw new Error("offline"); return created(); });
    const controller = new CaptureController(new CompanionClient(URL_, c.fetchFn), queue);
    await controller.capture("c1", "timer", snapshot); // offline → stays queued
    up = true;
    await controller.drainQueue();
    expect(c.seen).toHaveLength(2);
    expect(c.seen[0].captureId).toMatch(/^[0-9a-f-]{36}$/);
    expect(c.seen[1].captureId).toBe(c.seen[0].captureId);
  });

  it("gives two captures different ids", async () => {
    const c = companion(() => created());
    const controller = new CaptureController(new CompanionClient(URL_, c.fetchFn), queue);
    await controller.capture("c1", "timer", snapshot);
    await controller.capture("c1", "timer", snapshot);
    expect(c.seen[0].captureId).not.toBe(c.seen[1].captureId);
  });
});

describe("one locked case does not block the others (#2397)", () => {
  it("sends the captures behind a locked case's capture", async () => {
    await queue.enqueue(row("locked-case", "1"));
    await queue.enqueue(row("open-case", "2"));
    const c = companion((p) => (p.caseId === "locked-case" ? locked() : created()));
    const drain = await new CaptureController(new CompanionClient(URL_, c.fetchFn), queue).drainQueue();
    expect(drain).toMatchObject({ sent: 1, queued: 1, lockedQueuedCaseId: "locked-case" });
  });

  it("tries a wrong case password once per drain, and still sends other cases", async () => {
    await queue.enqueue(row("A", "1"));
    await queue.enqueue(row("A", "2"));
    await queue.enqueue(row("B", "3"));
    const c = companion((p) => (p.caseId === "A" ? locked() : created()));
    const client = new CompanionClient(URL_, c.fetchFn, "", credentialFor("A"));
    const drain = await new CaptureController(client, queue).drainQueue();
    expect(c.seen.filter((p) => p.caseId === "A")).toHaveLength(1);
    expect(drain).toMatchObject({ sent: 1, queued: 2, credentialRefused: true, lockedQueuedCaseId: "A" });
    expect(describeQueueDrain(drain).forgetCredential).toBe(true);
  });

  it("treats a case-password lockout as that case's problem, not the whole queue's", async () => {
    await queue.enqueue(row("A", "1"));
    await queue.enqueue(row("A", "2"));
    await queue.enqueue(row("B", "3"));
    const c = companion((p) => (p.caseId === "A" ? lockout() : created()));
    const drain = await new CaptureController(new CompanionClient(URL_, c.fetchFn), queue).drainQueue();
    expect(c.seen.filter((p) => p.caseId === "A")).toHaveLength(1);
    expect(drain).toMatchObject({ sent: 1, queued: 2, lockedQueuedCaseId: "A" });
  });

  it("still stops on a 429 that applies to every case", async () => {
    await queue.enqueue(row("A", "1"));
    await queue.enqueue(row("B", "2"));
    const c = companion(() => ceiling());
    const drain = await new CaptureController(new CompanionClient(URL_, c.fetchFn), queue).drainQueue();
    expect(c.seen).toHaveLength(1);
    expect(drain).toMatchObject({ sent: 0, queued: 2, stoppedStatus: 429 });
  });

  it("keeps naming the locked case while its capture waits out its backoff", async () => {
    await queue.enqueue(row("A", "1"));
    const c = companion(() => locked());
    const controller = new CaptureController(new CompanionClient(URL_, c.fetchFn), queue);
    await controller.drainQueue();
    now += 1_000; // inside the first backoff window
    const second = await controller.drainQueue();
    expect(c.seen).toHaveLength(1);
    expect(second.lockedQueuedCaseId).toBe("A");
    expect(describeQueueDrain(second).diag).toContain('Case "A" is locked');
    expect(describeQueueDrain(second).diag).not.toContain("check the service token");
  });

  it("sends a waiting capture as soon as its case password is held, without waiting out the backoff", async () => {
    await queue.enqueue(row("A", "1"));
    const first = companion(() => locked());
    await new CaptureController(new CompanionClient(URL_, first.fetchFn), queue).drainQueue();
    now += 1_000;
    const second = companion(() => created());
    const withPassword = new CompanionClient(URL_, second.fetchFn, "", credentialFor("A"));
    const drain = await new CaptureController(withPassword, queue).drainQueue();
    expect(second.seen).toHaveLength(1);
    expect(drain).toMatchObject({ sent: 1, queued: 0 });
  });

  it("does not skip the backoff for a capture refused for the token, not the password", async () => {
    await queue.enqueue(row("A", "1"));
    const first = companion(() => new Response(JSON.stringify({ error: "unauthorized" }), { status: 401 }));
    await new CaptureController(new CompanionClient(URL_, first.fetchFn), queue).drainQueue();
    now += 1_000;
    const second = companion(() => created());
    await new CaptureController(new CompanionClient(URL_, second.fetchFn, "", credentialFor("A")), queue).drainQueue();
    expect(second.seen).toHaveLength(0);
  });
});

describe("a live capture for a locked-out case (#2397)", () => {
  it("is kept and reported as locked, not as an outage", async () => {
    const c = companion(() => lockout());
    const status = await new CaptureController(new CompanionClient(URL_, c.fetchFn), queue).capture("A", "timer", snapshot);
    expect(status).toMatchObject({ locked: true, queued: 1 });
    expect(describeCaptureOutcome(status, false).diag).toContain("Case is locked");
  });
});
