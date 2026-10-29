import { describe, it, expect, beforeEach, vi } from "vitest";
import "fake-indexeddb/auto";
import { CaptureController } from "../src/captureController.js";
import { CaptureQueue } from "../src/captureQueue.js";
import { CompanionClient } from "../src/companionClient.js";
import { describeCaptureOutcome } from "../src/captureOutcome.js";

// #2256: a failed write to the offline queue (quota exceeded, aborted transaction) used to reject
// out of capture(). Automatic triggers call it with `void`, so the rejection was unhandled, nothing
// was recorded and the badge did not change — the screenshot was lost silently.

const RED = "#cc3333";
const snapshot = { url: "https://velociraptor.local", tabTitle: "VR", imageBase64: "AAAA" };

let queue: CaptureQueue;
beforeEach(async () => {
  queue = new CaptureQueue(`dfir-${Math.random().toString(36).slice(2)}`);
  await queue.clear();
  vi.spyOn(queue, "enqueue").mockRejectedValue(new Error("QuotaExceededError"));
});

describe("CaptureController — queue write failure (#2256)", () => {
  it.each([
    ["offline", () => { throw new Error("offline"); }],
    ["a transient 503", () => new Response("{}", { status: 503 })],
    ["locked", () => new Response(JSON.stringify({ error: "locked" }), { status: 401 })],
    ["refused for access (403)", () => new Response(JSON.stringify({ error: "no" }), { status: 403 })],
  ])("resolves with queueWriteFailed when the capture is %s and enqueue rejects", async (_label, reply) => {
    const client = new CompanionClient("http://x", vi.fn(async () => reply()));
    const status = await new CaptureController(client, queue).capture("c1", "timer", snapshot);
    expect(status.queueWriteFailed).toBe("QuotaExceededError");
    expect(await queue.size()).toBe(0);
  });

  // The locked flag survives: a refused password must still be forgotten, or auto-capture would
  // keep sending it and burn the case's shared lockout (#2135).
  it("keeps the locked flag when the locked capture could not be queued", async () => {
    const client = new CompanionClient("http://x",
      vi.fn(async () => new Response(JSON.stringify({ error: "locked" }), { status: 401 })));
    const status = await new CaptureController(client, queue).capture("c1", "timer", snapshot);
    expect(status.locked).toBe(true);
    expect(status.queueWriteFailed).toBe("QuotaExceededError");
  });
});

describe("describeCaptureOutcome — queue write failure (#2256)", () => {
  it("says the capture was NOT saved, with a red '!' and an error", () => {
    const out = describeCaptureOutcome({ online: false, queued: 0, queueWriteFailed: "QuotaExceededError" }, true);
    expect(out.diag).toBe("capture NOT saved — queue write failed: QuotaExceededError");
    expect(out.badgeText).toBe("!");
    expect(out.badgeColor).toBe(RED);
    expect(out.ok).toBe(false);
    expect(out.error).toBe(out.diag);
    expect(out.forgetCredential).toBe(false);
  });

  it("ranks the failure above locked, but still forgets the refused password", () => {
    const out = describeCaptureOutcome(
      { online: true, queued: 0, locked: true, queueWriteFailed: "aborted" }, true);
    expect(out.diag).toBe("capture NOT saved — queue write failed: aborted");
    expect(out.badgeColor).toBe(RED);
    expect(out.forgetCredential).toBe(true);
  });
});
