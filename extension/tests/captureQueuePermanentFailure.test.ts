import { describe, it, expect, beforeEach, vi } from "vitest";
import "fake-indexeddb/auto";
import { CaptureQueue } from "../src/captureQueue.js";
import { CaptureController } from "../src/captureController.js";
import { CompanionClient } from "../src/companionClient.js";
import type { CapturePayload } from "../src/types.js";

// A capture queued during an outage can later get a PERMANENT answer — 404 (case deleted) or 423
// (case closed/archived). Treating that as retryable left it at the head of the queue forever, so
// every still-valid capture behind it could never upload (#215).
function payload(seq: number): CapturePayload {
  return { caseId: "c1", timestamp: `2026-05-28T10:0${seq}:00.000Z`, url: "u", tabTitle: "t",
    triggerType: "timer", imageBase64: "AAAA" };
}

let queue: CaptureQueue;
beforeEach(async () => {
  queue = new CaptureQueue(`dfir-${Math.random().toString(36).slice(2)}`);
  await queue.clear();
});

describe("CaptureQueue permanent failures (#215)", () => {
  it("drops an entry the companion permanently rejected and keeps going", async () => {
    await queue.enqueue(payload(1)); // will be permanently rejected
    await queue.enqueue(payload(2)); // must still be delivered
    await queue.enqueue(payload(3));

    const sent: string[] = [];
    const result = await queue.drain(async (p) => {
      if (p.timestamp.endsWith("10:01:00.000Z")) return { outcome: "drop", status: 404 };
      sent.push(p.timestamp);
      return { outcome: "sent" };
    });

    expect(sent).toEqual(["2026-05-28T10:02:00.000Z", "2026-05-28T10:03:00.000Z"]);
    expect(await queue.size()).toBe(0); // the dropped entry is gone, not stuck
    expect(result.sent).toBe(2);
    expect(result.dropped).toHaveLength(1);
    expect(result.dropped[0].status).toBe(404);
    expect(result.dropped[0].payload.timestamp).toBe("2026-05-28T10:01:00.000Z");
  });

  it("still stops at a transient failure and preserves the rest in order", async () => {
    await queue.enqueue(payload(1));
    await queue.enqueue(payload(2));

    const result = await queue.drain(async () => ({ outcome: "retry", status: 503 }));

    expect(await queue.size()).toBe(2); // nothing lost — the companion is simply down
    expect(result.sent).toBe(0);
    expect(result.dropped).toEqual([]);
  });

  it("delivers entries queued behind a transient failure once it clears", async () => {
    await queue.enqueue(payload(1));
    await queue.enqueue(payload(2));

    await queue.drain(async () => ({ outcome: "retry", status: 0 })); // companion unreachable
    expect(await queue.size()).toBe(2);

    const sent: string[] = [];
    await queue.drain(async (p) => { sent.push(p.timestamp); return { outcome: "sent" }; });
    expect(sent).toEqual(["2026-05-28T10:01:00.000Z", "2026-05-28T10:02:00.000Z"]);
    expect(await queue.size()).toBe(0);
  });

  it("drops several permanently-rejected entries in one pass without blocking the good one", async () => {
    await queue.enqueue(payload(1));
    await queue.enqueue(payload(2));
    await queue.enqueue(payload(3)); // the only deliverable one, behind two dead entries

    const result = await queue.drain(async (p) =>
      p.timestamp.endsWith("10:03:00.000Z") ? { outcome: "sent" } : { outcome: "drop", status: 423 },
    );

    expect(result.sent).toBe(1);
    expect(result.dropped).toHaveLength(2);
    expect(await queue.size()).toBe(0);
  });
});

describe("CaptureController surfaces dropped captures (#215)", () => {
  it("reports what the drain discarded so the popup can warn the analyst", async () => {
    const queue2 = new CaptureQueue(`dfir-${Math.random().toString(36).slice(2)}`);
    await queue2.clear();
    await queue2.enqueue(payload(1)); // stale: its case is gone

    // The live capture succeeds (201); the queued one gets a permanent 410.
    let call = 0;
    const fetchFn = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => {
      call += 1;
      return call === 1 ? new Response("{}", { status: 201 }) : new Response(JSON.stringify({ error: "case deleted" }), { status: 410 });
    });
    const controller = new CaptureController(new CompanionClient("http://x", fetchFn), queue2);

    const status = await controller.capture("c1", "timer", { url: "u", tabTitle: "t", imageBase64: "AAAA" });

    expect(status.online).toBe(true);
    expect(status.queued).toBe(0); // the unsendable entry was cleared, not left blocking
    expect(status.dropped).toHaveLength(1);
    expect(status.dropped![0].status).toBe(410);
  });

  it("keeps a queued capture when the companion is merely down", async () => {
    const queue2 = new CaptureQueue(`dfir-${Math.random().toString(36).slice(2)}`);
    await queue2.clear();
    await queue2.enqueue(payload(1));

    let call = 0;
    const fetchFn = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => {
      call += 1;
      return call === 1 ? new Response("{}", { status: 201 }) : new Response("", { status: 500 });
    });
    const controller = new CaptureController(new CompanionClient("http://x", fetchFn), queue2);

    const status = await controller.capture("c1", "timer", { url: "u", tabTitle: "t", imageBase64: "AAAA" });

    expect(status.queued).toBe(1);
    expect(status.dropped ?? []).toHaveLength(0);
  });
});
