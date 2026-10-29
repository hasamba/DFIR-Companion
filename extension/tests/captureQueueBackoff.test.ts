import { describe, it, expect, beforeEach } from "vitest";
import "fake-indexeddb/auto";
import { CaptureQueue, keptBackoffMs, KEPT_BACKOFF_BASE_MS, KEPT_BACKOFF_MAX_MS } from "../src/captureQueue.js";
import type { QueueSendResult } from "../src/captureQueue.js";
import type { CapturePayload } from "../src/types.js";

// #2263: a queued capture refused for access (#2254) is kept — correctly — but was then re-sent as
// a full PNG on EVERY drain, i.e. after every successful capture, with no backoff. Each kept item
// now carries an attempt count and a next-attempt time; the drain skips it until that time.

const MIN = 60_000;

function payload(caseId: string, ts: string): CapturePayload {
  return { caseId, timestamp: ts, url: "u", tabTitle: "t", triggerType: "timer", imageBase64: "AAAA" };
}

let clock: number;
let queue: CaptureQueue;
let dbName: string;
beforeEach(async () => {
  clock = Date.UTC(2026, 9, 29, 10, 0, 0);
  dbName = `dfir-${Math.random().toString(36).slice(2)}`;
  queue = new CaptureQueue(dbName, () => clock);
  await queue.clear();
});

/** A sender that refuses (skip) case "old" and accepts everything else, recording what it saw. */
function refusingOld(seen: string[]) {
  return async (p: CapturePayload): Promise<QueueSendResult> => {
    seen.push(p.caseId);
    return p.caseId === "old"
      ? { outcome: "skip", status: 403, errorMessage: "case role does not permit capture" }
      : { outcome: "sent" };
  };
}

describe("keptBackoffMs (#2263)", () => {
  it("starts at one minute, doubles, and caps at thirty minutes", () => {
    expect(KEPT_BACKOFF_BASE_MS).toBe(MIN);
    expect(KEPT_BACKOFF_MAX_MS).toBe(30 * MIN);
    expect(keptBackoffMs(1)).toBe(1 * MIN);
    expect(keptBackoffMs(2)).toBe(2 * MIN);
    expect(keptBackoffMs(3)).toBe(4 * MIN);
    expect(keptBackoffMs(5)).toBe(16 * MIN);
    expect(keptBackoffMs(6)).toBe(30 * MIN);
    expect(keptBackoffMs(500)).toBe(30 * MIN);
  });

  it("treats a nonsense attempt count as the first attempt", () => {
    expect(keptBackoffMs(0)).toBe(MIN);
    expect(keptBackoffMs(Number.NaN)).toBe(MIN);
  });
});

describe("CaptureQueue kept-item backoff (#2263)", () => {
  it("does not re-send a kept item within its backoff window, but still reports it as kept", async () => {
    await queue.enqueue(payload("old", "a"));
    const seen: string[] = [];
    const first = await queue.drain(refusingOld(seen));
    expect(seen).toEqual(["old"]);
    expect(first.kept).toHaveLength(1);

    clock += 30_000; // half the first window
    await queue.enqueue(payload("new", "b"));
    const second = await queue.drain(refusingOld(seen));
    expect(seen).toEqual(["old", "new"]); // the kept PNG was NOT uploaded again
    expect(second.sent).toBe(1);
    // Still surfaced, with the refusal that put it there, so the amber badge does not go quiet.
    expect(second.kept).toHaveLength(1);
    expect(second.kept[0].status).toBe(403);
    expect(second.kept[0].errorMessage).toBe("case role does not permit capture");
    expect(await queue.size()).toBe(1); // never auto-deleted
  });

  it("re-sends the kept item once its window has passed, and doubles the next window", async () => {
    await queue.enqueue(payload("old", "a"));
    const seen: string[] = [];
    await queue.drain(refusingOld(seen)); // attempt 1 -> next in 1 min

    clock += MIN;
    await queue.drain(refusingOld(seen)); // due: attempt 2 -> next in 2 min
    expect(seen).toEqual(["old", "old"]);

    clock += MIN + 59_000; // inside the 2-minute window
    await queue.drain(refusingOld(seen));
    expect(seen).toEqual(["old", "old"]);

    clock += 1_000; // exactly 2 minutes after attempt 2
    await queue.drain(refusingOld(seen));
    expect(seen).toEqual(["old", "old", "old"]);
    expect(await queue.size()).toBe(1);
  });

  it("delivers and removes a kept item once the companion accepts it", async () => {
    await queue.enqueue(payload("old", "a"));
    await queue.drain(refusingOld([]));
    clock += MIN;
    const res = await queue.drain(async () => ({ outcome: "sent" }));
    expect(res.sent).toBe(1);
    expect(res.kept).toHaveLength(0);
    expect(await queue.size()).toBe(0);
  });

  it("treats a legacy entry with no backoff fields as due", async () => {
    // Written by a pre-#2263 extension: just { payload }.
    await queue.enqueue(payload("old", "a"));
    const seen: string[] = [];
    await queue.drain(refusingOld(seen));
    expect(seen).toEqual(["old"]);
  });

  it("treats a nextAttemptAt far beyond the cap (clock moved back) as due", async () => {
    await queue.enqueue(payload("old", "a"));
    const seen: string[] = [];
    await queue.drain(refusingOld(seen));
    clock -= 24 * 60 * MIN; // the machine clock jumped back a day
    await queue.drain(refusingOld(seen));
    expect(seen).toEqual(["old", "old"]);
  });

  it("persists the backoff across queue instances (service worker restart)", async () => {
    await queue.enqueue(payload("old", "a"));
    await queue.drain(refusingOld([]));
    const restarted = new CaptureQueue(dbName, () => clock + 10_000);
    const seen: string[] = [];
    await restarted.drain(refusingOld(seen));
    expect(seen).toEqual([]);
  });

  it("keeps #215 ordering: a deferred kept item does not block valid captures behind it", async () => {
    await queue.enqueue(payload("old", "a"));
    await queue.drain(refusingOld([]));
    await queue.enqueue(payload("new", "b"));
    await queue.enqueue(payload("new", "c"));
    const sent: string[] = [];
    const res = await queue.drain(async (p) => {
      sent.push(p.timestamp);
      return { outcome: "sent" };
    });
    expect(sent).toEqual(["b", "c"]);
    expect(res.sent).toBe(2);
    expect(await queue.size()).toBe(1);
  });
});
