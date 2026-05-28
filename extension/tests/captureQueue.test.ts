import { describe, it, expect, beforeEach, vi } from "vitest";
import "fake-indexeddb/auto";
import { CaptureQueue } from "../src/captureQueue.js";
import type { CapturePayload } from "../src/types.js";

function payload(seq: number): CapturePayload {
  return { caseId: "c1", timestamp: `2026-05-28T10:0${seq}:00.000Z`, url: "u", tabTitle: "t",
    triggerType: "timer", imageBase64: "AAAA" };
}

let queue: CaptureQueue;
beforeEach(async () => {
  // fresh DB name per test for isolation
  queue = new CaptureQueue(`dfir-${Math.random().toString(36).slice(2)}`);
  await queue.clear();
});

describe("CaptureQueue", () => {
  it("enqueues and reports size", async () => {
    await queue.enqueue(payload(1));
    await queue.enqueue(payload(2));
    expect(await queue.size()).toBe(2);
  });

  it("drains oldest-first and empties on success", async () => {
    await queue.enqueue(payload(1));
    await queue.enqueue(payload(2));
    const sent: string[] = [];
    const sender = vi.fn(async (p: CapturePayload) => { sent.push(p.timestamp); return true; });

    await queue.drain(sender);
    expect(sent).toEqual(["2026-05-28T10:01:00.000Z", "2026-05-28T10:02:00.000Z"]);
    expect(await queue.size()).toBe(0);
  });

  it("stops draining on first failure and keeps remaining", async () => {
    await queue.enqueue(payload(1));
    await queue.enqueue(payload(2));
    const sender = vi.fn(async () => false); // always fails

    await queue.drain(sender);
    expect(await queue.size()).toBe(2);
  });
});
