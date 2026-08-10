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
    const sender = vi.fn(async (p: CapturePayload) => { sent.push(p.timestamp); return { outcome: "sent" as const }; });

    await queue.drain(sender);
    expect(sent).toEqual(["2026-05-28T10:01:00.000Z", "2026-05-28T10:02:00.000Z"]);
    expect(await queue.size()).toBe(0);
  });

  it("stops draining on first RETRYABLE failure and keeps remaining", async () => {
    await queue.enqueue(payload(1));
    await queue.enqueue(payload(2));
    // The companion is down, not refusing — every entry must survive for the next drain (#215).
    const sender = vi.fn(async () => ({ outcome: "retry" as const, status: 0 }));

    await queue.drain(sender);
    expect(await queue.size()).toBe(2);
  });

  it("concurrent drain calls do not duplicate sends", async () => {
    await queue.enqueue(payload(1));
    await queue.enqueue(payload(2));

    const sent: string[] = [];
    const sender = vi.fn(async (p: CapturePayload) => {
      sent.push(p.timestamp);
      // yield to allow interleaving if there were no guard
      await new Promise<void>((r) => setTimeout(r, 0));
      return { outcome: "sent" as const };
    });

    await Promise.all([queue.drain(sender), queue.drain(sender)]);

    // Each payload sent exactly once, no duplicates
    expect(sender).toHaveBeenCalledTimes(2);
    expect(sent.sort()).toEqual([
      "2026-05-28T10:01:00.000Z",
      "2026-05-28T10:02:00.000Z",
    ]);
    expect(await queue.size()).toBe(0);
  });
});

// A queue promise has to mean "durable", not "the request succeeded". Resolving from a request's
// onsuccess returned while its transaction was still open, so in a Manifest V3 service worker — which
// can be suspended the instant it goes idle — the caller believed a capture was saved before it was.
describe("CaptureQueue durability", () => {
  // THE CONTRACT, asserted directly on ordering. fake-indexeddb commits promptly, so no
  // state-observing test can reproduce the service-worker suspend window that made this matter —
  // but the ordering itself is exactly what changed, and it is observable: the promise must settle
  // AFTER the transaction's "complete" event, never on the request's success that precedes it.
  it("resolves an enqueue after the transaction commits, not when the request succeeds", async () => {
    const q = new CaptureQueue(`dfir-${Math.random().toString(36).slice(2)}`);
    // Create the store first: the version-change transaction of a first open would otherwise
    // contribute a "complete" of its own to the measured window.
    await q.enqueue(payload(1));

    const order: string[] = [];
    const original = IDBDatabase.prototype.transaction;
    IDBDatabase.prototype.transaction = function patched(
      this: IDBDatabase,
      ...args: Parameters<IDBDatabase["transaction"]>
    ): IDBTransaction {
      const tx = original.apply(this, args);
      // Registered before the queue assigns its own oncomplete, so this listener runs first.
      tx.addEventListener("complete", () => order.push("commit"));
      return tx;
    } as IDBDatabase["transaction"];

    try {
      await q.enqueue(payload(2));
      order.push("resolved");
    } finally {
      IDBDatabase.prototype.transaction = original;
    }

    expect(order).toEqual(["commit", "resolved"]);
  });

  // A fresh CaptureQueue opens its own connection, so it can only see what actually committed. If
  // enqueue resolved early, the write would still be in an open transaction at this point.
  it("has committed an enqueue by the time it resolves", async () => {
    const name = `dfir-${Math.random().toString(36).slice(2)}`;
    await new CaptureQueue(name).enqueue(payload(1));

    expect(await new CaptureQueue(name).size()).toBe(1);
  });

  it("has committed every enqueue of a burst by the time they resolve", async () => {
    const name = `dfir-${Math.random().toString(36).slice(2)}`;
    const writer = new CaptureQueue(name);
    await Promise.all([1, 2, 3, 4, 5].map((n) => writer.enqueue(payload(n))));

    expect(await new CaptureQueue(name).size()).toBe(5);
  });

  // The same guarantee on the other side: a sent capture's REMOVAL must be committed before the
  // drain moves on, or a suspend in that window resurrects an already-delivered capture.
  it("has committed each deletion before the drain reports it sent", async () => {
    const name = `dfir-${Math.random().toString(36).slice(2)}`;
    const writer = new CaptureQueue(name);
    await writer.enqueue(payload(1));
    await writer.enqueue(payload(2));

    const observed: number[] = [];
    const summary = await writer.drain(async () => {
      // Read through an independent connection: it sees committed state only.
      observed.push(await new CaptureQueue(name).size());
      return { outcome: "sent" as const };
    });

    expect(summary.sent).toBe(2);
    // Before the first send nothing is deleted yet; before the second, the first deletion has
    // already committed. A drain resolving on request success could still show 2 here.
    expect(observed).toEqual([2, 1]);
    expect(await new CaptureQueue(name).size()).toBe(0);
  });

  it("keeps a retried capture, and its successors, committed in the queue", async () => {
    const name = `dfir-${Math.random().toString(36).slice(2)}`;
    const writer = new CaptureQueue(name);
    await writer.enqueue(payload(1));
    await writer.enqueue(payload(2));

    const summary = await writer.drain(async () => ({ outcome: "retry" as const, status: 0 }));

    expect(summary.sent).toBe(0);
    expect(await new CaptureQueue(name).size()).toBe(2);
  });

  // Connections left open block a future version upgrade, which would strand the queue rather than
  // migrate it. An upgrade completing is the observable proof that nothing is still holding one.
  it("closes its connections, so a later version upgrade is not blocked", async () => {
    const name = `dfir-${Math.random().toString(36).slice(2)}`;
    const q = new CaptureQueue(name);
    await q.enqueue(payload(1));
    await q.size();
    await q.drain(async () => ({ outcome: "sent" as const }));

    const upgraded = await new Promise<boolean>((resolve, reject) => {
      const req = indexedDB.open(name, 2);
      req.onupgradeneeded = () => {
        req.result.createObjectStore("probe");
      };
      req.onsuccess = () => {
        req.result.close();
        resolve(true);
      };
      req.onerror = () => reject(req.error);
      req.onblocked = () => reject(new Error("upgrade blocked — a connection was left open"));
    });

    expect(upgraded).toBe(true);
  });
});
