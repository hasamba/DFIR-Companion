import { describe, it, expect, beforeEach, vi } from "vitest";
import "fake-indexeddb/auto";
import { CaptureController } from "../src/captureController.js";
import { CaptureQueue } from "../src/captureQueue.js";
import { CompanionClient } from "../src/companionClient.js";

let queue: CaptureQueue;
beforeEach(async () => {
  queue = new CaptureQueue(`dfir-${Math.random().toString(36).slice(2)}`);
  await queue.clear();
});

const snapshot = { url: "https://velociraptor.local", tabTitle: "VR", imageBase64: "AAAA" };

describe("CaptureController", () => {
  it("delivers directly when online and drains queue", async () => {
    const client = new CompanionClient("http://x", vi.fn(async () => new Response("{}", { status: 201 })));
    const controller = new CaptureController(client, queue);
    const status = await controller.capture("c1", "timer", snapshot);
    expect(status.online).toBe(true);
    expect(status.queued).toBe(0);
  });

  it("enqueues when offline", async () => {
    const client = new CompanionClient("http://x", vi.fn(async () => { throw new Error("offline"); }));
    const controller = new CaptureController(client, queue);
    const status = await controller.capture("c1", "timer", snapshot);
    expect(status.online).toBe(false);
    expect(status.queued).toBe(1);
  });

  it("does NOT queue when the companion rejects the capture (404 case missing)", async () => {
    const client = new CompanionClient("http://x", vi.fn(async () => new Response("{}", { status: 404 })));
    const controller = new CaptureController(client, queue);
    const status = await controller.capture("ghost", "timer", snapshot);
    expect(status.rejected).toBe(404);
    expect(status.queued).toBe(0);
    expect(await queue.size()).toBe(0);
  });

  // A 429 (case-password lockout) or 408 is a "try again later", not a verdict on the capture —
  // dropping it lost the screenshot outright (#2174).
  it.each([408, 429])("queues a capture whose first POST gets a transient %i", async (code) => {
    const client = new CompanionClient("http://x", vi.fn(async () => new Response("{}", { status: code })));
    const controller = new CaptureController(client, queue);
    const status = await controller.capture("c1", "timer", snapshot);
    expect(status.rejected).toBeUndefined();
    expect(status.online).toBe(false);
    expect(status.queued).toBe(1);
    expect(await queue.size()).toBe(1);
  });

  it("flushes the queue once the companion is back", async () => {
    let online = false;
    const client = new CompanionClient("http://x",
      vi.fn(async () => online ? new Response("{}", { status: 201 }) : (() => { throw new Error("off"); })()));
    const controller = new CaptureController(client, queue);

    await controller.capture("c1", "timer", snapshot); // offline -> queued
    expect(await queue.size()).toBe(1);

    online = true;
    const status = await controller.capture("c1", "timer", snapshot); // online -> sends new + drains old
    expect(status.online).toBe(true);
    expect(status.queued).toBe(0);
  });
});

// #2135: a locked case answers 401 {error:"locked"}. That is "waiting for the case password", not a
// verdict on the screenshot — it used to be discarded. Evidence-first: keep it queued.
describe("CaptureController — locked case (#2135)", () => {
  const lockedResponse = () => new Response(JSON.stringify({ error: "locked", caseId: "c1" }), { status: 401 });

  it("queues a capture the companion refuses as locked and reports locked", async () => {
    const client = new CompanionClient("http://x", vi.fn(async () => lockedResponse()));
    const controller = new CaptureController(client, queue);
    const status = await controller.capture("c1", "timer", snapshot);
    expect(status.locked).toBe(true);
    expect(status.rejected).toBeUndefined();
    expect(status.queued).toBe(1);
    expect(await queue.size()).toBe(1);
  });

  it("never writes the case password into the persistent capture queue", async () => {
    const client = new CompanionClient("http://x", vi.fn(async () => lockedResponse()), "", {
      caseId: "c1", companionUrl: "http://x", password: "pw-123456",
    });
    await new CaptureController(client, queue).capture("c1", "timer", snapshot);
    const seen: unknown[] = [];
    await queue.drain(async (p) => { seen.push(p); return { outcome: "retry" }; });
    expect(seen).toHaveLength(1);
    expect(JSON.stringify(seen[0])).not.toContain("pw-123456");
    expect(seen[0]).not.toHaveProperty("casePassword");
  });

  it("keeps a plain 401 (bad team token) permanent — not queued", async () => {
    const client = new CompanionClient(
      "http://x",
      vi.fn(async () => new Response(JSON.stringify({ error: "unauthorized" }), { status: 401 })),
    );
    const controller = new CaptureController(client, queue);
    const status = await controller.capture("c1", "timer", snapshot);
    expect(status.rejected).toBe(401);
    expect(status.locked).toBeUndefined();
    expect(await queue.size()).toBe(0);
  });

  it("uploads the waiting captures once the password is accepted", async () => {
    let locked = true;
    const client = new CompanionClient(
      "http://x",
      vi.fn(async () => (locked ? lockedResponse() : new Response("{}", { status: 201 }))),
    );
    const controller = new CaptureController(client, queue);
    await controller.capture("c1", "timer", snapshot);
    await controller.capture("c1", "timer", snapshot);
    expect(await queue.size()).toBe(2);
    locked = false; // the analyst entered the password
    const status = await controller.capture("c1", "timer", snapshot);
    expect(status.locked).toBeUndefined();
    expect(status.queued).toBe(0);
    expect(status.dropped).toBeUndefined();
  });

  it("stops the drain (retry, not drop) when a queued capture is still locked", async () => {
    await queue.enqueue({
      caseId: "locked-case", timestamp: "t", url: "u", tabTitle: "t", triggerType: "timer", imageBase64: "AAAA",
    });
    const fetchFn = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(init?.body as string) as { caseId: string };
      return body.caseId === "locked-case" ? lockedResponse() : new Response("{}", { status: 201 });
    });
    const controller = new CaptureController(new CompanionClient("http://x", fetchFn), queue);
    const status = await controller.capture("open-case", "timer", snapshot);
    expect(status.online).toBe(true);
    expect(status.dropped).toBeUndefined();
    expect(await queue.size()).toBe(1);
    // #2185: the drain reports WHICH case is still locked, without claiming the current capture was.
    expect(status.lockedQueuedCaseId).toBe("locked-case");
    expect(status.locked).toBeUndefined();
    expect(status.queued).toBe(1);
  });

  it("reports no locked queued case when every queued capture sends", async () => {
    await queue.enqueue({
      caseId: "other-case", timestamp: "t", url: "u", tabTitle: "t", triggerType: "timer", imageBase64: "AAAA",
    });
    const client = new CompanionClient("http://x", vi.fn(async () => new Response("{}", { status: 201 })));
    const status = await new CaptureController(client, queue).capture("open-case", "timer", snapshot);
    expect(status.queued).toBe(0);
    expect(status.lockedQueuedCaseId).toBeUndefined();
  });

  it("reports no locked queued case when a queued capture gets a transient 503", async () => {
    await queue.enqueue({
      caseId: "busy-case", timestamp: "t", url: "u", tabTitle: "t", triggerType: "timer", imageBase64: "AAAA",
    });
    const fetchFn = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(init?.body as string) as { caseId: string };
      return new Response("{}", { status: body.caseId === "busy-case" ? 503 : 201 });
    });
    const status = await new CaptureController(new CompanionClient("http://x", fetchFn), queue)
      .capture("open-case", "timer", snapshot);
    expect(status.queued).toBe(1);
    expect(status.lockedQueuedCaseId).toBeUndefined();
  });
});
