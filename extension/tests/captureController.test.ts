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
