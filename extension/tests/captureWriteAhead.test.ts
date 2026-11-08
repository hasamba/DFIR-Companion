// #2396: a capture is in the durable queue BEFORE its upload starts, and the queue is retried on its
// own schedule — not only after the next successful capture.
import { describe, it, expect, beforeEach, vi } from "vitest";
import "fake-indexeddb/auto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { CaptureController } from "../src/captureController.js";
import { CaptureQueue, CaptureQueueFullError, MAX_QUEUED_CAPTURES } from "../src/captureQueue.js";
import { CompanionClient } from "../src/companionClient.js";
import { companionServerKey } from "../src/casePasswordSession.js";
import { describeQueueDrain, describeCaptureOutcome } from "../src/captureOutcome.js";
import type { CapturePayload } from "../src/types.js";

let queue: CaptureQueue;
beforeEach(async () => {
  queue = new CaptureQueue(`dfir-wa-${Math.random().toString(36).slice(2)}`);
  await queue.clear();
});

const snapshot = { url: "https://console.example.com", tabTitle: "VR", imageBase64: "AAAA" };
const payload = (caseId = "c1", ts = "2026-11-08T10:00:00.000Z"): CapturePayload => ({
  caseId, timestamp: ts, url: "u", tabTitle: "t", triggerType: "timer", imageBase64: "AAAA",
});
const created = () => new Response("{}", { status: 201 });
const lockedResponse = () => new Response(JSON.stringify({ error: "locked" }), { status: 401 });

describe("write-ahead capture (#2396)", () => {
  it("has the capture committed in the queue, and the retry scheduled, before the upload starts", async () => {
    const order: string[] = [];
    let sizeDuringPost = -1;
    const client = new CompanionClient("http://x", vi.fn(async () => {
      order.push("post");
      sizeDuringPost = await queue.size();
      return created();
    }));
    const controller = new CaptureController(client, queue, { onQueued: async () => { order.push("scheduled"); } });
    const status = await controller.capture("c1", "timer", snapshot);
    expect(order).toEqual(["scheduled", "post"]);
    expect(sizeDuringPost).toBe(1);
    expect(status).toMatchObject({ online: true, queued: 0 });
    expect(await queue.size()).toBe(0);
  });

  it("leaves the capture queued while an upload hangs (a suspended worker loses nothing)", async () => {
    let release!: () => void;
    const client = new CompanionClient("http://x", vi.fn(() => new Promise<Response>((r) => { release = () => r(created()); })));
    const pending = new CaptureController(client, queue).capture("c1", "timer", snapshot);
    await vi.waitFor(() => expect(release).toBeTypeOf("function"));
    expect(await queue.size()).toBe(1);
    release();
    await pending;
    expect(await queue.size()).toBe(0);
  });

  it("removes the row when the companion refuses the capture for good", async () => {
    const client = new CompanionClient("http://x", vi.fn(async () => new Response("{}", { status: 404 })));
    const status = await new CaptureController(client, queue).capture("ghost", "timer", snapshot);
    expect(status.rejected).toBe(404);
    expect(await queue.size()).toBe(0);
  });

  it("a scheduling hook that fails does not stop the upload", async () => {
    const client = new CompanionClient("http://x", vi.fn(async () => created()));
    const status = await new CaptureController(client, queue, { onQueued: async () => { throw new Error("alarms"); } })
      .capture("c1", "timer", snapshot);
    expect(status.online).toBe(true);
  });

  it("still uploads when the queue is full, and reports success, not a lost capture", async () => {
    vi.spyOn(queue, "enqueue").mockRejectedValue(new CaptureQueueFullError(MAX_QUEUED_CAPTURES));
    const client = new CompanionClient("http://x", vi.fn(async () => created()));
    const status = await new CaptureController(client, queue).capture("c1", "timer", snapshot);
    expect(status.online).toBe(true);
    expect(status.queueWriteFailed).toBeUndefined();
  });

  it("reports a full queue when the capture also could not be delivered", async () => {
    vi.spyOn(queue, "enqueue").mockRejectedValue(new CaptureQueueFullError(MAX_QUEUED_CAPTURES));
    const client = new CompanionClient("http://x", vi.fn(async () => { throw new Error("offline"); }));
    const status = await new CaptureController(client, queue).capture("c1", "timer", snapshot);
    expect(status.queueWriteFailed).toBe(`offline queue full (${MAX_QUEUED_CAPTURES} captures waiting)`);
    expect(describeCaptureOutcome(status, false)).toMatchObject({ badgeText: "!", ok: false });
  });
});

describe("queue bound (#2396)", () => {
  it(`refuses the ${MAX_QUEUED_CAPTURES + 1}th capture and keeps every one already waiting`, async () => {
    for (let i = 0; i < MAX_QUEUED_CAPTURES; i++) await queue.enqueue(payload("c1", String(i)));
    await expect(queue.enqueue(payload())).rejects.toBeInstanceOf(CaptureQueueFullError);
    expect(await queue.size()).toBe(MAX_QUEUED_CAPTURES);
  });
});

describe("drain ownership (#2396)", () => {
  it("never sends a row a live capture is uploading", async () => {
    let release!: () => void;
    const liveFetch = vi.fn(() => new Promise<Response>((r) => { release = () => r(created()); }));
    const live = new CaptureController(new CompanionClient("http://x", liveFetch), queue).capture("c1", "timer", snapshot);
    await vi.waitFor(() => expect(release).toBeTypeOf("function"));

    const drainFetch = vi.fn(async () => created());
    const drain = await new CaptureController(new CompanionClient("http://x", drainFetch), queue).drainQueue();
    expect(drainFetch).not.toHaveBeenCalled();
    expect(drain.sent).toBe(0);
    release();
    await live;
    expect(await queue.size()).toBe(0);
  });

  it("does not re-send a row removed after the drain listed it", async () => {
    await queue.enqueue(payload("c1", "a"));
    const second = await queue.enqueue(payload("c1", "b"));
    const sent: string[] = [];
    await queue.drain(async (p) => {
      sent.push(p.timestamp);
      if (p.timestamp === "a") await queue.remove(second); // delivered by someone else meanwhile
      return { outcome: "sent" };
    });
    expect(sent).toEqual(["a"]);
  });
});

describe("drain destination (#2396)", () => {
  it("keeps captures taken for another companion instead of replaying them here", async () => {
    await queue.enqueue(payload("c1", "a"), { companionUrl: "http://old" });
    await queue.enqueue(payload("c1", "b")); // a row from an older extension: no destination recorded
    const fetchFn = vi.fn(async () => created());
    const drain = await new CaptureController(new CompanionClient("http://new", fetchFn), queue).drainQueue();
    expect(fetchFn).toHaveBeenCalledTimes(1);
    expect(drain).toMatchObject({ sent: 1, elsewhere: 1, queued: 1 });
  });

  it("binds a live capture's row to the companion it was taken for", async () => {
    const client = new CompanionClient("http://a", vi.fn(async () => { throw new Error("offline"); }));
    await new CaptureController(client, queue).capture("c1", "timer", snapshot);
    const other = vi.fn(async () => created());
    const drain = await new CaptureController(new CompanionClient("http://b", other), queue).drainQueue();
    expect(other).not.toHaveBeenCalled();
    expect(drain.elsewhere).toBe(1);
  });
});

describe("standalone drain and the case password (#2396)", () => {
  it("flags a queued capture refused as locked although it carried the stored password", async () => {
    await queue.enqueue(payload("c1"));
    const credential = { caseId: "c1", companionUrl: companionServerKey("http://x"), password: "wrong" };
    const client = new CompanionClient("http://x", vi.fn(async () => lockedResponse()), "", credential);
    const drain = await new CaptureController(client, queue).drainQueue();
    expect(drain).toMatchObject({ credentialRefused: true, lockedQueuedCaseId: "c1", queued: 1 });
    expect(describeQueueDrain(drain).forgetCredential).toBe(true);
  });

  it("does not blame the stored password for another case being locked", async () => {
    await queue.enqueue(payload("other"));
    const credential = { caseId: "c1", companionUrl: companionServerKey("http://x"), password: "p" };
    const client = new CompanionClient("http://x", vi.fn(async () => lockedResponse()), "", credential);
    const drain = await new CaptureController(client, queue).drainQueue();
    expect(drain.credentialRefused).toBe(false);
  });
});

describe("describeQueueDrain (#2396)", () => {
  const base = { sent: 0, dropped: [], kept: [], elsewhere: 0, credentialRefused: false };

  it("says when the companion could not be reached", () => {
    const d = describeQueueDrain({ ...base, queued: 3, stoppedStatus: 0 });
    expect(d.diag).toContain("companion unreachable — 3 queued capture(s) will be retried");
    expect(d.badgeText).toBe("off");
  });

  it("clears the count once everything went out", () => {
    const d = describeQueueDrain({ ...base, queued: 0, sent: 4 });
    expect(d.diag).toBe("queue: 4 sent, 0 still waiting");
    expect(d.badgeText).toBe("");
  });

  it("names a capture discarded by the companion", () => {
    const d = describeQueueDrain({ ...base, queued: 0, dropped: [{ payload: payload(), status: 404 }] });
    expect(d.diag).toContain("1 queued capture(s) discarded");
    expect(d.badgeText).toBe("!");
  });
});

describe("upload timeout (#2396)", () => {
  it("gives up on a stalled companion and reports it unreachable", async () => {
    const fetchFn = vi.fn((_url: RequestInfo | URL, init?: RequestInit) => new Promise<Response>((_r, reject) => {
      init?.signal?.addEventListener("abort", () => reject(new Error("aborted")));
    }));
    const client = new CompanionClient("http://x", fetchFn as typeof fetch, "", undefined, 20);
    expect(await client.postCapture(payload())).toEqual({ ok: false, status: 0 });
  });
});

// serviceWorker.ts registers its listeners at import time, so its wiring is asserted on the source.
describe("service worker drains the queue on its own (#2396)", () => {
  const sw = readFileSync(resolve(__dirname, "../src/serviceWorker.ts"), "utf-8");

  it("retries on a dedicated alarm, at browser start and on install", () => {
    expect(sw).toMatch(/alarm\.name === DRAIN_ALARM\) runSafely\("queue retry", drainQueuedCaptures\)/);
    const startup = /onStartup\.addListener\(\(\) => \{[\s\S]*?\}\);/.exec(sw)?.[0];
    expect(startup).toContain("drainQueuedCaptures");
    const installed = /onInstalled\.addListener\(\(\) => \{[\s\S]*?\}\);/.exec(sw)?.[0];
    expect(installed).toContain("drainQueuedCaptures");
  });

  it("schedules the retry before the upload and on every worker wake", () => {
    expect(sw).toContain("{ onQueued: ensureDrainAlarm }");
    expect(sw).toMatch(/^void syncDrainAlarm\(\)/m);
  });

  it("does not drop automatic capture failures with a bare void", () => {
    expect(sw).not.toMatch(/void captureActiveTab\("(timer|tab_switch|navigation|click|manual)"\)/);
  });
});

// Codex review of #2396.
describe("drain review fixes (#2396)", () => {
  it("matches a stored destination by server identity, not spelling", async () => {
    await queue.enqueue(payload("c1"), { companionUrl: "http://LOCALHOST:4773/" });
    const fetchFn = vi.fn(async () => created());
    const drain = await new CaptureController(new CompanionClient("http://localhost:4773", fetchFn), queue).drainQueue();
    expect(fetchFn).toHaveBeenCalledTimes(1);
    expect(drain).toMatchObject({ sent: 1, elsewhere: 0 });
  });

  it("still reports a discarded capture when the drain fails afterwards", async () => {
    await queue.enqueue(payload("c1", "a"));
    await queue.enqueue(payload("c1", "b"));
    let calls = 0;
    const fetchFn = vi.fn(async () => {
      calls += 1;
      if (calls === 1) return new Response("{}", { status: 404 });
      throw new Error("unreachable");
    });
    vi.spyOn(queue, "size").mockRejectedValue(new Error("db gone"));
    const drain = await new CaptureController(new CompanionClient("http://x", fetchFn), queue).drainQueue();
    expect(drain.dropped).toHaveLength(1);
    expect(drain.error).toBe("db gone");
    expect(describeQueueDrain(drain).diag).toContain("1 queued capture(s) discarded");
    expect(describeQueueDrain(drain).diag).toContain("queue retry failed: db gone");
  });

  it("keeps what a drain did before an error part-way through it", async () => {
    await queue.enqueue(payload("c1", "a"));
    await queue.enqueue(payload("c1", "b"));
    const summary = await queue.drain(async (p) => {
      if (p.timestamp === "a") return { outcome: "drop", status: 404 };
      throw new Error("sender blew up");
    });
    expect(summary.dropped).toHaveLength(1);
    expect(summary.error).toBe("sender blew up");
    expect(await queue.size()).toBe(1);
  });
});
