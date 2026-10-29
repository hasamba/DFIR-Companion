import { describe, it, expect, beforeEach, vi } from "vitest";
import "fake-indexeddb/auto";
import { CaptureController } from "../src/captureController.js";
import { CaptureQueue } from "../src/captureQueue.js";
import { CompanionClient } from "../src/companionClient.js";
import { describeCaptureOutcome } from "../src/captureOutcome.js";
import { isHeldRefusal, isKeptQueuedRefusal } from "../src/captureRefusal.js";
import type { CapturePayload, DroppedCapture } from "../src/types.js";

// #2254: a 401/403 is the companion refusing WHO is asking (a missing/rotated service token, a case
// role that cannot capture), not a verdict on the screenshot. The live capture used to be dropped,
// and a queued capture for another case was deleted after a token switch. Evidence-first: keep both.

const AMBER = "#d18616";
const snapshot = { url: "https://velociraptor.local", tabTitle: "VR", imageBase64: "AAAA" };

function payload(caseId: string, ts = "t"): CapturePayload {
  return { caseId, timestamp: ts, url: "u", tabTitle: "t", triggerType: "timer", imageBase64: "AAAA" };
}

function json(status: number, body: Record<string, unknown>): Response {
  return new Response(JSON.stringify(body), { status });
}

let queue: CaptureQueue;
beforeEach(async () => {
  queue = new CaptureQueue(`dfir-${Math.random().toString(36).slice(2)}`);
  await queue.clear();
});

describe("captureRefusal classification (#2254)", () => {
  it("holds a non-locked 401, a 403 and a capture-log-needs-repair 409", () => {
    expect(isHeldRefusal(401, "authentication required")).toBe(true);
    expect(isHeldRefusal(403, "case role does not permit capture")).toBe(true);
    expect(isHeldRefusal(409, "capture log corrupt", "capture-log-needs-repair")).toBe(true);
  });

  it("does not hold a locked 401, a plain 409, or case-gone statuses", () => {
    expect(isHeldRefusal(401, "locked")).toBe(false);
    expect(isHeldRefusal(409, "conflict")).toBe(false);
    for (const s of [400, 404, 410, 413, 423]) expect(isHeldRefusal(s, undefined)).toBe(false);
  });

  it("keeps a queued capture on team-auth 404 'case not found or access denied', but not on a plain 404", () => {
    expect(isKeptQueuedRefusal(404, "case not found or access denied")).toBe(true);
    expect(isKeptQueuedRefusal(404, "case not found")).toBe(false);
    expect(isKeptQueuedRefusal(404, undefined)).toBe(false);
    expect(isKeptQueuedRefusal(403, undefined)).toBe(true);
  });
});

describe("CaptureController — live capture refused for access (#2254)", () => {
  it.each([
    [401, "authentication required"],
    [403, "case role does not permit capture"],
  ])("queues a live capture refused with %i instead of dropping it", async (code, error) => {
    const client = new CompanionClient("http://x", vi.fn(async () => json(code, { error })));
    const status = await new CaptureController(client, queue).capture("c1", "timer", snapshot);
    expect(status.rejected).toBeUndefined();
    expect(status.locked).toBeUndefined();
    expect(status.held).toBe(code);
    expect(status.heldMessage).toBe(error);
    expect(status.queued).toBe(1);
    expect(await queue.size()).toBe(1);
  });

  it("queues a live capture refused with 409 capture-log-needs-repair (#2252 hand-off)", async () => {
    const client = new CompanionClient(
      "http://x",
      vi.fn(async () => json(409, { error: "capture log needs repair", code: "capture-log-needs-repair" })),
    );
    const status = await new CaptureController(client, queue).capture("c1", "timer", snapshot);
    expect(status.held).toBe(409);
    expect(status.heldCode).toBe("capture-log-needs-repair");
    expect(await queue.size()).toBe(1);
  });

  it("still rejects (does not queue) a plain 404 and a plain 409", async () => {
    for (const code of [404, 409]) {
      const client = new CompanionClient("http://x", vi.fn(async () => json(code, { error: "nope" })));
      const status = await new CaptureController(client, queue).capture("c1", "timer", snapshot);
      expect(status.rejected).toBe(code);
    }
    expect(await queue.size()).toBe(0);
  });

  it("leaves a locked 401 on the locked path", async () => {
    const client = new CompanionClient("http://x", vi.fn(async () => json(401, { error: "locked" })));
    const status = await new CaptureController(client, queue).capture("c1", "timer", snapshot);
    expect(status.locked).toBe(true);
    expect(status.held).toBeUndefined();
  });
});

describe("CaptureController — drain keeps and skips refused queued captures (#2254)", () => {
  function routedFetch(byCase: Record<string, () => Response>) {
    return vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(init?.body as string) as { caseId: string };
      return (byCase[body.caseId] ?? (() => new Response("{}", { status: 201 })))();
    });
  }

  it("keeps an unreachable-case capture (403) and still sends the reachable one behind it", async () => {
    await queue.enqueue(payload("old-case", "1"));
    await queue.enqueue(payload("open-case", "2"));
    const fetchFn = routedFetch({ "old-case": () => json(403, { error: "case role does not permit capture" }) });
    const status = await new CaptureController(new CompanionClient("http://x", fetchFn), queue)
      .capture("open-case", "timer", snapshot);
    // live + the reachable queued one were sent; the old-case capture was KEPT, not dropped
    expect(fetchFn).toHaveBeenCalledTimes(3);
    expect(status.dropped).toBeUndefined();
    expect(status.kept).toHaveLength(1);
    expect(status.kept?.[0].status).toBe(403);
    expect(status.queued).toBe(1);
    // What is left is the old-case capture. An immediate second drain does not re-send it — it is
    // inside its backoff window (#2263) — but still reports it as kept.
    const sentAgain: string[] = [];
    const again = await queue.drain(async (p) => { sentAgain.push(p.caseId); return { outcome: "retry" }; });
    expect(sentAgain).toEqual([]);
    expect(again.kept.map((k) => k.payload.caseId)).toEqual(["old-case"]);
  });

  it("keeps a queued capture on team-auth 404 'case not found or access denied'", async () => {
    await queue.enqueue(payload("hidden-case"));
    const fetchFn = routedFetch({ "hidden-case": () => json(404, { error: "case not found or access denied" }) });
    const status = await new CaptureController(new CompanionClient("http://x", fetchFn), queue)
      .capture("open-case", "timer", snapshot);
    expect(status.dropped).toBeUndefined();
    expect(status.kept).toHaveLength(1);
    expect(await queue.size()).toBe(1);
  });

  it("still drops a queued capture whose case is really gone (plain 404, 410, 423)", async () => {
    await queue.enqueue(payload("gone-404"));
    await queue.enqueue(payload("gone-410"));
    await queue.enqueue(payload("gone-423"));
    const fetchFn = routedFetch({
      "gone-404": () => json(404, { error: "case not found" }),
      "gone-410": () => json(410, {}),
      "gone-423": () => json(423, { error: "case closed" }),
    });
    const status = await new CaptureController(new CompanionClient("http://x", fetchFn), queue)
      .capture("open-case", "timer", snapshot);
    expect(status.dropped).toHaveLength(3);
    expect(status.kept).toBeUndefined();
    expect(await queue.size()).toBe(0);
  });

  it("keeps a queued capture on 409 capture-log-needs-repair (#2252 hand-off)", async () => {
    await queue.enqueue(payload("broken-log"));
    const fetchFn = routedFetch({
      "broken-log": () => json(409, { error: "repair", code: "capture-log-needs-repair" }),
    });
    const status = await new CaptureController(new CompanionClient("http://x", fetchFn), queue)
      .capture("open-case", "timer", snapshot);
    expect(status.kept?.[0].status).toBe(409);
    expect(status.kept?.[0].errorCode).toBe("capture-log-needs-repair");
    expect(await queue.size()).toBe(1);
  });
});

describe("CaptureQueue — skip outcome (#2254)", () => {
  it("keeps a skipped entry in place and carries on with the rest, preserving order", async () => {
    await queue.enqueue(payload("a", "1"));
    await queue.enqueue(payload("b", "2"));
    await queue.enqueue(payload("c", "3"));
    const sent: string[] = [];
    const result = await queue.drain(async (p) => {
      if (p.caseId === "a") return { outcome: "skip", status: 403 };
      sent.push(p.caseId);
      return { outcome: "sent" };
    });
    expect(sent).toEqual(["b", "c"]);
    expect(result.sent).toBe(2);
    expect(result.dropped).toEqual([]);
    expect(result.kept).toHaveLength(1);
    expect(result.kept[0].payload.caseId).toBe("a");
    expect(await queue.size()).toBe(1);
  });
});

describe("describeCaptureOutcome — held and kept captures (#2254)", () => {
  function kept(status: number, errorCode?: string): DroppedCapture {
    return { payload: payload("x"), status, ...(errorCode ? { errorCode } : {}) };
  }

  it("says the live capture was queued and to check the token / case role", () => {
    const out = describeCaptureOutcome(
      { online: true, queued: 1, held: 403, heldMessage: "case role does not permit capture" },
      false,
    );
    expect(out.diag).toBe(
      "queued (HTTP 403) — case role does not permit capture; check the service token / case role (queued=1)",
    );
    expect(out.badgeText).toBe("1");
    expect(out.badgeColor).toBe(AMBER);
    expect(out.ok).toBe(false);
    expect(out.error).toBe(out.diag);
    expect(out.forgetCredential).toBe(false);
  });

  it("names the capture-log repair condition for a held 409", () => {
    const out = describeCaptureOutcome(
      { online: true, queued: 2, held: 409, heldCode: "capture-log-needs-repair" },
      false,
    );
    expect(out.diag).toContain("case capture log needs repair — captures are being queued");
  });

  it("reports kept queued captures without calling them discarded", () => {
    const out = describeCaptureOutcome({ online: true, queued: 1, kept: [kept(403)] }, false);
    expect(out.diag).toBe(
      "ok (online=true, queued=1) · 1 queued capture(s) kept — refused (HTTP 403); check the service token / case role",
    );
    expect(out.diag).not.toContain("discarded");
    expect(out.badgeText).toBe("1");
    expect(out.badgeColor).toBe(AMBER);
    expect(out.ok).toBe(true);
  });

  it("only says 'case gone/closed' for case-gone statuses", () => {
    const gone = describeCaptureOutcome({ online: true, queued: 0, dropped: [kept(404), kept(423)] }, false);
    expect(gone.diag).toContain("case gone/closed (HTTP 404, 423)");
    const other = describeCaptureOutcome({ online: true, queued: 0, dropped: [kept(413)] }, false);
    expect(other.diag).not.toContain("case gone");
    expect(other.diag).toContain("refused by the companion (HTTP 413)");
  });
});
