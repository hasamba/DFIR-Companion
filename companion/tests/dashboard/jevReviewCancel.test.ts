import { readFile } from "node:fs/promises";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// Stopping the wait for a missed-evidence review (#1552), driven the way the browser drives it.
//
// A review request that never settles — a laptop that slept, a proxy that dropped the socket — used
// to leave both review buttons disabled on "Reviewing…" until the analyst switched case or reloaded.
// The suite pins the way out:
//
//   1. A STOP CONTROL, SHOWN ONLY WHILE A REVIEW RUNS. Pressing it aborts the request, frees the
//      panel and says plainly that the server may still be running the review.
//   2. THE CAPPED REVIEW GIVES UP ON ITS OWN after a generous wait, with its own message. The full
//      read does NOT: a large case can legitimately take longer, and giving up in the browser does
//      not stop the server.
//   3. A CASE SWITCH ABORTS THE REQUEST TOO, and an answer that arrives after the analyst stopped
//      waiting paints nothing.

interface Api {
  loadJevReview(caseId: string): Promise<void>;
  initJevReview(): void;
}

interface Deferred {
  url: string;
  signal: AbortSignal | undefined;
  resolve(body: unknown, init?: { ok?: boolean; status?: number }): void;
  reject(err: Error): void;
}

interface FakeEl {
  id: string;
  value: string;
  textContent: string;
  innerHTML: string;
  checked: boolean;
  disabled: boolean;
  hidden: boolean;
  title: string;
  addEventListener(type: string, fn: (e: unknown) => void): void;
  fire(type: string, ev?: unknown): void;
  querySelector(sel: string): FakeEl | null;
  focus(): void;
}

function present(html: string, sel: string): boolean {
  return sel.startsWith("#") && html.includes(`id="${sel.slice(1)}"`);
}

function makeEl(id: string): FakeEl {
  const handlers: Record<string, ((e: unknown) => void)[]> = {};
  let children = new Map<string, FakeEl>();
  let html = "";
  const el: FakeEl = {
    id,
    value: "",
    textContent: "",
    get innerHTML() {
      return html;
    },
    set innerHTML(next: string) {
      html = next;
      children = new Map();
    },
    checked: true,
    disabled: false,
    hidden: false,
    title: "",
    addEventListener: (type, fn) => {
      (handlers[type] ||= []).push(fn);
    },
    fire: (type, ev) => (handlers[type] || []).forEach((f) => f(ev ?? {})),
    querySelector: (sel) => {
      if (!present(html, sel)) return null;
      let cur = children.get(sel);
      if (!cur) {
        cur = makeEl(sel);
        children.set(sel, cur);
      }
      return cur;
    },
    focus: () => {},
  };
  return el;
}

/**
 * `honourAbort: false` is a fetch whose abort does not take — the case where only the panel's own
 * bookkeeping stands between a late answer and the screen.
 */
function harness({ honourAbort = true } = {}) {
  const pending: Deferred[] = [];
  const els = new Map<string, FakeEl>();
  const el = (id: string): FakeEl => {
    if (!els.has(id)) els.set(id, makeEl(id));
    return els.get(id) as FakeEl;
  };
  const globals = {
    document: { getElementById: (id: string) => el(id) },
    AbortController,
    // Read per call, so the fake clock a test installs later still reaches the module.
    setTimeout: (fn: () => void, ms: number) => globalThis.setTimeout(fn, ms),
    clearTimeout: (t: ReturnType<typeof setTimeout>) => globalThis.clearTimeout(t),
    fetch: (url: string, init?: { signal?: AbortSignal }) =>
      new Promise((res, rej) => {
        const signal = init?.signal;
        if (honourAbort && signal)
          signal.addEventListener("abort", () =>
            rej(signal.reason instanceof Error ? signal.reason : new Error(String(signal.reason))),
          );
        pending.push({
          url,
          signal,
          resolve: (body, i = {}) =>
            res({ ok: i.ok ?? true, status: i.status ?? 200, json: () => Promise.resolve(body) }),
          reject: rej,
        });
      }),
  };
  const api = loadDashboardModule<Api>(
    "dashboard-jev-review.js",
    ["dashboard-escape.js", "dashboard-jev-review-format.js"],
    globals,
  );
  const panel = () => el("jevReviewPanel");
  return { api, pending, el, panel };
}

/** Microtasks only — the fake clock would freeze a setTimeout-based settle. */
const settle = async () => {
  for (let i = 0; i < 12; i++) await Promise.resolve();
};

const REVIEW = {
  model: "typesafe/jev-1.13",
  rows: [
    {
      id: "e-1",
      score: 3,
      grade: "High",
      confidence: 0.9,
      tooling: 0.1,
      description: "row e-1",
      timestamp: "2026-03-01T04:05:06Z",
    },
  ],
  matched: 1,
  read: 1,
  graded: 1,
  alreadyAnalyzed: 0,
  capped: false,
  readAll: false,
};

const reviewPosts = (h: ReturnType<typeof harness>) => h.pending.filter((p) => p.url.endsWith("/jev/review"));

/** Jev configured, a case connected, nothing run yet. */
async function ready(opts?: { honourAbort?: boolean }) {
  const h = harness(opts);
  h.api.initJevReview();
  const load = h.api.loadJevReview("case-1");
  h.pending.shift()!.resolve({ configured: true, model: "typesafe/jev-1.13" });
  await load;
  await settle();
  return h;
}

/** Start the capped review and hand back its request. */
function startCapped(h: ReturnType<typeof harness>): Deferred {
  h.el("jevRunBtn").fire("click");
  const posts = reviewPosts(h);
  return posts[posts.length - 1];
}

/** Start the full read. With no earlier run the size is unknown, so it asks first. */
function startAll(h: ReturnType<typeof harness>): Deferred {
  h.el("jevRunAllBtn").fire("click");
  h.panel().querySelector("#jevConfirmRun")!.fire("click");
  const posts = reviewPosts(h);
  return posts[posts.length - 1];
}

const MINUTE = 60 * 1000;
const CANCEL_TEXT = "You stopped waiting for this review. It may still be running on the server";
const TIMEOUT_TEXT = "No answer after 15 minutes. The review may still be running on the server";

const unhandled: unknown[] = [];
const onUnhandled = (e: unknown) => unhandled.push(e);
beforeEach(() => {
  unhandled.length = 0;
  process.on("unhandledRejection", onUnhandled);
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
});
afterEach(async () => {
  await settle();
  vi.useRealTimers();
  // One real macrotask, so a rejection nobody handled has time to be reported.
  await new Promise((r) => setTimeout(r, 0));
  process.off("unhandledRejection", onUnhandled);
  expect(unhandled, "a promise rejected with nobody listening").toEqual([]);
});

describe("the stop control", () => {
  it("is hidden until a review runs, shown while it runs, hidden again after", async () => {
    const h = await ready();
    expect(h.el("jevCancelBtn").hidden).toBe(true);
    const req = startCapped(h);
    expect(h.el("jevCancelBtn").hidden).toBe(false);
    req.resolve(REVIEW);
    await settle();
    expect(h.el("jevCancelBtn").hidden).toBe(true);
  });

  it("aborts the request, frees both buttons and says the server may still be running", async () => {
    const h = await ready();
    const req = startCapped(h);
    expect(h.el("jevRunBtn").disabled).toBe(true);
    h.el("jevCancelBtn").fire("click");
    await settle();
    expect(req.signal?.aborted, "the request was not aborted").toBe(true);
    expect(h.el("jevRunBtn").disabled).toBe(false);
    expect(h.el("jevRunAllBtn").disabled).toBe(false);
    expect(h.el("jevRunBtn").textContent).toBe("Review missed evidence");
    expect(h.el("jevCancelBtn").hidden).toBe(true);
    expect(h.panel().innerHTML).toContain(CANCEL_TEXT);
    expect(h.panel().innerHTML).toContain("a new review of this case is refused until it ends");
    // Not dressed up as a network failure.
    expect(h.panel().innerHTML).not.toContain("The review did not run");
  });

  it("leaves the panel really usable — a new review starts", async () => {
    const h = await ready();
    startCapped(h);
    h.el("jevCancelBtn").fire("click");
    await settle();
    startCapped(h);
    expect(reviewPosts(h)).toHaveLength(2);
  });

  it("frees the panel even when the abort does not take, and the late answer paints nothing", async () => {
    const h = await ready({ honourAbort: false });
    const req = startCapped(h);
    h.el("jevCancelBtn").fire("click");
    await settle();
    expect(h.el("jevRunBtn").disabled).toBe(false);
    req.resolve(REVIEW);
    await settle();
    expect(h.panel().innerHTML).toContain(CANCEL_TEXT);
    expect(h.panel().innerHTML, "an answer after the analyst stopped waiting was drawn").not.toContain(
      "row e-1",
    );
  });

  it("does nothing when no review is running", async () => {
    const h = await ready();
    h.el("jevCancelBtn").fire("click");
    await settle();
    expect(h.panel().innerHTML).not.toContain(CANCEL_TEXT);
  });
});

describe("the capped review's own time limit", () => {
  it("gives up after 15 minutes with its own message", async () => {
    const h = await ready();
    const req = startCapped(h);
    await vi.advanceTimersByTimeAsync(15 * MINUTE - 1000);
    expect(req.signal?.aborted).toBe(false);
    expect(h.el("jevRunBtn").disabled).toBe(true);
    await vi.advanceTimersByTimeAsync(1000);
    await settle();
    expect(req.signal?.aborted, "the capped review never timed out").toBe(true);
    expect(h.el("jevRunBtn").disabled).toBe(false);
    expect(h.panel().innerHTML).toContain(TIMEOUT_TEXT);
    expect(h.panel().innerHTML).not.toContain(CANCEL_TEXT);
  });

  it("is cleared when the review answers in time", async () => {
    const h = await ready();
    const req = startCapped(h);
    req.resolve(REVIEW);
    await settle();
    await vi.advanceTimersByTimeAsync(30 * MINUTE);
    expect(h.panel().innerHTML).not.toContain(TIMEOUT_TEXT);
    expect(h.panel().innerHTML).toContain("row e-1");
  });

  it("does not apply to a full read — a large case can take longer", async () => {
    const h = await ready();
    const req = startAll(h);
    expect(h.el("jevCancelBtn").hidden).toBe(false);
    await vi.advanceTimersByTimeAsync(120 * MINUTE);
    expect(req.signal?.aborted, "the full read was cut off by a client timeout").toBe(false);
    expect(h.el("jevRunAllBtn").disabled).toBe(true);
    // The analyst can still stop waiting by hand.
    h.el("jevCancelBtn").fire("click");
    await settle();
    expect(req.signal?.aborted).toBe(true);
    expect(h.panel().innerHTML).toContain(CANCEL_TEXT);
  });
});

describe("other ways a run ends", () => {
  it("still reports an ordinary network error as one", async () => {
    const h = await ready();
    startCapped(h).reject(new Error("socket hang up"));
    await settle();
    expect(h.panel().innerHTML).toContain("The review did not run: socket hang up");
    expect(h.el("jevCancelBtn").hidden).toBe(true);
  });

  it("aborts the request when the analyst switches case", async () => {
    const h = await ready();
    const req = startCapped(h);
    const load = h.api.loadJevReview("case-2");
    h.pending
      .find((p) => p.url.endsWith("/jev/status") && p.url.includes("case-2"))!
      .resolve({
        configured: true,
        model: "typesafe/jev-1.13",
      });
    await load;
    await settle();
    expect(req.signal?.aborted, "the old case's request kept running").toBe(true);
    expect(h.el("jevCancelBtn").hidden).toBe(true);
    // The switch is not the analyst stopping the wait, and the new case carries no message.
    expect(h.panel().innerHTML).not.toContain(CANCEL_TEXT);
    // And the old run's timer cannot fire a timeout onto the new case.
    await vi.advanceTimersByTimeAsync(30 * MINUTE);
    expect(h.panel().innerHTML).not.toContain(TIMEOUT_TEXT);
  });
});

describe("the markup", () => {
  it("ships the stop control hidden, beside the review buttons", async () => {
    const page = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    expect(page).toMatch(/<button type="button" id="jevCancelBtn"[^>]*\bhidden\b/);
    expect(page.indexOf('id="jevCancelBtn"')).toBeGreaterThan(page.indexOf('id="jevRunAllBtn"'));
  });
});
