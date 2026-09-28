// #1783: the Analysis run ledger overlay waited on the run list AND the integrity check together,
// with no time limit, so one slow request left "loading…" on screen for good. Now the list renders
// as soon as it arrives, each request has its own time limit, and a late answer from an older open
// never writes over a newer one.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface RunsApi {
  openAnalysisRuns: () => Promise<unknown>;
}

const RUN = {
  id: "run-1",
  kind: "synthesis",
  startedAt: "2026-09-24T08:49:00Z",
  durationMs: 1200,
  input: { eventCount: 3 },
  output: { claimCount: 2 },
  versions: { application: "1.0.0" },
};

interface Pending {
  url: string;
  resolve: (v: unknown) => void;
  reject: (e: unknown) => void;
  signal?: AbortSignal;
}

function el() {
  return {
    textContent: "",
    innerHTML: "",
    value: "",
    selectedIndex: -1,
    style: { color: "", display: "" } as Record<string, string>,
    classList: { add: () => {}, remove: () => {} },
    querySelectorAll: () => [],
  };
}

/** A page whose fetches stay pending until the test answers them, one by one. */
function harness() {
  const elements: Record<string, ReturnType<typeof el>> = {};
  const get = (id: string) => (elements[id] ??= el());
  get("caseId").value = "case-1";
  const pending: Pending[] = [];
  const globals = {
    document: { getElementById: get },
    fetch: (url: string, init?: { signal?: AbortSignal }) =>
      new Promise((resolve, reject) => {
        const p: Pending = { url, resolve, reject, signal: init?.signal };
        init?.signal?.addEventListener("abort", () => reject(new Error("The operation was aborted")));
        pending.push(p);
      }),
    setTimeout: (fn: () => void, ms: number) => setTimeout(fn, ms),
    clearTimeout: (t: ReturnType<typeof setTimeout>) => clearTimeout(t),
    AbortController,
    analysisRunLabel: (r: { id: string }) => r.id,
  };
  const api = loadDashboardModule<RunsApi>("dashboard-analysis-runs.js", ["dashboard-escape.js"], globals);
  const answer = (match: RegExp, body: unknown, ok = true, status = ok ? 200 : 500) => {
    const i = pending.findIndex((p) => match.test(p.url));
    const [p] = pending.splice(i, 1);
    p.resolve({ ok, status, json: () => Promise.resolve(body) });
  };
  return { api, get, pending, answer };
}

const RUNS = /analysis-runs$/;
const INTEGRITY = /analysis-runs\/integrity$/;
const flush = async () => {
  for (let i = 0; i < 20; i++) await Promise.resolve();
};

beforeEach(() => vi.useFakeTimers());
afterEach(() => vi.useRealTimers());

describe("the run ledger overlay", () => {
  it("lists the runs while the integrity check is still running", async () => {
    const h = harness();
    void h.api.openAnalysisRuns();
    h.answer(RUNS, [RUN]);
    await flush();
    expect(h.get("arList").innerHTML).toContain("synthesis");
    expect(h.get("arIntegrity").textContent).toBe("checking integrity…");
    h.answer(INTEGRITY, { ok: true, manifests: 1 });
    await flush();
    expect(h.get("arIntegrity").textContent).toContain("Ledger intact");
  });

  it("says the integrity check timed out instead of waiting for ever", async () => {
    const h = harness();
    void h.api.openAnalysisRuns();
    h.answer(RUNS, [RUN]);
    await vi.advanceTimersByTimeAsync(15000);
    const text = h.get("arIntegrity").textContent;
    expect(text).toBe("Integrity check timed out — close and reopen to retry.");
    expect(text).not.toContain("FAILED");
    expect(h.get("arList").innerHTML).toContain("synthesis");
  });

  it("says the run list is still loading after the limit, and how to retry", async () => {
    const h = harness();
    void h.api.openAnalysisRuns();
    h.answer(INTEGRITY, { ok: true, manifests: 0 });
    await vi.advanceTimersByTimeAsync(15000);
    expect(h.get("arList").textContent).toBe("Still loading after 15 s — close and reopen to retry.");
  });

  it("does not let an older open's timeout or late answer overwrite a newer one", async () => {
    const h = harness();
    void h.api.openAnalysisRuns(); // first open: both requests stall
    const [oldRuns, oldIntegrity] = [...h.pending];
    h.pending.length = 0;
    await vi.advanceTimersByTimeAsync(5000);
    void h.api.openAnalysisRuns(); // reopen
    h.answer(RUNS, [RUN]);
    h.answer(INTEGRITY, { ok: true, manifests: 1 });
    await flush();
    await vi.advanceTimersByTimeAsync(15000); // the first open's timers fire now
    oldRuns.resolve({ ok: true, status: 200, json: () => Promise.resolve([]) });
    oldIntegrity.reject(new Error("late"));
    await flush();
    expect(h.get("arList").innerHTML).toContain("synthesis");
    expect(h.get("arList").textContent).not.toContain("Still loading");
    expect(h.get("arIntegrity").textContent).toContain("Ledger intact");
  });

  // Only a real verification result may say FAILED. Nothing was verified on these answers.
  it.each([
    ["501, runs not configured", { error: "analysis runs not configured" }, 501],
    ["a JSON 500", { error: "boom" }, 500],
    ["a malformed 200", { manifests: 3 }, 200],
  ])("does not report ledger corruption on %s", async (_label, body, status) => {
    const h = harness();
    void h.api.openAnalysisRuns();
    h.answer(INTEGRITY, body, status === 200, status);
    await flush();
    const text = h.get("arIntegrity").textContent;
    expect(text).toMatch(/^Integrity check did not answer/);
    expect(text).not.toContain("FAILED");
  });

  it("reports a real broken chain (409 with problems) as FAILED", async () => {
    const h = harness();
    void h.api.openAnalysisRuns();
    h.answer(INTEGRITY, { ok: false, manifests: 2, problems: ["hash mismatch at run-2"] }, false, 409);
    await flush();
    expect(h.get("arIntegrity").textContent).toBe("⚠ Ledger integrity FAILED — hash mismatch at run-2");
  });

  it("still reports a server error on the run list", async () => {
    const h = harness();
    void h.api.openAnalysisRuns();
    h.answer(RUNS, { error: "disk full" }, false);
    await flush();
    expect(h.get("arList").textContent).toBe("failed to load: disk full");
  });
});
