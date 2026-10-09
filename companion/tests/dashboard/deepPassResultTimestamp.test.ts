// The card for a deep pass that just finished shows when it ran (#2068).
//
// The run time was stamped only onto the localStorage copy, while the fresh render used the raw
// server response, so "What did my last deep pass do?" had no timestamp until a reload. The stamp
// must also survive a blocked localStorage (private window), where setItem throws.
import { describe, it, expect } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface El {
  innerHTML: string;
  textContent: string;
  value: string;
  disabled: boolean;
  style: Record<string, string>;
}
const el = (value = ""): El => ({ innerHTML: "", textContent: "", value, disabled: false, style: {} });

const RESULT = {
  aborted: false,
  floor: "High",
  events: 10,
  rows: 8,
  batches: 1,
  batchesFailed: 0,
  observations: 3,
};

const ok = (body: unknown) => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });

function finishedRunPage(setItem: (k: string, v: string) => void) {
  const all: Record<string, El> = {
    caseId: el("case-1"),
    deepPassGuidance: el(),
    deepPassProgress: el(),
    deepPassResult: el(),
  };
  const globals = {
    document: {
      getElementById: (id: string) => all[id] ?? null,
      querySelector: () => ({ value: "High" }),
      querySelectorAll: (): unknown[] => [],
      addEventListener: () => {},
    },
    fetch: (url: string) => (url.endsWith("/deep-pass") ? ok(RESULT) : ok({})),
    localStorage: { setItem, getItem: () => null, removeItem: () => {} },
    applyHeavyAiJobLock: () => {},
    loadJobs: () => {},
    loadSynthMeta: () => {},
    render: () => {},
  };
  const api = loadDashboardModule<{ runDeepPass: () => void }>(
    "dashboard-deep-pass.js",
    ["dashboard-escape.js", "dashboard-values.js", "dashboard-presidio.js"],
    globals,
  );
  return { all, api };
}

const settle = () => new Promise((r) => setTimeout(r, 10));
const ISO_STAMP = /\(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/;

describe("a freshly finished deep pass shows its run time (#2068)", () => {
  it("renders the timestamp without a reload, and stores the same stamp", async () => {
    const stored: Record<string, string> = {};
    const { all, api } = finishedRunPage((k, v) => {
      stored[k] = v;
    });
    api.runDeepPass();
    await settle();
    const html = all.deepPassResult.innerHTML;
    expect(html).toContain("What did my last deep pass do?");
    expect(html).toMatch(ISO_STAMP);
    const saved = Object.values(stored).map((v) => JSON.parse(v) as { at?: string });
    expect(saved).toHaveLength(1);
    expect(html).toContain(`(${saved[0].at})`);
  });

  it("still renders the timestamp when localStorage refuses the write", async () => {
    const { all, api } = finishedRunPage(() => {
      throw new Error("QuotaExceededError");
    });
    api.runDeepPass();
    await settle();
    expect(all.deepPassResult.innerHTML).toContain("What did my last deep pass do?");
    expect(all.deepPassResult.innerHTML).toMatch(ISO_STAMP);
  });
});
