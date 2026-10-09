// The deep-pass result card says when batches were read by the fallback model (#2076), and the
// fallback setting's hint says it covers the deep pass too.
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface El {
  innerHTML: string;
  textContent: string;
  value: string;
  disabled: boolean;
  style: Record<string, string>;
}
const el = (value = ""): El => ({ innerHTML: "", textContent: "", value, disabled: false, style: {} });
const ok = (body: unknown) => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });

const BASE = {
  aborted: false,
  floor: "Medium",
  events: 300,
  rows: 250,
  batches: 3,
  batchesFailed: 0,
  observations: 9,
};

async function renderResult(result: Record<string, unknown>): Promise<string> {
  const all: Record<string, El> = {
    caseId: el("case-1"),
    deepPassGuidance: el(),
    deepPassProgress: el(),
    deepPassResult: el(),
  };
  const globals = {
    document: {
      getElementById: (id: string) => all[id] ?? null,
      querySelector: () => ({ value: "Medium" }),
      querySelectorAll: (): unknown[] => [],
      addEventListener: () => {},
    },
    fetch: (url: string) => (url.endsWith("/deep-pass") ? ok(result) : ok({})),
    localStorage: { setItem: () => {}, getItem: () => null, removeItem: () => {} },
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
  api.runDeepPass();
  await new Promise((r) => setTimeout(r, 10));
  return all.deepPassResult.innerHTML;
}

describe("deep-pass result names the fallback model (#2076)", () => {
  it("says how many batches the fallback model read after a safety stop", async () => {
    const html = await renderResult({ ...BASE, batchesOnFallback: 2, fallbackModel: "gpt-6-sol" });
    expect(html).toContain("2 batch(es) read by the fallback model");
    expect(html).toContain("gpt-6-sol");
    expect(html).toContain("safety stop");
  });

  it("escapes the model label", async () => {
    const html = await renderResult({ ...BASE, batchesOnFallback: 1, fallbackModel: "<img src=x>" });
    expect(html).not.toContain("<img src=x>");
  });

  it("says nothing about a fallback when none answered", async () => {
    const html = await renderResult({ ...BASE, batchesOnFallback: 0 });
    expect(html).not.toContain("fallback");
  });
});

describe("fallback model setting hint (#2076)", () => {
  it("says the fallback covers synthesis and the deep pass", () => {
    const html = readFileSync(
      fileURLToPath(new URL("../../../public/dashboard.html", import.meta.url)),
      "utf8",
    );
    expect(html).toContain(
      "DFIR_AI_SYNTH_FALLBACK_MODEL — blank = no fallback; synthesis and deep pass, not imports or reports",
    );
  });
});
