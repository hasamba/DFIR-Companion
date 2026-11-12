import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// #2603: when the synthesis model's safety filter stopped the answer and the fallback model wrote
// the findings, the Findings card's synthesis strip says so — which model was stopped, how many
// times, and which model wrote what the analyst is reading. A run with no fallback shows nothing.

interface Api {
  loadSynthMeta(caseId: string): void;
}

const settle = () => new Promise((r) => setTimeout(r, 0));

async function render(meta: unknown): Promise<string> {
  const synthMeta = { innerHTML: "", style: {} as Record<string, string> };
  const globals = {
    document: {
      getElementById: (id: string) => (id === "synthMeta" ? synthMeta : null),
      addEventListener: () => {},
    },
    fetch: () => Promise.resolve({ ok: true, json: () => Promise.resolve(meta) }),
  };
  const api = loadDashboardModule<Api>(
    "dashboard-narrative.js",
    ["dashboard-escape.js", "dashboard-time.js"],
    globals,
  );
  api.loadSynthMeta("c1");
  await settle();
  await settle();
  return synthMeta.innerHTML;
}

const BASE = {
  lastSynthesizedAt: "2026-11-12T10:00:00.000Z",
  lastDiff: { added: [], removed: [], severityChanged: [] },
  findingsCount: 3,
};

describe("synthesis fallback notice on the Findings card (#2603)", () => {
  it("names the stopped model, the stop count and the fallback model", async () => {
    const html = await render({
      ...BASE,
      synthModel: "gpt-6-sol",
      synthFallback: { from: "opus", to: "gpt-6-sol", safetyStops: 2 },
    });
    expect(html).toContain("synth-fallback");
    expect(html).toContain("opus's safety filter stopped this synthesis 2 times");
    expect(html).toContain("the fallback model <strong>gpt-6-sol</strong> wrote these findings");
    expect(html).toContain("var(--sev-medium)");
  });

  it("says 1 time, not 1 times", async () => {
    const html = await render({
      ...BASE,
      synthModel: "gpt-6-sol",
      synthFallback: { from: "opus", to: "gpt-6-sol", safetyStops: 1 },
    });
    expect(html).toContain("stopped this synthesis 1 time;");
  });

  it("shows no notice for a run on the synthesis model", async () => {
    const html = await render({ ...BASE, synthModel: "opus" });
    expect(html).toContain("opus");
    expect(html).not.toContain("synth-fallback");
    expect(html).not.toContain("fallback model");
  });

  it("escapes both model labels", async () => {
    const bad = '<img src=x onerror="alert(1)">';
    const html = await render({
      ...BASE,
      synthModel: bad,
      synthFallback: { from: bad, to: bad, safetyStops: "<b>2</b>" },
    });
    expect(html).not.toContain("<img");
    expect(html).not.toContain("<b>2</b>");
    expect(html).toContain("&lt;img");
  });
});
