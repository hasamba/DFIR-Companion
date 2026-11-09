// #2468: on an empty case the deep-pass preview returned floors that all read 0 events, and the
// panel drew a table of zeros with every radio disabled and no sentence saying why. All-zero floors
// now get the same "nothing to read" sentence as no floors at all.
import { describe, it, expect } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface El {
  innerHTML: string;
  textContent: string;
  value: string;
  disabled: boolean;
  style: Record<string, string>;
  querySelectorAll: () => unknown[];
}
const el = (value = ""): El => ({
  innerHTML: "",
  textContent: "",
  value,
  disabled: false,
  style: {},
  querySelectorAll: () => [],
});
const ok = (body: unknown) => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });

const floor = (name: string, events: number) => ({
  floor: name,
  events,
  rows: events,
  batches: events ? 1 : 0,
  estimatedInputTokens: events * 10,
});

async function preview(floors: unknown[]): Promise<string> {
  return (await previewEls(floors)).deepPassFloors.innerHTML;
}

async function previewEls(floors: unknown[]): Promise<Record<string, El>> {
  const all: Record<string, El> = {
    caseId: el("case-1"),
    deepPassFloors: el(),
    deepPassGuidance: el(),
    deepPassResult: el(),
    deepPassRun: el(),
  };
  const api = loadDashboardModule<{
    loadDeepPassPreview: (force?: boolean) => void;
    setDeepPassSynthesisEnabled: (on: boolean) => void;
  }>("dashboard-deep-pass.js", ["dashboard-escape.js", "dashboard-values.js", "dashboard-presidio.js"], {
    document: {
      getElementById: (id: string) => all[id] ?? null,
      querySelector: () => null,
      querySelectorAll: (): unknown[] => [],
      addEventListener: () => {},
    },
    fetch: () => ok({ cap: 400, floors }),
    localStorage: { setItem: () => {}, getItem: () => null, removeItem: () => {} },
    applyHeavyAiJobLock: () => {},
  });
  // A provider is set, so the gate's answer turns on the floor pick alone, not "no provider".
  api.setDeepPassSynthesisEnabled(true);
  api.loadDeepPassPreview(true);
  await new Promise((r) => setTimeout(r, 10));
  return all;
}

const SENTENCE = "No graded events in scope — nothing for a deep pass to read.";

describe("deep-pass preview on an empty case (#2468)", () => {
  it("says there is nothing to read when every floor has 0 events", async () => {
    const html = await preview([floor("Critical", 0), floor("High", 0), floor("Medium", 0), floor("Low", 0)]);
    expect(html).toBe(SENTENCE);
  });

  it("re-runs the Run gate, so a refresh to an empty case cannot leave Run enabled", async () => {
    const all = await previewEls([floor("High", 0)]);
    expect(all.deepPassRun.disabled).toBe(true);
  });

  it("keeps the sentence for no floors at all", async () => {
    expect(await preview([])).toBe(SENTENCE);
  });

  it("still draws the table when any floor has events", async () => {
    const html = await preview([floor("Critical", 0), floor("High", 3)]);
    expect(html).toContain("dp-table");
    expect(html).not.toContain(SENTENCE);
  });
});
