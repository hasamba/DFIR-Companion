import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// #1547: the hint paint threw AFTER its test had passed, from a floated promise, and vitest
// reported a run with 3,954 green tests and a red exit. Two things let that happen: an element
// stub with no `classList`, and a fire-and-forget call whose rejection nothing caught. Both are
// pinned here, because neither shows up as a failing assertion anywhere else.

type Surface = { initEnvSettings?: () => void };

/**
 * An element with what the rest of the initializer needs and NOT a classList — which is exactly
 * the shape the settings harness hands back, and exactly the shape that broke this.
 */
const stubEl = () => ({
  textContent: "",
  value: "",
  dataset: { aiModelsWired: "1" },
  addEventListener: () => {},
  appendChild: () => {},
  querySelectorAll: () => [],
});

function load(extra: Record<string, unknown>) {
  return loadDashboardModule<Surface>("dashboard-env-settings.js", [], {
    document: { getElementById: () => stubEl(), addEventListener: () => {}, querySelectorAll: () => [] },
    fetch: () => Promise.reject(new Error("no network in this test")),
    ...extra,
  });
}

describe("the Jev key hint never takes the page down with it", () => {
  it("paints onto an element with no classList without throwing", () => {
    // Fires only the listeners the Jev fields register. That path calls the paint DIRECTLY, with
    // no try/catch above it, so it is what proves the classList guard rather than the guard around
    // the probe. Other fields on this screen register their own listeners that want a richer DOM;
    // firing those too would fail for reasons that have nothing to do with this hint.
    const JEV_IDS = ["env-DFIR_JEV_PROVIDER", "env-DFIR_JEV_KEY"];
    const fired: Array<() => void> = [];
    const els = new Map<string, Record<string, unknown>>();
    const doc = {
      getElementById: (id: string) => {
        if (!els.has(id)) {
          els.set(id, {
            ...stubEl(),
            addEventListener: (_t: string, fn: () => void) => {
              if (JEV_IDS.includes(id)) fired.push(fn);
            },
          });
        }
        return els.get(id);
      },
      addEventListener: () => {},
      querySelectorAll: () => [],
    };
    const mod = loadDashboardModule<Surface>("dashboard-env-settings.js", [], {
      document: doc,
      fetch: () => Promise.reject(new Error("no network in this test")),
    });
    mod.initEnvSettings?.();
    expect(fired.length, "the provider and key fields must both be wired").toBe(2);
    for (const fire of fired) expect(fire).not.toThrow();
  });

  it("survives a probe that rejects, without an unhandled rejection", async () => {
    const rejections: unknown[] = [];
    const onRejection = (e: unknown) => rejections.push(e);
    process.on("unhandledRejection", onRejection);
    try {
      load({}).initEnvSettings?.();
      // Let the floated promise settle and any rejection surface.
      await new Promise((r) => setTimeout(r, 20));
    } finally {
      process.off("unhandledRejection", onRejection);
    }
    expect(rejections).toEqual([]);
  });

  it("survives a probe that resolves into an element that cannot take a class", async () => {
    const rejections: unknown[] = [];
    const onRejection = (e: unknown) => rejections.push(e);
    process.on("unhandledRejection", onRejection);
    try {
      load({
        fetch: () => Promise.resolve({ ok: true, json: () => Promise.resolve({ inheritable: false }) }),
      }).initEnvSettings?.();
      await new Promise((r) => setTimeout(r, 20));
    } finally {
      process.off("unhandledRejection", onRejection);
    }
    expect(rejections).toEqual([]);
  });
});
