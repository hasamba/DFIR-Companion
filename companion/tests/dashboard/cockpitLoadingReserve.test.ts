// Load-time layout shift (#1791).
//
// QA measured CLS 0.33 when a case opens at 1900x1000. The shift is the cockpit ("Now" panel), not
// the Collection Plan: the cockpit loads by its own fetch, AFTER the page's other panels paint, and
// grew from a one-line "Loading…" placeholder to 2,455 px. That pushed everything under it out of
// the viewport; the Collection Plan, which opens right under the cockpit, was simply the largest
// thing it pushed. The fix makes the loading placeholder hold the rest of the viewport, so the
// panels below are off-screen before the cockpit knows its size. Measured after: 0.003.
import { describe, expect, it } from "vitest";
import { dashboardStylesheet, loadDashboardModule } from "../helpers/dashboardModule.js";

interface Api {
  loadCockpit: (caseId?: string) => Promise<void>;
}

function harness(fetchImpl: () => Promise<unknown>) {
  const body = { innerHTML: "" };
  const seen: string[] = [];
  const tracked = {
    get innerHTML() {
      return body.innerHTML;
    },
    set innerHTML(v: string) {
      seen.push(v);
      body.innerHTML = v;
    },
  };
  const caseInput = { value: "c1" };
  const api = loadDashboardModule<Api>(
    "dashboard-cockpit.js",
    ["dashboard-escape.js", "dashboard-time.js", "dashboard-fragments.js", "dashboard-cockpit-story.js"],
    {
      // Page globals the module reads by bare name (dashboard.html declares them).
      lastCockpit: null,
      lastCockpitRenderSignature: "",
      document: {
        getElementById: (id: string) => (id === "cockpitBody" ? tracked : id === "caseId" ? caseInput : null),
      },
      investigatorName: () => "",
      fetch: fetchImpl,
    },
  );
  return { api, seen, body };
}

const snapshot = {
  caseId: "c1",
  phase: "triage",
  sections: {},
  parked: [],
  story: null,
};

describe("cockpit loading placeholder reserves its space (#1791)", () => {
  it("the first placeholder for a case carries now-loading", async () => {
    const h = harness(async () => ({ ok: true, json: async () => snapshot }));
    await h.api.loadCockpit("c1");
    expect(h.seen[0]).toMatch(/class="now-state now-loading"/);
  });

  it("the rendered cockpit replaces it and does not carry now-loading", async () => {
    const h = harness(async () => ({ ok: true, json: async () => snapshot }));
    await h.api.loadCockpit("c1");
    expect(h.seen.length).toBeGreaterThan(1);
    expect(h.body.innerHTML).not.toContain("now-loading");
    expect(h.body.innerHTML).toContain("now-grid");
  });

  it("the stylesheet gives the loading placeholder a viewport-high minimum", () => {
    const css = dashboardStylesheet();
    const rule = css.match(/\.now-state\.now-loading\s*\{([^}]*)\}/);
    expect(rule, "no .now-state.now-loading rule").not.toBeNull();
    expect(rule![1].replace(/\s+/g, "")).toMatch(/min-height:calc\(100vh-\d+px\)/);
  });
});
