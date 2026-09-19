import { beforeEach, describe, expect, it } from "vitest";
import type { VeloCollectApi, VeloTriageApi } from "./dashboardApi.js";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// public/js/dashboard-velo-collect.js — the Fleet Collection panel's run list.
//
// SETTINGS IS GLOBAL; RUNNING A BUNDLE IS NOT. Every Settings tab configures the application — except
// the Velociraptor tab, where "▶ Run" launched a hunt into the connected case from between Edit and
// Delete. The run list now lives on the dashboard, next to the hunts it feeds, and the Settings tab
// keeps only the shared bundle library. These tests pin both halves: the panel offers Run (or says
// why it cannot), and the library never does.

const picker = { value: "  remembered-case  " };
const runList = { innerHTML: "", querySelectorAll: () => [] as unknown[] };
const bundleList = { innerHTML: "", querySelectorAll: () => [] as unknown[] };
const BUNDLES = [
  { id: "best-practice", name: "Best Practice", artifacts: ["Windows.System.Pslist"], builtIn: true },
  { id: "custom-1", name: "Custom", artifacts: ["Linux.Sys.Pslist"], description: "mine" },
];

const document = {
  getElementById: (id: string) =>
    id === "veloRunList" ? runList : id === "veloBundleList" ? bundleList : id === "caseId" ? picker : null,
  querySelectorAll: () => [] as unknown[],
};

const collect = loadDashboardModule<VeloCollectApi>(
  "dashboard-velo-collect.js",
  ["dashboard-escape.js", "dashboard-velo-case.js"],
  { document, activeCaseId: null, veloEnabled: true },
);

// The triage module loads the bundles and fans out to BOTH lists; the collect module must be on the
// page for the run list to render at all.
const triage = loadDashboardModule<VeloTriageApi>(
  "dashboard-velo-triage.js",
  ["dashboard-escape.js", "dashboard-velo-case.js", "dashboard-velo-collect.js"],
  {
    document,
    fetch: async () => ({ ok: true, json: async () => BUNDLES }),
    activeCaseId: null,
    veloEnabled: true,
  },
);

beforeEach(() => {
  collect.activeCaseId = null;
  collect.veloEnabled = true;
  triage.activeCaseId = null;
  triage.veloEnabled = true;
  runList.innerHTML = "";
  bundleList.innerHTML = "";
});

describe("renderVeloRunList", () => {
  it("is disabled, and says why, with no case connected", () => {
    collect.renderVeloRunList(BUNDLES);
    expect(runList.innerHTML).toContain("Connect to a case first");
    expect(runList.innerHTML).not.toContain("velo-run-btn");
  });

  it("is live once a case is connected", () => {
    collect.activeCaseId = "c1";
    collect.renderVeloRunList(BUNDLES);
    expect(runList.innerHTML).toContain("velo-run-btn");
    expect(runList.innerHTML).not.toContain("Connect to a case first");
  });

  it("still names the unconfigured server when there is one", () => {
    collect.veloEnabled = false;
    collect.activeCaseId = "c1";
    collect.renderVeloRunList(BUNDLES);
    expect(runList.innerHTML).toContain("Velociraptor API not configured");
  });

  it("names every bundle and where to edit it, never the editing controls themselves", () => {
    collect.activeCaseId = "c1";
    collect.renderVeloRunList(BUNDLES);
    expect(runList.innerHTML).toContain("Best Practice");
    expect(runList.innerHTML).toContain("Custom");
    expect(runList.innerHTML).toContain("velo-run-form");
    for (const cls of ["velo-edit-btn", "velo-dup-btn", "velo-del-btn", "velo-reset-btn"]) {
      expect(runList.innerHTML, cls).not.toContain(cls);
    }
  });

  it("folds each bundle's artifact list into a collapsed toggle", () => {
    collect.activeCaseId = "c1";
    collect.renderVeloRunList(BUNDLES);
    const html = runList.innerHTML;
    // One <details> per bundle, never pre-opened, with the count as its summary and the names inside.
    expect(html.match(/<details class="velo-artifacts"/g)?.length).toBe(BUNDLES.length);
    expect(html).not.toMatch(/<details class="velo-artifacts"[^>]*\sopen/);
    expect(html).toMatch(/<summary[^>]*>1 artifact\(s\)<\/summary>/);
    const inner = html.slice(html.indexOf("<details"), html.indexOf("</details>"));
    expect(inner).toContain("Windows.System.Pslist");
  });

  it("points at the Settings library when there is nothing to run", () => {
    collect.renderVeloRunList([]);
    expect(runList.innerHTML).toContain("No bundles yet");
    expect(runList.innerHTML).toContain("velo-open-library");
  });

  it("survives a page without the panel", () => {
    const bare = loadDashboardModule<VeloCollectApi>(
      "dashboard-velo-collect.js",
      ["dashboard-escape.js", "dashboard-velo-case.js"],
      { document: { getElementById: () => null }, activeCaseId: "c1", veloEnabled: true },
    );
    expect(() => bare.renderVeloRunList(BUNDLES)).not.toThrow();
  });
});

describe("the bundle load fans out", () => {
  it("renders the run list on the dashboard and the library in Settings from one fetch", async () => {
    triage.activeCaseId = "c1";
    await triage.loadVeloBundles();
    expect(runList.innerHTML).toContain("velo-run-btn");
    expect(bundleList.innerHTML).toContain("velo-edit-btn");
  });

  it("never puts a Run button in the Settings library, however live the case is", async () => {
    triage.activeCaseId = "c1";
    await triage.loadVeloBundles();
    expect(bundleList.innerHTML).not.toContain("velo-run-btn");
    expect(bundleList.innerHTML).not.toContain("velo-run-form");
    expect(bundleList.innerHTML).not.toContain("Connect to a case first");
  });
});
