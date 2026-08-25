import { beforeEach, describe, expect, it } from "vitest";
import type { VeloCaseApi, VeloTriageApi } from "./dashboardApi.js";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// public/js/dashboard-velo-case.js + the Run button it gates in public/js/dashboard-velo-triage.js.
//
// THE PICKER IS NOT THE CASE. js/dashboard-case-connect.js pre-fills #caseId from localStorage on a
// bare /dashboard and deliberately does NOT connect, so "the field has a value" was true on a page
// where no case had been opened — and every Velociraptor guard spelled "connect to a case first" as
// `if (!caseId)` over exactly that field. Run launched a hunt on live endpoints for a case the
// analyst had not opened, and (for a typed-in id) for one that had never existed at all.

// A picker holding a case that was never connected — the state a bare /dashboard loads into.
const picker = { value: "  remembered-case  " };
const bundleList = { innerHTML: "", querySelectorAll: () => [] as unknown[] };
const BUNDLES = [{ id: "best-practice", name: "Best Practice", artifacts: ["Windows.System.Pslist"] }];

const document = {
  getElementById: (id: string) => (id === "veloBundleList" ? bundleList : id === "caseId" ? picker : null),
};

const veloCase = loadDashboardModule<VeloCaseApi>("dashboard-velo-case.js", [], {
  document,
  activeCaseId: null, // page vocabulary (a top-level let in dashboard.html)
});

const triage = loadDashboardModule<VeloTriageApi>(
  "dashboard-velo-triage.js",
  ["dashboard-escape.js", "dashboard-velo-case.js"],
  {
    document,
    fetch: async () => ({ ok: true, json: async () => BUNDLES }),
    activeCaseId: null,
    veloEnabled: true,
  },
);

beforeEach(() => {
  veloCase.activeCaseId = null;
  triage.activeCaseId = null;
  triage.veloEnabled = true;
  bundleList.innerHTML = "";
});

describe("veloCaseId", () => {
  it("is empty when no case is connected, however full the picker is", () => {
    expect(picker.value.trim()).not.toBe(""); // the trap: a pre-filled, unconnected case
    expect(veloCase.veloCaseId()).toBe("");
  });

  it("is the connected case once one is loaded", () => {
    veloCase.activeCaseId = "c1";
    expect(veloCase.veloCaseId()).toBe("c1");
  });

  // Cancelling a case load clears activeCaseId but leaves the id sitting in the picker.
  it("goes empty again when a case load is cancelled", () => {
    veloCase.activeCaseId = "c1";
    expect(veloCase.veloCaseId()).toBe("c1");
    veloCase.activeCaseId = null;
    expect(veloCase.veloCaseId()).toBe("");
  });
});

describe("veloRunBlockedReason", () => {
  it("blocks on a missing case even with the server configured", () => {
    expect(veloCase.veloRunBlockedReason(true, "")).toContain("Connect to a case first");
  });

  it("reports the unconfigured server first — that is the blocker the analyst can act on", () => {
    expect(veloCase.veloRunBlockedReason(false, "c1")).toContain("not configured");
    expect(veloCase.veloRunBlockedReason(false, "")).toContain("not configured");
  });

  it("clears once both hold", () => {
    expect(veloCase.veloRunBlockedReason(true, "c1")).toBe("");
  });
});

describe("the bundle list's Run button", () => {
  // The list renders at page load so bundles can be built with no case open — which is exactly why
  // Velociraptor-is-configured was never enough on its own to make Run live.
  it("is disabled, and says why, with no case connected", async () => {
    await triage.loadVeloBundles();
    expect(bundleList.innerHTML).toContain("Connect to a case first");
    expect(bundleList.innerHTML).not.toContain("velo-run-btn");
  });

  it("is live once a case is connected", async () => {
    triage.activeCaseId = "c1";
    await triage.loadVeloBundles();
    expect(bundleList.innerHTML).toContain("velo-run-btn");
    expect(bundleList.innerHTML).not.toContain("Connect to a case first");
  });

  it("still names the unconfigured server when there is one", async () => {
    triage.veloEnabled = false;
    triage.activeCaseId = "c1";
    await triage.loadVeloBundles();
    expect(bundleList.innerHTML).toContain("Velociraptor API not configured");
  });
});
