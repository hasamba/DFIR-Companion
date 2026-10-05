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

describe("the Settings bundle library", () => {
  // The list renders at page load so bundles can be built with no case open. Run used to sit here
  // too, gated on the connected case; it moved to the dashboard's Fleet Collection panel (the
  // case-scoped surface — see dashboardVeloCollect.test.ts). Settings is global, so the library
  // must offer the editing controls and never a Run.
  it("offers the editing controls with no case connected", async () => {
    await triage.loadVeloBundles();
    expect(bundleList.innerHTML).toContain("velo-edit-btn");
    expect(bundleList.innerHTML).not.toContain("velo-run-btn");
    expect(bundleList.innerHTML).not.toContain("Connect to a case first");
  });

  it("never grows a Run button once a case is connected", async () => {
    triage.activeCaseId = "c1";
    await triage.loadVeloBundles();
    expect(bundleList.innerHTML).toContain("velo-edit-btn");
    expect(bundleList.innerHTML).not.toContain("velo-run-btn");
  });
});

// #1965: a hunt or flow already pulled into the case answers 409 { alreadyImported } before any
// Velociraptor read. The panel says when, and offers "Re-import anyway" — never a block, since a
// running hunt can gain rows. The Import button calls veloImportExternal with its click event, so
// only a literal `true` may ask for the re-import.
describe("import external: already pulled into this case", () => {
  const reimportBtn = { onclick: null as null | (() => void) };
  const extMsg = {
    textContent: "",
    innerHTML: "",
    querySelector: (sel: string) => (sel === ".velo-reimport-btn" ? reimportBtn : null),
  };
  const extEls: Record<string, unknown> = {
    veloExtMsg: extMsg,
    veloExtRef: { value: " H.ABC " },
    veloExtMinsev: { value: "" },
    veloExtSuper: { checked: false },
    veloExtGo: { disabled: false },
  };
  const bodies: Record<string, unknown>[] = [];
  let answer: { status: number; json: unknown } = { status: 200, json: {} };
  const ext = loadDashboardModule<{
    veloImportExternal(reimport?: unknown): void;
    activeCaseId: string | null;
  }>("dashboard-velo-triage.js", ["dashboard-escape.js", "dashboard-velo-case.js"], {
    document: { getElementById: (id: string) => extEls[id] ?? null },
    fetch: async (_url: string, init: { body: string }) => {
      bodies.push(JSON.parse(init.body));
      const { status, json } = answer;
      return { ok: status < 300, status, json: async () => json };
    },
    activeCaseId: "c1",
    veloEnabled: true,
  });
  const settle = () => new Promise((r) => setTimeout(r, 0));

  const PRIOR = {
    alreadyImported: {
      kind: "hunt",
      huntId: "H.ABC",
      firstImportedAt: "2026-10-01T09:00:00.000Z",
      lastImportedAt: "2026-10-02T10:30:00.000Z",
      artifacts: ["Windows.NTFS.MFT", "Windows.System.Pslist"],
    },
  };

  beforeEach(() => {
    bodies.length = 0;
    reimportBtn.onclick = null;
    extMsg.innerHTML = "";
    extMsg.textContent = "";
    ext.activeCaseId = "c1";
  });

  it("does not ask for a re-import when the Import button passes its click event", async () => {
    answer = { status: 200, json: { kind: "hunt", huntId: "H.ABC", artifacts: [] } };
    ext.veloImportExternal({ type: "click" });
    await settle();
    expect(bodies[0].reimport).toBe(false);
  });

  it("shows the prior import date and a Re-import anyway button, and the click re-imports", async () => {
    answer = { status: 409, json: PRIOR };
    ext.veloImportExternal({ type: "click" });
    await settle();
    expect(extMsg.innerHTML).toContain("already pulled into this case");
    expect(extMsg.innerHTML).toContain("2026-10-02");
    expect(extMsg.innerHTML).toContain("2 artifact(s)");
    expect(extMsg.innerHTML).toContain("velo-reimport-btn");
    expect(extMsg.innerHTML).toContain("Re-import anyway");
    expect(extMsg.innerHTML).not.toContain("error:");
    expect(typeof reimportBtn.onclick).toBe("function");

    answer = { status: 200, json: { kind: "hunt", huntId: "H.ABC", artifacts: ["Windows.NTFS.MFT"] } };
    reimportBtn.onclick?.();
    await settle();
    expect(bodies).toHaveLength(2);
    expect(bodies[1]).toMatchObject({ ref: "H.ABC", reimport: true });
  });

  it("escapes the server's strings", async () => {
    answer = {
      status: 409,
      json: { alreadyImported: { ...PRIOR.alreadyImported, huntId: "H.<i>x</i>" } },
    };
    ext.veloImportExternal();
    await settle();
    expect(extMsg.innerHTML).not.toContain("<i>");
    expect(extMsg.innerHTML).toContain("&lt;i&gt;");
  });
});
