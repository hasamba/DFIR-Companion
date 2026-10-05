import { describe, it, expect } from "vitest";
import { backfillHighSeverityFindings } from "../../src/analysis/highSeverityFindings.js";
import { absorbedHighRowIds } from "../../src/analysis/absorbedHighRows.js";
import {
  emptyState,
  type Finding,
  type ForensicEvent,
  type InvestigationState,
} from "../../src/analysis/stateTypes.js";

// #1943: a finding that groups many rows can absorb a High row from a different step. When the
// finding's text names neither the row's file nor its folder, and the row sits in a folder no other
// cited row shares, the row gets its own High finding.

const UPLOADS = "C:\\inetpub\\wwwroot\\uploads";
const AUTH = "C:\\inetpub\\wwwroot\\auth";

function ev(over: Partial<ForensicEvent> & { id: string }): ForensicEvent {
  return {
    timestamp: "2026-05-26T12:25:36Z",
    description: "File written",
    severity: "Medium",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...over,
  };
}

function finding(id: string, relatedEventIds: string[], over: Partial<Finding> = {}): Finding {
  return {
    id,
    severity: "High",
    title: "Webshell copies dropped",
    description: `Several ASPX webshell copies were written to the uploads folder.`,
    relatedIocs: [],
    mitreTechniques: [],
    sourceScreenshots: [],
    firstSeen: "t0",
    lastUpdated: "t0",
    status: "open",
    relatedEventIds,
    ...over,
  };
}

// e1–e3 in uploads, e4 (High) in auth. All four cited by f1.
function scenario(
  opts: { f1?: Partial<Finding>; e4?: Partial<ForensicEvent>; cite?: string[] } = {},
): InvestigationState {
  const state = emptyState("c1");
  const cite = opts.cite ?? ["e1", "e2", "e3", "e4"];
  state.forensicTimeline.push(
    ev({ id: "e1", path: `${UPLOADS}\\a.aspx`, relatedFindingIds: ["f1"] }),
    ev({ id: "e2", path: `${UPLOADS}\\b.aspx`, relatedFindingIds: ["f1"] }),
    ev({ id: "e3", path: `${UPLOADS}\\c.aspx`, relatedFindingIds: ["f1"] }),
    ev({
      id: "e4",
      path: `${AUTH}\\login.aspx`,
      severity: "High",
      description: "Authentication page overwritten",
      relatedFindingIds: ["f1"],
      ...opts.e4,
    }),
  );
  state.findings.push(finding("f1", cite, opts.f1));
  return state;
}

const ALL = new Set(["e1", "e2", "e3", "e4"]);

function e4Of(state: InvestigationState): ForensicEvent {
  return state.forensicTimeline.find((e) => e.id === "e4")!;
}

describe("absorbed High row backfill (#1943)", () => {
  it("gives a High row in another folder its own finding when the citing finding does not name it", () => {
    const out = backfillHighSeverityFindings(scenario(), ALL, "t");
    const auto = out.findings.find((f) => f.id === "f-auto-e4");
    expect(auto).toBeDefined();
    expect(auto!.severity).toBe("High");
    // The model's citation stays; the auto link is added.
    expect(e4Of(out).relatedFindingIds).toEqual(["f1", "f-auto-e4"]);
    expect(out.findings).toHaveLength(2);
  });

  it("does not split the row out when the finding names its file", () => {
    const state = scenario({ f1: { description: "Webshells in uploads; login.aspx was also replaced." } });
    expect(backfillHighSeverityFindings(state, ALL, "t")).toBe(state);
  });

  it("does not split the row out when the finding names its folder", () => {
    const state = scenario({ f1: { title: "Webshells dropped in uploads and auth" } });
    expect(backfillHighSeverityFindings(state, ALL, "t")).toBe(state);
  });

  it("does not split the row out when the finding names its full parent path", () => {
    const state = scenario({
      f1: { description: "Files written under c:/inetpub/wwwroot/auth and uploads." },
    });
    expect(backfillHighSeverityFindings(state, ALL, "t")).toBe(state);
  });

  it("does not treat a folder name inside a longer word as naming it", () => {
    const state = scenario({ f1: { description: "Authoring tool wrote webshells to uploads." } });
    const out = backfillHighSeverityFindings(state, ALL, "t");
    expect(out.findings.map((f) => f.id)).toContain("f-auto-e4");
  });

  it("does nothing when the finding cites only 2 rows in 2 folders", () => {
    const state = scenario({ cite: ["e1", "e4"] });
    expect(backfillHighSeverityFindings(state, ALL, "t")).toBe(state);
  });

  it("does nothing when another cited row shares the High row's folder", () => {
    const state = scenario();
    state.forensicTimeline.push(ev({ id: "e5", path: `${AUTH}\\other.aspx`, relatedFindingIds: ["f1"] }));
    state.findings[0] = { ...state.findings[0], relatedEventIds: ["e1", "e2", "e3", "e4", "e5"] };
    expect(backfillHighSeverityFindings(state, ALL, "t")).toBe(state);
  });

  it("does nothing when the row reaches the finding only through a grouped-burst link", () => {
    // e4 carries f1's link, but f1 does not cite e4 directly (#1702 burst membership).
    const state = scenario({ cite: ["e1", "e2", "e3"] });
    expect(backfillHighSeverityFindings(state, ALL, "t")).toBe(state);
  });

  it("does nothing when a second citing finding names the row", () => {
    const state = scenario({ e4: { relatedFindingIds: ["f1", "f2"] } });
    state.findings.push(
      finding("f2", ["e4"], { title: "Login page replaced", description: "login.aspx was overwritten." }),
    );
    expect(backfillHighSeverityFindings(state, ALL, "t")).toBe(state);
  });

  it("ignores a dismissed or auto citing finding as an absorber", () => {
    const dismissed = scenario({ f1: { status: "dismissed" } });
    expect(absorbedHighRowIds(dismissed).size).toBe(0);
  });

  it("is idempotent: re-running on its own output changes nothing", () => {
    const once = backfillHighSeverityFindings(scenario(), ALL, "t");
    const twice = backfillHighSeverityFindings(once, ALL, "t");
    expect(twice).toBe(once);
    expect(e4Of(twice).relatedFindingIds).toEqual(["f1", "f-auto-e4"]);
  });

  it("leaves a Medium row alone (High/Critical only)", () => {
    const state = scenario({ e4: { severity: "Medium" } });
    expect(absorbedHighRowIds(state).size).toBe(0);
    expect(backfillHighSeverityFindings(state, ALL, "t")).toBe(state);
  });

  it("reports the absorbed row id", () => {
    expect([...absorbedHighRowIds(scenario())]).toEqual(["e4"]);
  });
});
