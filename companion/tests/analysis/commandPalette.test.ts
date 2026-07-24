import { describe, it, expect } from "vitest";
import {
  buildActionRegistry,
  allActions,
  fuzzyMatch,
  searchActions,
  type PaletteAction,
} from "../../src/analysis/commandPalette.js";
import { emptyState, type InvestigationState } from "../../src/analysis/stateTypes.js";

function state(partial: Partial<InvestigationState> = {}): InvestigationState {
  return { ...emptyState("c1"), ...partial };
}

const navFindings: PaletteAction = {
  id: "nav.findings",
  label: "Go to Findings",
  keywords: ["findings", "alerts"],
  category: "Navigation",
};

describe("commandPalette fuzzyMatch", () => {
  it("scores an exact word match highest", () => {
    expect(fuzzyMatch("findings", navFindings)).toBeGreaterThanOrEqual(800);
  });

  it("scores a prefix match above substring", () => {
    const prefix = fuzzyMatch("find", navFindings);
    const sub = fuzzyMatch("ings", navFindings);
    expect(prefix).toBeGreaterThan(sub);
    expect(prefix).toBeGreaterThanOrEqual(600);
  });

  it("scores a substring match above zero", () => {
    const score = fuzzyMatch("ings", navFindings);
    expect(score).toBeGreaterThan(0);
  });

  it("returns 0 for no character overlap", () => {
    expect(fuzzyMatch("zzz", navFindings)).toBe(0);
  });
});

describe("commandPalette buildActionRegistry", () => {
  it("groups actions under all five categories", () => {
    const r = buildActionRegistry();
    expect(Object.keys(r).sort()).toEqual(["Actions", "Case", "Exports", "Navigation", "Settings"]);
    for (const cat of Object.keys(r) as Array<keyof typeof r>) {
      expect(r[cat].length).toBeGreaterThan(0);
    }
    expect(allActions(r).length).toBeGreaterThan(10);
  });
});

describe("commandPalette searchActions", () => {
  const all = allActions(buildActionRegistry());

  it("filters by category using the > prefix", () => {
    const res = searchActions(">Exports", all);
    expect(res.length).toBeGreaterThan(0);
    expect(res.every((r) => r.action.category === "Exports")).toBe(true);
  });

  it("combines > category filter with a query term", () => {
    const res = searchActions(">Actions synthesize", all);
    expect(res.some((r) => r.action.id === "act.synthesize")).toBe(true);
    expect(res.every((r) => r.action.category === "Actions")).toBe(true);
  });

  it("filters out unavailable actions when given case state", () => {
    const synthesize = all.find((a) => a.id === "act.synthesize")!;
    expect(synthesize.available?.(state())).toBe(false);
    expect(synthesize.available?.(state({ findings: [{ id: "f1", severity: "High", title: "t", description: "d", relatedIocs: [], sourceScreenshots: [], mitreTechniques: [], firstSeen: "x", lastUpdated: "y", status: "open" }] }))).toBe(true);
  });

  it("ranks higher-scoring matches first", () => {
    const res = searchActions("findings", all);
    expect(res.length).toBeGreaterThan(1);
    expect(res[0].score).toBeGreaterThanOrEqual(res[1].score);
  });

  it("returns empty for an unmatched query", () => {
    expect(searchActions("zzzzznomatch", all)).toEqual([]);
  });

  it("treats an empty query as matching all (ranked by category order)", () => {
    const res = searchActions("", all);
    expect(res.length).toBe(all.length);
    expect(res[0].action.category).toBe("Navigation");
  });
});