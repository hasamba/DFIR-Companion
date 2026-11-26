// #2904: after a case switch, the previous case's time window (scope) and its findings filters
// (confidence floor, origin lenses) must never filter the new case — not while the new case's
// answer is on its way, not when that answer fails, and not when the old case's answer lands late.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { drainAll, fakePage } from "../helpers/caseSwitchPage.js";
import { A_WINDOW, bState, scopePage, type Finding } from "../helpers/scopePage.js";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// ── scope: js/dashboard-scope-load.js, run against the real DfirScope ─────────────────────────
// (The page and the scope sandbox live in ../helpers/scopePage.ts, shared with caseSwitchScope.)

async function scopeHeldForA(t: ReturnType<typeof scopePage>) {
  t.sb.loadScope("CASE-A");
  t.p.requests[0].answer(A_WINDOW);
  await drainAll();
  expect(t.sb.DfirScope.isEmpty()).toBe(false);
}

describe("scope: case A's time window never filters case B (#2904)", () => {
  it("is dropped the moment B's load starts, before B's answer", async () => {
    const t = scopePage();
    await scopeHeldForA(t);
    t.p.switchCase("CASE-B");
    t.sb.loadScope("CASE-B");
    expect(t.sb.DfirScope.isEmpty()).toBe(true);
    expect(t.p.el("scopeStart").value).toBe("");
  });

  it("B's read failing leaves B's timeline and findings unfiltered", async () => {
    const t = scopePage();
    await scopeHeldForA(t);
    t.p.switchCase("CASE-B");
    t.sb.loadScope("CASE-B");
    t.p.requests[1].fail();
    await drainAll();
    const shown = t.sb.DfirScope.project(bState);
    expect(shown.forensicTimeline.map((e) => e.id)).toEqual(["e1", "e2"]);
    expect(shown.findings.map((f) => f.id)).toEqual(["f1"]);
  });

  it("B's error answer leaves B unfiltered", async () => {
    const t = scopePage();
    await scopeHeldForA(t);
    t.p.switchCase("CASE-B");
    t.sb.loadScope("CASE-B");
    t.p.requests[1].answer({ error: "boom" }, false);
    await drainAll();
    expect(t.sb.DfirScope.project(bState).forensicTimeline).toHaveLength(2);
  });

  it("A's answer landing after B's does not commit A's window on B", async () => {
    const t = scopePage();
    t.sb.loadScope("CASE-A");
    t.p.switchCase("CASE-B");
    t.sb.loadScope("CASE-B");
    t.p.requests[1].answer({ start: null, end: null });
    t.p.requests[0].answer(A_WINDOW);
    await drainAll();
    expect(t.sb.DfirScope.isEmpty()).toBe(true);
  });

  it("a late call for case A neither fetches nor clears B's window", async () => {
    const t = scopePage();
    t.p.switchCase("CASE-B");
    t.sb.loadScope("CASE-B");
    t.p.requests[0].answer(A_WINDOW);
    await drainAll();
    t.sb.loadScope("CASE-A");
    expect(t.p.urls()).toEqual(["/cases/CASE-B/scope"]);
    expect(t.sb.DfirScope.isEmpty()).toBe(false);
  });

  it("B's window arriving after B's state rendered redraws once; an unchanged window does not", async () => {
    const t = scopePage();
    t.p.switchCase("CASE-B");
    t.sb.loadScope("CASE-B");
    t.hold(bState);
    t.p.requests[0].answer(A_WINDOW);
    await drainAll();
    expect(t.renders).toEqual([bState]);
    t.sb.loadScope("CASE-B");
    t.p.requests[1].answer(A_WINDOW);
    await drainAll();
    expect(t.renders).toHaveLength(1);
  });
});

// ── confidence floor and origin lenses ──────────────────────────────────────────────────────────
interface ConfApi {
  loadConfidenceControl(caseId: string): void;
  saveFindingOriginFilters(caseId: string, patch: object): Promise<void>;
}

// The Findings panel's own predicate over these three controls (js/dashboard-render.js reads them
// once per render — pinned by the next test, so this mirror cannot drift silently).
function visibleFindings(p: ReturnType<typeof fakePage>, findings: Finding[]): string[] {
  const minConf = parseInt(String(p.el("confFilter").value), 10) || 0;
  const hideAuto = p.el("hideAutoFindings").checked;
  const hideGap = p.el("hideGapFindings").checked;
  return findings
    .filter((f) => f.confidence === undefined || f.confidence >= minConf)
    .filter((f) => !(hideAuto && f.id.startsWith("f-auto-")))
    .filter((f) => !(hideGap && f.id.startsWith("f-gap-")))
    .map((f) => f.id);
}
const bFindings: Finding[] = [
  { id: "f1", confidence: 40 },
  { id: "f-auto-1", confidence: 90 },
  { id: "f-gap-1" },
];
const A_FILTERS = { minConfidence: 80, hideAutoFindings: true, hideGapFindings: true };

describe("confidence control: case A's filters never hide case B's findings (#2904)", () => {
  it("the Findings panel reads exactly these three controls", () => {
    const src = readFileSync(new URL("../../../public/js/dashboard-render.js", import.meta.url), "utf8");
    for (const id of ["confFilter", "hideAutoFindings", "hideGapFindings"])
      expect(src).toContain(`getElementById("${id}")`);
  });

  function conf() {
    const p = fakePage();
    const api = loadDashboardModule<ConfApi>("dashboard-confidence-control.js", [], {
      ...p.globals,
      render: () => {},
    });
    return { p, api };
  }
  async function filtersHeldForA(t: ReturnType<typeof conf>) {
    t.api.loadConfidenceControl("CASE-A");
    t.p.requests[0].answer(A_FILTERS);
    await drainAll();
    expect(visibleFindings(t.p, bFindings)).toEqual([]);
  }

  it("B's read failing shows every one of B's findings", async () => {
    const t = conf();
    await filtersHeldForA(t);
    t.p.switchCase("CASE-B");
    t.api.loadConfidenceControl("CASE-B");
    expect(visibleFindings(t.p, bFindings)).toEqual(["f1", "f-auto-1", "f-gap-1"]);
    t.p.requests[1].fail();
    await drainAll();
    expect(visibleFindings(t.p, bFindings)).toEqual(["f1", "f-auto-1", "f-gap-1"]);
  });

  it("an A save still in flight does not keep A's filters on B", async () => {
    const t = conf();
    await filtersHeldForA(t);
    void t.api.saveFindingOriginFilters("CASE-A", { hideGapFindings: true });
    t.p.switchCase("CASE-B");
    t.api.loadConfidenceControl("CASE-B");
    expect(visibleFindings(t.p, bFindings)).toEqual(["f1", "f-auto-1", "f-gap-1"]);
  });

  it("A's late answer after the switch does not apply A's filters to B", async () => {
    const t = conf();
    t.api.loadConfidenceControl("CASE-A");
    t.p.switchCase("CASE-B");
    t.api.loadConfidenceControl("CASE-B");
    t.p.requests[1].answer({ minConfidence: null });
    t.p.requests[0].answer(A_FILTERS);
    await drainAll();
    expect(visibleFindings(t.p, bFindings)).toEqual(["f1", "f-auto-1", "f-gap-1"]);
  });

  it("#2915: after a cancelled load, reopening the same case resets and reads its filters again", async () => {
    const t = conf();
    await filtersHeldForA(t);
    t.api.loadConfidenceControl("CASE-A"); // on its way at the cancel: never settles
    t.p.cancel(t.api);
    expect(visibleFindings(t.p, bFindings)).toEqual([]); // the view the cancel left keeps its filter
    t.p.switchCase("CASE-A", t.api);
    t.api.loadConfidenceControl("CASE-A");
    expect(t.p.requests).toHaveLength(3);
    expect(visibleFindings(t.p, bFindings)).toEqual(["f1", "f-auto-1", "f-gap-1"]);
    t.p.requests[1].answer({ minConfidence: 0 });
    t.p.requests[2].answer(A_FILTERS);
    await drainAll();
    expect(visibleFindings(t.p, bFindings)).toEqual([]);
  });

  it("B's own filters still apply, and a late call for A neither fetches nor resets them", async () => {
    const t = conf();
    t.p.switchCase("CASE-B");
    t.api.loadConfidenceControl("CASE-B");
    t.p.requests[0].answer({ minConfidence: 50 });
    await drainAll();
    expect(visibleFindings(t.p, bFindings)).toEqual(["f-auto-1", "f-gap-1"]);
    t.api.loadConfidenceControl("CASE-A");
    expect(t.p.urls()).toEqual(["/cases/CASE-B/confidence-control"]);
    expect(visibleFindings(t.p, bFindings)).toEqual(["f-auto-1", "f-gap-1"]);
  });
});
