import { readFileSync } from "node:fs";
import ts from "typescript";
import { describe, expect, it } from "vitest";
import { withEventTechniques } from "../../src/analysis/eventTechniques.js";
import { applyFalsePositive, type FalsePositiveMarker } from "../../src/analysis/falsePositive.js";
import { emptyState, type InvestigationState } from "../../src/analysis/stateTypes.js";
import type { FiltersApi } from "./dashboardApi.js";
import { callsWithin, functionsOf, scriptFromSource, type DashboardScript } from "../helpers/dashboardAst.js";
import { DASHBOARD_HELPER_FILES, loadDashboardModule } from "../helpers/dashboardModule.js";

// The MITRE derivation is the same rule written twice — src/analysis/eventTechniques.ts on the
// server, deriveMitreRows() in public/js/dashboard-filters.js on the client — and until now nothing
// checked that the mirror still matched (#918).
//
// tests/dashboard/dashboardScope.test.ts documents this exact failure mode for projectScope: "the
// same rule written twice... nothing checked that the mirror still matched". That suite is the
// template here, and it is followed in the part that matters most: the server's REAL function is
// imported and run, never re-implemented in the test. A re-implementation pins the test author's
// reading of the rule, which is the divergence it was written to catch.
//
// TWO HALVES, BECAUSE THE BUG THIS SUITE EXISTS FOR WAS IN NEITHER FUNCTION.
//
//   1. The rule — deriveMitreRows vs withEventTechniques over the same inputs. Pure, so it is
//      compared directly.
//   2. The COMPOSITION — which findings list render() feeds it. #917 was exactly this: both
//      functions were right, and render() handed the derivation the raw state.findings while the
//      findings panel three hundred lines above used the false-positive-filtered `notFp`. A
//      technique whose only support was a finding the analyst had just confirmed benign stayed in
//      the dashboard panel while the report and every server-side export had already dropped it.
//      Half 1 cannot see that; render() is a 700-line DOM function with no behavioural harness, so
//      half 2 answers it at the call site, the way dashboardRenderOriginLens.test.ts does.

const RENDER_SOURCE = readFileSync(
  new URL("../../../public/js/dashboard-render.js", import.meta.url),
  "utf8",
);

function filters(): FiltersApi {
  const globals = loadDashboardModule<{ DfirFilters: FiltersApi }>(
    "dashboard-filters.js",
    DASHBOARD_HELPER_FILES.filter((f) => f !== "dashboard-filters.js"),
  );
  return globals.DfirFilters;
}

/**
 * A state exercising every branch of the rule at once.
 *
 * f-benign is the #917 case: "beaconing" is the only support T1071 has, and a marker confirms it
 * benign. f-open backs T1059, which an event also carries. T1486 is in the table with no support at
 * all. T1583 is analyst-accepted, so it survives with no support by construction. T1490 is carried
 * only by an event and is not in the table, so it has to be appended — and it is one of the ids the
 * SERVER's name table knows, which is what makes the name carve-out below observable at all.
 */
function fixture(): InvestigationState {
  const finding = (id: string, title: string) => ({
    id,
    severity: "High" as const,
    title,
    description: "",
    relatedIocs: [],
    mitreTechniques: [],
    sourceScreenshots: [],
    firstSeen: "",
    lastUpdated: "",
    status: "open" as const,
  });
  const event = (id: string, techniques: string[]) => ({
    id,
    timestamp: "2026-05-20T09:00:00Z",
    description: id,
    severity: "High" as const,
    mitreTechniques: techniques,
    relatedFindingIds: [],
    sourceScreenshots: [],
  });
  return {
    ...emptyState("c1"),
    findings: [finding("f-open", "Encoded PowerShell"), finding("f-benign", "beaconing")],
    forensicTimeline: [event("e1", ["T1059"]), event("e2", ["T1490"]), event("e3", [])],
    mitreTechniques: [
      { id: "T1059", name: "Command and Scripting Interpreter", findingIds: ["f-open"] },
      { id: "T1071", name: "Application Layer Protocol", findingIds: ["f-benign"] },
      { id: "T1486", name: "Data Encrypted for Impact", findingIds: [] },
      { id: "T1583", name: "Acquire Infrastructure", findingIds: [], analystAccepted: true },
    ],
  };
}

/**
 * Ids and finding links only.
 *
 * THE `name` FIELD IS A KNOWN, DELIBERATE DIVERGENCE, not an oversight this normalisation hides.
 * A row appended from an event id gets its real name on the server, from the id -> name table in
 * analysis/attackTechniqueNames.ts, and the bare id on the client, which is never sent that table.
 * It is pinned as its own test below rather than left to fail here, so the day someone ships the
 * table to the browser this suite says which assertion to delete.
 */
function shape(rows: ReadonlyArray<{ id: string; findingIds: string[] }>) {
  return rows.map((r) => ({ id: r.id, findingIds: r.findingIds }));
}

// ── HALF 1: THE RULE ─────────────────────────────────────────────────────────────────────────────
describe("the client MITRE derivation matches the server's", () => {
  const CASES: Array<[string, (s: InvestigationState) => InvestigationState]> = [
    ["the full fixture", (s) => s],
    ["no findings at all", (s) => ({ ...s, findings: [] })],
    ["no events at all", (s) => ({ ...s, forensicTimeline: [] })],
    ["an empty stored table", (s) => ({ ...s, mitreTechniques: [] })],
    ["nothing anywhere", (s) => ({ ...s, findings: [], forensicTimeline: [], mitreTechniques: [] })],
    [
      "an event carrying an empty id, which neither side may append",
      (s) => ({
        ...s,
        forensicTimeline: [
          ...s.forensicTimeline,
          { ...s.forensicTimeline[0], id: "e9", mitreTechniques: [""] },
        ],
      }),
    ],
    [
      "the same id on two events, which must appear once",
      (s) => ({
        ...s,
        forensicTimeline: [...s.forensicTimeline, { ...s.forensicTimeline[1], id: "e8" }],
      }),
    ],
  ];

  it.each(CASES)("agrees with the server: %s", (_label, shapeIt) => {
    const state = shapeIt(fixture());
    const client = filters().deriveMitreRows(state.findings, state.forensicTimeline, state.mitreTechniques);
    const server = withEventTechniques(state).mitreTechniques;
    expect(shape(client)).toEqual(shape(server));
  });

  // The one field that does not match, stated out loud. Both sides keep the stored name for a row
  // that was already in the table; only an APPENDED row differs.
  it("keeps the stored name on both sides, and differs only on an appended row", () => {
    const state = fixture();
    const client = filters().deriveMitreRows(state.findings, state.forensicTimeline, state.mitreTechniques);
    const server = withEventTechniques(state).mitreTechniques;
    const nameOf = (rows: ReadonlyArray<{ id: string; name: string }>, id: string) =>
      rows.find((r) => r.id === id)?.name;
    expect(nameOf(client, "T1059")).toBe("Command and Scripting Interpreter");
    expect(nameOf(server, "T1059")).toBe("Command and Scripting Interpreter");
    // T1490 is appended from e2, and the server's table knows it. The client has no table, so it
    // shows the bare id — the one field where the two disagree, and the reason shape() drops name.
    expect(nameOf(client, "T1490")).toBe("T1490");
    expect(nameOf(server, "T1490")).toBe("Inhibit System Recovery");
  });

  // SHALLOW ON BOTH SIDES, and pinned as such rather than asserted away. The server's
  // unionEventTechniques() spreads each row ({ ...t }), so the row objects are fresh but their
  // findingIds arrays are the state's own. The client copies the same way. Claiming a deep copy
  // here would be the mirror drifting in the test rather than in the code — so the check is that
  // the two ALIAS ALIKE, which is the property a mirror actually owes.
  it("copies rows but shares findingIds — the same shallowness as the server", () => {
    const state = fixture();
    const client = filters().deriveMitreRows(state.findings, state.forensicTimeline, state.mitreTechniques);
    const server = withEventTechniques(state).mitreTechniques;
    expect(client[0]).not.toBe(state.mitreTechniques[0]);
    expect(server[0]).not.toBe(state.mitreTechniques[0]);
    expect(client[0].findingIds).toBe(state.mitreTechniques[0].findingIds);
    expect(server[0].findingIds).toBe(state.mitreTechniques[0].findingIds);
  });

  // The list itself is fresh, which is the half render() depends on: it appends event-carried rows.
  it("appends to its own array, leaving the stored table's length alone", () => {
    const state = fixture();
    const rows = filters().deriveMitreRows(state.findings, state.forensicTimeline, state.mitreTechniques);
    rows.push({ id: "T9999", name: "injected", findingIds: [] });
    expect(state.mitreTechniques).toHaveLength(4);
    expect(state.mitreTechniques.map((t) => t.id)).not.toContain("T9999");
  });

  it("tolerates the null and missing shapes the dashboard can hand it mid-load", () => {
    expect(filters().deriveMitreRows(null, null, null)).toEqual([]);
    expect(filters().deriveMitreRows([], [{}], [])).toEqual([]);
  });
});

// ── HALF 2: THE COMPOSITION — #917 ───────────────────────────────────────────────────────────────
//
// The server states the order in one expression, so the test can state it the same way: dismissing
// f-benign must take T1071 out of the table. Whether render() honours that order is the AST test
// below; this one pins what the order MEANS, so the AST check has something to point at.
describe("a finding confirmed false-positive withdraws the support it was giving", () => {
  const markers: FalsePositiveMarker[] = [
    {
      id: "finding:beaconing",
      kind: "finding",
      ref: "beaconing",
      reason: "authorized-test",
      markedAt: "2026-05-21T00:00:00Z",
      markedBy: "analyst",
      note: "",
    },
  ];

  it("drops the technique on the server", () => {
    const rows = withEventTechniques(applyFalsePositive(fixture(), markers)).mitreTechniques;
    expect(rows.map((r) => r.id)).not.toContain("T1071");
  });

  it("drops it on the client too, when the FILTERED findings are passed", () => {
    const state = fixture();
    const notFp = state.findings.filter((f) => !filters().isFindingFalsePositive(f.title, ["beaconing"]));
    const rows = filters().deriveMitreRows(notFp, state.forensicTimeline, state.mitreTechniques);
    expect(rows.map((r) => r.id)).not.toContain("T1071");
    expect(shape(rows)).toEqual(
      shape(withEventTechniques(applyFalsePositive(state, markers)).mitreTechniques),
    );
  });

  // The bug itself, pinned as a fact about the inputs rather than as a claim about render(): the
  // two lists give DIFFERENT answers, so which one render() passes is a real decision and not a
  // stylistic one. If this ever stops being true the AST test below is worth nothing.
  it("and keeps it when the RAW findings are passed — why the call site matters", () => {
    const state = fixture();
    const rows = filters().deriveMitreRows(state.findings, state.forensicTimeline, state.mitreTechniques);
    expect(rows.map((r) => r.id)).toContain("T1071");
  });
});

describe("render() feeds the derivation the false-positive-filtered findings", () => {
  function renderBody(script: DashboardScript): ts.Node {
    const fn = functionsOf(script).find((f) => f.name === "render" && f.declaration);
    if (!fn) throw new Error("render() function declaration not found in dashboard-render.js");
    return fn.node;
  }

  // Scoped to render's own body, not the whole file: parsed alone, dashboard-render.js never
  // invokes render() — it publishes it as window.render and its 17 call sites are in other scripts
  // — so callsByName would call the entire body dead code. dashboardRenderOriginLens.test.ts hit
  // the same wall and settled it the same way.
  function deriveMitreRowsArgs(node: ts.Node): string[] {
    let call: ts.CallExpression | undefined;
    const visit = (n: ts.Node): void => {
      if (call) return;
      if (
        ts.isCallExpression(n) &&
        ts.isIdentifier(n.expression) &&
        n.expression.text === "deriveMitreRows"
      ) {
        call = n;
        return;
      }
      ts.forEachChild(n, visit);
    };
    visit(node);
    if (!call) throw new Error("deriveMitreRows call not found in render()");
    return call.arguments.map((a) => (ts.isIdentifier(a) ? a.text : `<non-identifier: ${a.getText()}>`));
  }

  it("calls deriveMitreRows rather than deriving inline", () => {
    const script = scriptFromSource("dashboard-render.js", RENDER_SOURCE);
    expect(callsWithin(renderBody(script)).has("deriveMitreRows")).toBe(true);
  });

  it("goes red when the call is removed — the gate's own mutation check", () => {
    const stripped = RENDER_SOURCE.replace(/deriveMitreRows/g, "derivationRemovedByTest");
    const script = scriptFromSource("dashboard-render.js", stripped);
    expect(callsWithin(renderBody(script)).has("deriveMitreRows")).toBe(false);
  });

  // THE ARGUMENT, WHICH IS THE WHOLE OF #917. "is called" is true whether the first argument is
  // notFp or state.findings, and the two give different answers — the test three blocks up proves
  // that. `notFp` is the list the findings panel itself renders, so this also pins that the panel
  // and the MITRE table are reading the same findings.
  it("passes notFp — the filtered list — as the findings argument", () => {
    const script = scriptFromSource("dashboard-render.js", RENDER_SOURCE);
    expect(deriveMitreRowsArgs(renderBody(script))[0]).toBe("notFp");
  });

  it("goes red when the raw state.findings is passed instead", () => {
    const swapped = RENDER_SOURCE.replace("deriveMitreRows(notFp,", "deriveMitreRows(state.findings,");
    const script = scriptFromSource("dashboard-render.js", swapped);
    expect(deriveMitreRowsArgs(renderBody(script))[0]).not.toBe("notFp");
  });
});
