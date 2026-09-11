import { readFileSync } from "node:fs";
import ts from "typescript";
import { describe, expect, it } from "vitest";
import { techniqueNamesFor } from "../../src/analysis/attackTechniqueNames.js";
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
 * name table knows, so an appended row's NAME is a real assertion here and not a restated id.
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
 * Every field of a row: id, name and finding links.
 *
 * `name` used to be excluded. A row appended from an event id got its real name on the server, from
 * the id -> name table in analysis/attackTechniqueNames.ts, and the bare id on the client, which was
 * never sent that table — so the panel read "T1490" where the report read "Inhibit System Recovery".
 * The route now sends the table's answer with the state payload instead of copying the table into the
 * browser, and the carve-out that stood here went with it: there is no field left to normalise away.
 */
function shape(rows: ReadonlyArray<{ id: string; name: string; findingIds: string[] }>) {
  return rows.map((r) => ({ id: r.id, name: r.name, findingIds: r.findingIds }));
}

/**
 * The id -> name map the /cases/:id/state route sends with the payload, built by the route's OWN
 * function over the same two inputs it uses (src/routes/caseState.ts).
 *
 * Built here rather than written out, for the reason the header gives for importing
 * withEventTechniques: a literal map would pin the test author's reading of the table, which is the
 * divergence this suite exists to catch. Feeding the client the real map is also what makes the
 * comparison end to end — server resolves, client renders — rather than a check of two halves.
 */
function names(state: InvestigationState): Record<string, string> {
  return techniqueNamesFor(state.mitreTechniques, state.forensicTimeline);
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
    const client = filters().deriveMitreRows(
      state.findings,
      state.forensicTimeline,
      state.mitreTechniques,
      names(state),
    );
    const server = withEventTechniques(state).mitreTechniques;
    expect(shape(client)).toEqual(shape(server));
  });

  // shape() above compares every field, so the it.each cases already cover names. This one names the
  // case the comparison is weakest on: an APPENDED row, whose name comes from the map rather than
  // from the stored table. Spelled out as a literal so a map that silently went empty — both sides
  // falling back to the bare id, in agreement and both wrong — cannot pass.
  it("names an appended row the way the report does, not with the bare id", () => {
    const state = fixture();
    const client = filters().deriveMitreRows(
      state.findings,
      state.forensicTimeline,
      state.mitreTechniques,
      names(state),
    );
    const nameOf = (rows: ReadonlyArray<{ id: string; name: string }>, id: string) =>
      rows.find((r) => r.id === id)?.name;
    expect(nameOf(client, "T1490")).toBe("Inhibit System Recovery");
    expect(nameOf(withEventTechniques(state).mitreTechniques, "T1490")).toBe("Inhibit System Recovery");
  });

  // An id the table does not know: the map omits it and BOTH sides fall back to the bare id. That is
  // the property the omission rests on — techniqueNamesFor() leaving an entry out has to mean the
  // same answer as sending { T9999: "T9999" }, or the fallback is a second rule rather than the
  // same one.
  it("falls back to the bare id on both sides for a technique the table does not know", () => {
    const state = fixture();
    state.forensicTimeline = [
      ...state.forensicTimeline,
      { ...state.forensicTimeline[1], id: "e7", mitreTechniques: ["T9999"] },
    ];
    expect(names(state)).not.toHaveProperty("T9999");
    const client = filters().deriveMitreRows(
      state.findings,
      state.forensicTimeline,
      state.mitreTechniques,
      names(state),
    );
    expect(shape(client)).toEqual(shape(withEventTechniques(state).mitreTechniques));
    expect(client.find((r) => r.id === "T9999")?.name).toBe("T9999");
  });

  // SHALLOW ON BOTH SIDES, and pinned as such rather than asserted away. The server's
  // unionEventTechniques() spreads each row ({ ...t }), so the row objects are fresh but their
  // findingIds arrays are the state's own. The client copies the same way. Claiming a deep copy
  // here would be the mirror drifting in the test rather than in the code — so the check is that
  // the two ALIAS ALIKE, which is the property a mirror actually owes.
  it("copies rows but shares findingIds — the same shallowness as the server", () => {
    const state = fixture();
    const client = filters().deriveMitreRows(
      state.findings,
      state.forensicTimeline,
      state.mitreTechniques,
      names(state),
    );
    const server = withEventTechniques(state).mitreTechniques;
    expect(client[0]).not.toBe(state.mitreTechniques[0]);
    expect(server[0]).not.toBe(state.mitreTechniques[0]);
    expect(client[0].findingIds).toBe(state.mitreTechniques[0].findingIds);
    expect(server[0].findingIds).toBe(state.mitreTechniques[0].findingIds);
  });

  // The list itself is fresh, which is the half render() depends on: it appends event-carried rows.
  it("appends to its own array, leaving the stored table's length alone", () => {
    const state = fixture();
    const rows = filters().deriveMitreRows(
      state.findings,
      state.forensicTimeline,
      state.mitreTechniques,
      names(state),
    );
    rows.push({ id: "T9999", name: "injected", findingIds: [] });
    expect(state.mitreTechniques).toHaveLength(4);
    expect(state.mitreTechniques.map((t) => t.id)).not.toContain("T9999");
  });

  it("tolerates the null and missing shapes the dashboard can hand it mid-load", () => {
    expect(filters().deriveMitreRows(null, null, null)).toEqual([]);
    expect(filters().deriveMitreRows([], [{}], [])).toEqual([]);
    // A payload from a server that predates the map, and one that sent it empty. Neither may throw,
    // and both give the old rendering — the bare id — rather than a blank name.
    const state = fixture();
    for (const map of [undefined, null, {}]) {
      const rows = filters().deriveMitreRows(
        state.findings,
        state.forensicTimeline,
        state.mitreTechniques,
        map,
      );
      expect(rows.find((r) => r.id === "T1490")?.name).toBe("T1490");
    }
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
    const rows = filters().deriveMitreRows(
      notFp,
      state.forensicTimeline,
      state.mitreTechniques,
      names(state),
    );
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
    const rows = filters().deriveMitreRows(
      state.findings,
      state.forensicTimeline,
      state.mitreTechniques,
      names(state),
    );
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
    // Source text, whatever the argument's shape. An earlier version returned bare identifiers and
    // wrapped everything else in a marker, which was enough while every asserted argument was a
    // local; the names map is a property access, and its own text is what an assertion wants to
    // read. A wrong identifier still fails loudly — it just fails against its own text.
    return call.arguments.map((a) => a.getText());
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

  // THE NAMES ARGUMENT, for the reason the findings argument gets its own test: the call compiles,
  // renders and passes every behavioural test above with the fourth argument simply missing, and
  // the only visible symptom is a row reading "T1490" instead of "Inhibit System Recovery".
  // deriveMitreRows falls back to the bare id by design, so nothing throws to point at the omission.
  it("passes state.techniqueNames — the server's map — as the names argument", () => {
    const script = scriptFromSource("dashboard-render.js", RENDER_SOURCE);
    expect(deriveMitreRowsArgs(renderBody(script))[3]).toBe("state.techniqueNames");
  });

  it("goes red when the names argument is dropped", () => {
    const stripped = RENDER_SOURCE.replace(", state.techniqueNames)", ")");
    const script = scriptFromSource("dashboard-render.js", stripped);
    expect(deriveMitreRowsArgs(renderBody(script))[3]).toBeUndefined();
  });
});
