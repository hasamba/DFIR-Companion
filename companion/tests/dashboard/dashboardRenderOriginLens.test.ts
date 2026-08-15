import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { callsWithin, functionsOf, scriptFromSource, type DashboardScript } from "../helpers/dashboardAst.js";

// render() is a ~700-line DOM function with no behavioural harness in this repo — the confidence
// floor and corroboration lens beside it have none either. So the DECISION lives in
// findingPassesOriginLens, unit-tested exhaustively in dashboardFilters.test.ts, and render's only
// obligation is to call it. This suite checks exactly that obligation, and then checks itself:
// the second test re-parses a source with the call renamed away and asserts the check goes red,
// so the gate cannot pass for the wrong reason.
const SOURCE = readFileSync(new URL("../../../public/js/dashboard-render.js", import.meta.url), "utf8");

// NOT callsByName(script, "findingPassesOriginLens") directly on the whole file: that walks
// reachability from THIS FILE's own top level, and render() is never self-invoked here — it has 17
// call sites, all in OTHER dashboard scripts, and this file only publishes it as window.render at
// the bottom. Parsed alone, that makes render's entire body dead code by callsByName's own rule
// ("a function nothing invokes" — see dashboardAstContract.test.ts), true of every pre-existing call
// inside render() and not just this one: callsByName(scriptFromSource(...), "isFindingFalsePositive")
// on unmodified dashboard-render.js is false today, for the identical reason, though that call has
// shipped and worked for months. So the question actually worth asking here is scoped to render's
// own body — callsWithin() answers exactly that, independent of who calls render (which this
// single-file test cannot see anyway, and isn't its job to prove).
function renderBody(script: DashboardScript) {
  const fn = functionsOf(script).find((f) => f.name === "render" && f.declaration);
  if (!fn) throw new Error("render() function declaration not found in dashboard-render.js");
  return fn.node;
}

// The span of the findingsFiltering declaration alone — from "const findingsFiltering =" to its
// terminating ";". Scoped narrower than SOURCE on purpose: document.getElementById("hideAutoFindings")
// (edit 1, the checkbox read) already contains the substring "hideAutoFindings", so a whole-file
// SOURCE.toContain check is satisfied by edit 1 alone and stays green even if edit 3 — the
// hideAuto/hideGap terms inside findingsFiltering — were never written; that gap is what this helper
// exists to close. No export in dashboardAst.ts locates a named VariableDeclaration inside an
// arbitrary node: functionsOf() finds only function-like nodes, and callsWithin()/callsByName() see
// only call expressions, while findingsFiltering's hideAuto/hideGap references are plain identifier
// reads in a ||-chain, not calls — so there is no existing AST export this can be built from, and
// per instruction this narrows the STRING search instead, to exactly the span the fix calls for.
function findingsFilteringDecl(source: string): string {
  const start = source.indexOf("const findingsFiltering =");
  if (start === -1) throw new Error("findingsFiltering declaration not found in dashboard-render.js");
  const end = source.indexOf(";", start);
  if (end === -1) throw new Error("findingsFiltering declaration has no terminating ;");
  return source.slice(start, end);
}

describe("render() applies the finding-origin lens", () => {
  it("calls findingPassesOriginLens", () => {
    const script = scriptFromSource("dashboard-render.js", SOURCE);
    expect(callsWithin(renderBody(script)).has("findingPassesOriginLens")).toBe(true);
  });

  it("goes red when the call is removed — the gate's own mutation check", () => {
    const stripped = SOURCE.replace(/findingPassesOriginLens/g, "lensCallRemovedByTest");
    const script = scriptFromSource("dashboard-render.js", stripped);
    expect(callsWithin(renderBody(script)).has("findingPassesOriginLens")).toBe(false);
  });

  // The count label is the only signal that a row was hidden rather than absent. If the lenses are
  // left out of findingsFiltering the header reads a flat "(11 findings)" while two are suppressed,
  // which is the failure mode this whole feature must not introduce. This test covers edit 1 (the
  // checkbox reads) only — a whole-file substring search can't also prove edit 3 (wiring those reads
  // into findingsFiltering), because edit 1's own getElementById("hideAutoFindings") already satisfies
  // it. Edit 3 has its own test below.
  it("reads both checkboxes so the header can report a filtered count", () => {
    expect(SOURCE).toContain("hideAutoFindings");
    expect(SOURCE).toContain("hideGapFindings");
  });

  // The test above proves the DOM ids are read (edit 1); it does not prove the two local consts —
  // hideAuto / hideGap, READ from those ids, not the ids themselves — ever reach findingsFiltering
  // (edit 3). Verified empirically before this test was written: deleting only the "hideAuto ||" /
  // "hideGap ||" lines from findingsFiltering, with edits 1 and 2 left in place, leaves the test above
  // green (its strings are still in the file, in edit 1's getElementById calls) while this one goes
  // red — see the fix report for the transcript.
  it("wires hideAuto and hideGap into findingsFiltering, not just into the checkbox reads", () => {
    const decl = findingsFilteringDecl(SOURCE);
    expect(decl).toContain("hideAuto");
    expect(decl).toContain("hideGap");
  });
});
