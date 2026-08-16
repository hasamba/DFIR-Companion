import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import ts from "typescript";
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

// ARGUMENT ORDER at the call site. callsWithin(), used by the two tests above, returns a
// Set<string> of callee NAMES — it can prove findingPassesOriginLens is called, but "is called"
// is true whether the call reads findingPassesOriginLens(f, hideAuto, hideGap) or has the second
// and third arguments transposed. That swap is invisible to every OTHER test that exists: the
// contract tests above only ask "is it called"; the truth-table unit tests in
// dashboardFilters.test.ts exercise the function directly, never this call site; and the e2e
// spec's demo case has no backfill findings, so both checkboxes drive the same "N of M" header
// change regardless of which boolean lands in which parameter. Two checkboxes doing each other's
// job would ship silently.
//
// No export in dashboardAst.ts returns the CallExpression node itself — functionsOf() finds
// function-like nodes, callsWithin()/callsByName() see call NAMES, and nothing hands back one
// call's `arguments` list — so per instruction this is answered locally, narrowed to exactly the
// one call site render() has, rather than adding a new shared export for a single caller.
function findingPassesOriginLensArgs(node: ts.Node): string[] {
  let call: ts.CallExpression | undefined;
  const visit = (n: ts.Node): void => {
    if (call) return; // already found the one call site; nothing left to look for
    if (
      ts.isCallExpression(n) &&
      ts.isIdentifier(n.expression) &&
      n.expression.text === "findingPassesOriginLens"
    ) {
      call = n;
      return;
    }
    ts.forEachChild(n, visit);
  };
  visit(node);
  if (!call) throw new Error("findingPassesOriginLens call not found in render()");
  return call.arguments.map((a) => (ts.isIdentifier(a) ? a.text : `<non-identifier: ${a.getText()}>`));
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

  // THE ARGUMENT-ORDER GATE. Existence alone (the test above) is not the obligation: render() must
  // pass the checkbox reads to the RIGHT parameters. findingPassesOriginLens(f, hideAuto, hideGap)
  // and findingPassesOriginLens(f, hideGap, hideAuto) are both "calls findingPassesOriginLens",
  // and — see the truth table in dashboardFilters.test.ts — a swap would ship two checkboxes that
  // each do the OTHER one's job, with every other test in the suite still green.
  it("calls findingPassesOriginLens with (f, hideAuto, hideGap), in that order", () => {
    const script = scriptFromSource("dashboard-render.js", SOURCE);
    expect(findingPassesOriginLensArgs(renderBody(script))).toEqual(["f", "hideAuto", "hideGap"]);
  });

  it("goes red when the 2nd and 3rd arguments are swapped — this assertion's own mutation check", () => {
    const swapped = SOURCE.replace(
      "findingPassesOriginLens(f, hideAuto, hideGap)",
      "findingPassesOriginLens(f, hideGap, hideAuto)",
    );
    // Fails fast if the call text above ever drifts from the real call site, rather than silently
    // mutating something else and passing for the wrong reason.
    expect(swapped).not.toEqual(SOURCE);
    const script = scriptFromSource("dashboard-render.js", swapped);
    // Mirrors the call-removal check above: assert the POSITIVE test's own predicate no longer
    // holds against the mutated source, proving the test above it would fail on a real swap.
    expect(findingPassesOriginLensArgs(renderBody(script))).not.toEqual(["f", "hideAuto", "hideGap"]);
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
