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
  // which is the failure mode this whole feature must not introduce.
  it("reads both checkboxes so the header can report a filtered count", () => {
    expect(SOURCE).toContain("hideAutoFindings");
    expect(SOURCE).toContain("hideGapFindings");
  });
});
