// LOAD ORDER BETWEEN THE EXTRACTED MODULES (#482).
//
// `check:imports` includes `public/js/**` so that "the first cycle between extracted feature
// modules fails a PR". It cannot: all 138 of them are CLASSIC SCRIPTS publishing onto `window`, so
// the regex-over-import-statements graph sees 138 nodes and 0 edges. The real graph is ~463 edges
// carried by globals, and every one of them routes around that gate.
//
// CYCLES ARE THE WRONG QUESTION HERE, which is why this file does not ask it. The reasoning behind
// the import gate is ES-module semantics, where a cycle means a half-initialised binding. These are
// classic scripts: every cross-module name resolves through `window` at CALL time, so two features
// whose click handlers call each other are fine, and 32 such cycles exist today, harmlessly.
//
// The failure that actually happens — the one the import gate's own comment describes as
// "discovered later from a blank page", and that PR #475 hit twice — is about ORDER, not cycles: a
// module reaching for a sibling's published name DURING LOAD, before that sibling's <script> tag
// has run. The name is not there yet. Unguarded that is a ReferenceError inside a load-time IIFE,
// which kills the rest of that module; guarded with `typeof`, it is worse, because the guard is
// simply false and the feature is silently, permanently absent with nothing in the console.
//
// That number is 0 today, so this is a hard gate with no baseline, and the first PR to introduce
// the bug fails rather than shipping a blank panel.
import { describe, expect, it } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import {
  loadOrderViolations,
  moduleGlobals,
  scriptFromSource,
  type DashboardScript,
} from "../helpers/dashboardAst.js";

const JS_DIR = join(process.cwd(), "..", "public", "js");
const DASHBOARD = join(process.cwd(), "..", "public", "dashboard.html");

describe("the load-order analysis, on modules built for the purpose", () => {
  // Asking the real files proves nothing about the analysis: they are clean, so it returns []
  // whether the check works or not. These sources contain the shape being looked for.
  const mods = (sources: Record<string, string>): Array<{ file: string; script: DashboardScript }> =>
    Object.entries(sources).map(([file, src]) => ({ file, script: scriptFromSource(file, src) }));
  const run = (sources: Record<string, string>, published: Record<string, string[]>) =>
    loadOrderViolations(
      mods(sources),
      new Map(Object.entries(published)),
      new Map(Object.keys(sources).map((f, i) => [f, i])),
    );

  const LATE = { lateThing: ["b.js"] };

  it("reports a load-time call into a module that loads later", () => {
    const v = run({ "a.js": `(function () { lateThing(); })();`, "b.js": `` }, LATE);
    expect(v.map((x) => `${x.from} -> ${x.to}:${x.name}`)).toEqual(["a.js -> b.js:lateThing"]);
  });

  it("reports the typeof-guarded form too, which fails silently rather than loudly", () => {
    // The guard converts a ReferenceError into a no-op. The feature is still absent, and now there
    // is nothing in the console either — strictly the worse of the two outcomes.
    const v = run(
      { "a.js": `(function () { if (typeof lateThing === "function") lateThing(); })();`, "b.js": `` },
      LATE,
    );
    expect(v.map((x) => x.name)).toEqual(["lateThing"]);
  });

  it("reports a call reached through a helper that itself runs at load", () => {
    const v = run({ "a.js": `(function () { function go() { lateThing(); } go(); })();`, "b.js": `` }, LATE);
    expect(v.map((x) => x.name)).toEqual(["lateThing"]);
  });

  it.each([
    ["the callee loads FIRST", { "b.js": ``, "a.js": `(function () { lateThing(); })();` }],
    [
      "the call is deferred to a handler",
      { "a.js": `(function () { btn.onclick = function () { lateThing(); }; })();`, "b.js": `` },
    ],
    [
      "the call is deferred to an event",
      {
        "a.js": `(function () { addEventListener("DOMContentLoaded", function () { lateThing(); }); })();`,
        "b.js": ``,
      },
    ],
    [
      "the name is only published, never called",
      { "a.js": `(function () { window.lateThing = lateThing; })();`, "b.js": `` },
    ],
    [
      "the module declares the name itself",
      { "a.js": `(function () { function lateThing() {} lateThing(); })();`, "b.js": `` },
    ],
  ])("says nothing when %s", (_label, sources) => {
    expect(run(sources, LATE), "flagged a call that cannot hit a missing name").toEqual([]);
  });

  it("says nothing about a module the page never loads", () => {
    // Order is derived from the page's <script> tags, so a file on disk that no tag references
    // cannot be out of order with anything. Reporting it would be noise nobody can act on.
    const v = loadOrderViolations(
      mods({ "a.js": `(function () { lateThing(); })();`, "orphan.js": `` }),
      new Map([["lateThing", ["orphan.js"]]]),
      new Map([["a.js", 0]]),
    );
    expect(v).toEqual([]);
  });

  it("names the line, so the failure points at the call and not at the file", () => {
    const v = run({ "a.js": `(function () {\n\n  lateThing();\n})();`, "b.js": `` }, LATE);
    expect(v[0]?.line).toBe(3);
  });

  // A NAMESPACE IS THE DOMINANT SPELLING, and the first cut of this gate could not see it. 16
  // modules reach a sibling as `DfirState.cell(…)` rather than as a bare function — including
  // dashboard-facets.js, which calls `window.DfirState.cell(new Set())` at load. That is safe today
  // only because dashboard-state.js happens to sit at tag 1 and facets at 12; swap them and the
  // page throws during load with this gate green. Caught by Codex review.
  const NS = { DfirState: ["b.js"] };

  it.each([
    ["a bare namespace call", `(function () { DfirState.cell(1); })();`],
    ["the window-qualified spelling", `(function () { window.DfirState.cell(1); })();`],
    ["the computed spelling", `(function () { window["DfirState"].cell(1); })();`],
  ])("reports %s into a later module", (_label, src) => {
    expect(run({ "a.js": src, "b.js": `` }, NS).map((x) => x.name)).toEqual(["DfirState"]);
  });

  it.each([
    ["the namespace loads first", { "b.js": ``, "a.js": `(function () { DfirState.cell(1); })();` }],
    [
      "the namespace is the module's own local",
      { "a.js": `(function () { const DfirState = mk(); DfirState.cell(1); })();`, "b.js": `` },
    ],
    [
      "the namespace call is deferred",
      { "a.js": `(function () { btn.onclick = function () { DfirState.cell(1); }; })();`, "b.js": `` },
    ],
    [
      "the namespace is read but never called",
      { "a.js": `(function () { const c = DfirState.cell; void c; })();`, "b.js": `` },
    ],
  ])("says nothing when %s", (_label, sources) => {
    expect(run(sources, NS)).toEqual([]);
  });

  // A NAMED HANDLER IS NOT LOAD-TIME WORK. The deferred cases above all passed an INLINE function,
  // and the named form — the commoner style here — took a different path: invokedNames() followed
  // every identifier ARGUMENT of every call, so `addEventListener("click", h)` was walked as though
  // the page had clicked it. Also Codex.
  it.each([
    ["a click handler", `(function () { function h() { lateThing(); } addEventListener("click", h); })();`],
    ["a timer", `(function () { function h() { lateThing(); } setTimeout(h, 0); })();`],
    ["a promise callback", `(function () { function h() { lateThing(); } fetch("/x").then(h); })();`],
  ])("says nothing about %s that merely mentions the name", (_label, src) => {
    expect(run({ "a.js": src, "b.js": `` }, LATE)).toEqual([]);
  });

  it("still follows a handler into a synchronous iteration, which does run at load", () => {
    // The other side of the same fix: forEach invokes now, so its callback IS load-time work.
    const src = `(function () { function h() { lateThing(); } ["a"].forEach(h); })();`;
    expect(run({ "a.js": src, "b.js": `` }, LATE).map((x) => x.name)).toEqual(["lateThing"]);
  });

  it("says nothing about a local that merely shares a sibling's spelling", () => {
    // The gate used to join two file-wide analyses: "is this name free ANYWHERE in the file" and
    // "is it called at load ANYWHERE in the file". Neither knows the other's call site, so a local
    // called at load was reported on the strength of an unrelated deferred reference. Codex again.
    const src = `(function () {
  function a() { function lateThing() {} lateThing(); }
  a();
  function b() { lateThing(); }
  window.b = b;
})();`;
    expect(run({ "a.js": src, "b.js": `` }, LATE)).toEqual([]);
  });
});

describe("no extracted module reaches for a sibling before it is loaded", () => {
  const html = readFileSync(DASHBOARD, "utf8");
  const order = new Map<string, number>();
  [...html.matchAll(/<script[^>]*src="\/js\/([^"]+)"/g)].forEach((m, i) => {
    if (!order.has(m[1])) order.set(m[1], i);
  });
  const modules = readdirSync(JS_DIR)
    .filter((f) => f.endsWith(".js"))
    .sort()
    .map((file) => ({ file, script: scriptFromSource(file, readFileSync(join(JS_DIR, file), "utf8")) }));
  const published = new Map(
    [...moduleGlobals()].map(([name, owners]) => [name, owners.map((o) => o.replace(/^js\//, ""))] as const),
  );

  it("has a world to check, so a green result means something", () => {
    // A closed-world check whose world is empty passes for the wrong reason — the same failure this
    // whole file exists to prevent, one level up.
    expect(order.size, "no /js/ script tags found in the page").toBeGreaterThan(60);
    expect(modules.length, "no module files found on disk").toBeGreaterThan(60);
    expect(published.size, "no module publications found").toBeGreaterThan(100);
  });

  it("calls no sibling's published name during load", () => {
    const violations = loadOrderViolations(modules, published, order).map(
      (v) => `${v.from}:${v.line} calls ${v.name}(), published by ${v.to}, which loads later`,
    );
    expect(
      violations.sort(),
      "this runs before the sibling's <script> tag, so the name is not there yet: unguarded it " +
        "throws inside the load-time IIFE and kills the rest of the module, and guarded with " +
        "typeof it is simply skipped and the feature is silently absent for good",
    ).toEqual([]);
  });
});
