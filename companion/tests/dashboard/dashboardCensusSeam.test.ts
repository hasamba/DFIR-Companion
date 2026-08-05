import { describe, expect, it } from "vitest";
import type { DashboardScript } from "../helpers/dashboardAst.js";
import { scriptFromSource } from "../helpers/dashboardAst.js";
import { duplicateBindings } from "./featureManifest.js";

// ── THE CENSUS SEAM ITSELF ───────────────────────────────────────────────────────────────────────
//
// The suite above asks duplicateBindings() about the REAL modules, and the real modules are clean —
// so it returns [] whether the seam works or not. That is how this check was wrong twice without a
// single red test: a green suite proves the page is tidy, never that the gate can see.
//
// These rows drive the same function with synthetic module + inline sources carrying exactly the
// mutations that got through. Each one FAILS if the seam regresses to what it was.
describe("the census seam catches a duplicate the page kept", () => {
  const inline = (src: string): DashboardScript[] => [scriptFromSource("dashboard.html#inline-1", src)];

  it.each([
    [
      "a plain declaration on both sides",
      `function loadAnomalies() { return 1; }`,
      `function loadAnomalies() { return 2; }`,
    ],
    [
      // Defeated the regex census: legal, and the name vanished from the module's half.
      "a module declaration hidden behind a comment",
      `function /* moved out */ loadAnomalies() { return 1; }`,
      `function loadAnomalies() { return 2; }`,
    ],
    [
      // Defeated the declaration-only census on the INLINE side. This is the one that shadows.
      "an arrow left behind in the page",
      `function loadAnomalies() { return 1; }`,
      `const loadAnomalies = () => 2;`,
    ],
    [
      // ...and on the MODULE side, so neither half may be declaration-only.
      "a module that binds its function to a const",
      `const loadAnomalies = function () { return 1; };`,
      `function loadAnomalies() { return 2; }`,
    ],
    ["an arrow on both sides", `const loadAnomalies = () => 1;`, `const loadAnomalies = () => 2;`],
  ])("reports %s", (_label, moduleSrc, inlineSrc) => {
    expect(
      duplicateBindings("m.js", moduleSrc, inline(inlineSrc)),
      "a duplicate the gate cannot see is a stale copy the page keeps calling",
    ).not.toEqual([]);
  });

  it.each([
    [
      // The ACTIONS dispatch table. These MUST stay behind — they are how a click reaches the module.
      "a dispatch entry that forwards to the module",
      `function loadAnomalies() { return 1; }`,
      `const ACTIONS = { loadAnomalies: (el) => loadAnomalies(el) };`,
    ],
    [
      "a call site, not a binding",
      `function loadAnomalies() { return 1; }`,
      `document.getElementById("x").onclick = () => loadAnomalies();`,
    ],
    [
      "the module's own publication onto window",
      `function loadAnomalies() { return 1; }`,
      `window.loadAnomalies = window.loadAnomalies;`,
    ],
    [
      "a name the module does not own",
      `function loadAnomalies() { return 1; }`,
      `function renderSomethingElse() {}`,
    ],
  ])("stays silent on %s", (_label, moduleSrc, inlineSrc) => {
    expect(
      duplicateBindings("m.js", moduleSrc, inline(inlineSrc)),
      "flagging correct code is how a gate gets switched off",
    ).toEqual([]);
  });
});
