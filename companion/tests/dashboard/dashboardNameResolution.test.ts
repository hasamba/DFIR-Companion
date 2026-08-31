import ts from "typescript";
import { describe, expect, it } from "vitest";
import {
  dashboardScripts,
  freeIdentifiers,
  scriptFromSource,
  topLevelBindings,
} from "../helpers/dashboardAst.js";

// DOES EVERY NAME THE PAGE CALLS ACTUALLY EXIST?
//
// A missing module, a typo, a renamed function and a deleted one all look identical at runtime: a
// ReferenceError that aborts whatever was running. Three times in #415 that reached master, and
// each was found by a person blocking a file in a browser rather than by anything in CI.
//
// All four are decidable BEFORE merge, because this is a closed world. Every name the page may use
// legitimately is one of:
//   - declared in the page's own inline scripts
//   - published onto `window` by one of the /js/ modules it loads
//   - a browser or JavaScript built-in
// Anything else resolves to nothing at runtime.
//
// WHY THIS BEATS GUARDING EVERY CALL SITE. The alternative — a `typeof` guard, or a no-op stub, at
// every place a module name is used — defends the page at runtime against a file that a working
// build should never be missing. The server binds 127.0.0.1 and reads these files off local disk
// (src/server.ts), so a 404 here is a corrupt install, not a flaky network. This check makes the
// corrupt install fail at merge instead, which is both earlier and cheaper.

const scripts = dashboardScripts();
const inline = scripts.filter((s) => s.name.startsWith("dashboard.html#inline"));
const modules = scripts.filter((s) => !s.name.startsWith("dashboard.html"));

/**
 * Names the modules put on `window`, at ANY depth.
 *
 * Not just the load-time publications: js/dashboard-tickets.js publishes openIrisImportModal from
 * INSIDE initTicketIntegrations(), so a load-time-only harvest calls it undefined and this check
 * would report a name that is genuinely there by the time anything uses it.
 */
function publishedNames(): Set<string> {
  const out = new Set<string>();
  for (const s of modules) {
    const walk = (n: ts.Node): void => {
      if (
        ts.isBinaryExpression(n) &&
        n.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
        ts.isPropertyAccessExpression(n.left) &&
        ts.isIdentifier(n.left.expression) &&
        (n.left.expression.text === "window" || n.left.expression.text === "globalThis")
      ) {
        out.add(n.left.name.text);
      }
      // A classic script's top-level function/var declarations are page globals too.
      ts.forEachChild(n, walk);
    };
    ts.forEachChild(s.ast, walk);
    for (const b of topLevelBindings(s)) out.add(b.name);
  }
  return out;
}

/**
 * Built-ins. Hand-maintained on purpose: the list is short, it changes about once a year, and the
 * alternative — trusting a lib.dom.d.ts lookup — would quietly absolve a typo that happens to
 * collide with an obscure global nobody meant to use.
 */
const BUILT_INS = new Set([
  // JS
  "Array",
  "Boolean",
  "Date",
  "Error",
  "Infinity",
  "JSON",
  "Map",
  "Math",
  "NaN",
  "Number",
  "Object",
  "Promise",
  "RegExp",
  "Set",
  "String",
  "Symbol",
  "WeakMap",
  "WeakSet",
  "BigInt",
  "Intl",
  "Proxy",
  "Reflect",
  "decodeURIComponent",
  "encodeURIComponent",
  "isNaN",
  "isFinite",
  "parseFloat",
  "parseInt",
  "undefined",
  "globalThis",
  "structuredClone",
  "queueMicrotask",
  // DOM / browser
  "AbortController",
  "Blob",
  "CSS",
  "CustomEvent",
  "Event",
  "File",
  "FileReader",
  "FormData",
  "Headers",
  "Image",
  "IntersectionObserver",
  "MutationObserver",
  "Node",
  "Notification",
  "Request",
  "Response",
  "ResizeObserver",
  "TextDecoder",
  "TextEncoder",
  "URL",
  "URLSearchParams",
  "WebSocket",
  "Worker",
  "alert",
  "atob",
  "btoa",
  "clearInterval",
  "clearTimeout",
  "confirm",
  "console",
  "document",
  "fetch",
  "getComputedStyle",
  "history",
  "localStorage",
  "location",
  "matchMedia",
  "navigator",
  "prompt",
  "requestAnimationFrame",
  "cancelAnimationFrame",
  "screen",
  "sessionStorage",
  "setInterval",
  "setTimeout",
  "window",
  "performance",
  "crypto",
]);

/**
 * Names referenced ONLY behind a `typeof` guard, and therefore safe to be absent.
 *
 * `typeof x` is the one operation that does not throw on an undeclared identifier, so
 * `if (typeof refresh === "function") refresh()` is a deliberate optional call, not a missing name.
 * Listed rather than detected because there is exactly one and a detector would be more code than
 * the thing it detects — but if this list grows past a handful, build the detector.
 *
 * `refresh` is public/dashboard.html:11310, a wizard hook that only exists on the settings page.
 */
const OPTIONAL = new Set(["refresh"]);

describe("every name the page calls resolves to something", () => {
  const declared = new Set<string>();
  for (const s of inline) for (const b of topLevelBindings(s)) declared.add(b.name);
  const published = publishedNames();

  it("harvests the three sources it resolves against", () => {
    // A closed-world check whose world is empty passes for the wrong reason.
    //
    // The inline floor is deliberately low. It exists to catch "the parse produced nothing", and
    // #415 drives this number DOWN on purpose — a floor set near the current count is a treadmill
    // that has to be edited every extraction, and one edited that often stops being read. It was
    // 100 and the count reached exactly 100 when latestEventMs was deleted (the scope presets stopped
    // needing an anchor), proving the point: give it real headroom instead of nudging it each time.
    expect(declared.size, "no top-level bindings found in the inline scripts").toBeGreaterThan(50);
    expect(published.size, "no module publications found").toBeGreaterThan(100);
    expect(inline.length, "no inline scripts found").toBeGreaterThan(0);
    // The invariant that DOES hold across extraction: the world is conserved. Every name that
    // leaves the inline script arrives in a module's publish list, so the sum only grows. If it
    // collapses, a harvester broke — which is exactly the failure the floors above are guarding.
    expect(declared.size + published.size, "the resolvable world collapsed").toBeGreaterThan(600);
  });

  it("leaves no identifier unaccounted for", () => {
    const free = new Map<string, number>();
    for (const s of inline) {
      for (const [name, count] of freeIdentifiers(s)) free.set(name, (free.get(name) ?? 0) + count);
    }
    expect(free.size, "no free identifiers at all — the analysis is broken, not the page").toBeGreaterThan(
      50,
    );

    const unresolved = [...free.keys()]
      .filter((n) => !declared.has(n) && !published.has(n) && !BUILT_INS.has(n) && !OPTIONAL.has(n))
      .sort();
    expect(
      unresolved,
      "the page reads a name nothing declares, publishes or provides — at runtime that is a " +
        "ReferenceError that aborts whatever was running, and it is a typo, a rename, a deletion " +
        "or a module that is loaded but never registered in STATIC_ASSETS",
    ).toEqual([]);
  });
});

// THE ANALYSIS ITSELF, mutated. The check above is a closed-world claim about a page that is
// currently clean, so it returns [] whether the scope analysis works or not — the same shape of
// silence that let two other gates in this issue be wrong for weeks.
describe("the scope analysis behind it", () => {
  const free = (src: string): string[] => [...freeIdentifiers(scriptFromSource("p.js", src)).keys()];

  it.each([
    ["a bare undeclared call", `missingFn();`],
    ["a reference inside a function", `function go() { missingFn(); } go();`],
    ["a reference inside a listener", `el.addEventListener("c", () => missingFn());`],
    ["a reference in a nested block", `if (x) { { missingFn(); } }`],
    ["a reference in a catch body", `try { a(); } catch (e) { missingFn(); }`],
  ])("reports %s", (_label, src) => {
    expect(free(src)).toContain("missingFn");
  });

  it.each([
    // Hoisting. The page calls functions above their declarations constantly, so a single-pass
    // walker would report most of the script as free.
    ["a function declared after its call", `missingFn(); function missingFn() {}`],
    ["a var hoisted out of a block", `if (x) { var missingFn = 1; } missingFn;`],
    ["a parameter", `function go(missingFn) { return missingFn; }`],
    ["a catch binding", `try { a(); } catch (missingFn) { return missingFn; }`],
    ["a destructured local", `const { missingFn } = obj; missingFn();`],
    ["an array-destructured local", `const [missingFn] = xs; missingFn();`],
    ["a for-of binding", `for (const missingFn of xs) missingFn();`],
    ["a named function expression calling itself", `const f = function missingFn() { missingFn(); };`],
    ["a property that shares the name", `const o = { missingFn: 1 }; o.missingFn;`],
    ["a shorthand in a destructuring pattern", `const { a: missingFn } = o; missingFn;`],
    ["a label", `missingFn: for (;;) { break missingFn; }`],
  ])("does not report %s", (_label, src) => {
    expect(free(src)).not.toContain("missingFn");
  });
});
