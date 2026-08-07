// WHAT THE EXTRACTED MODULES READ, AND WHAT THEY LEAK.
//
// dashboardNameResolution.test.ts asks "does every name the PAGE reads resolve". That gate has a
// blind spot that gets wider with every extraction in #415: it iterates the inline scripts only.
// Code that moves out of dashboard.html moves out of its coverage at the same moment, so the gate
// is strongest when it is least needed and blind exactly where the work is happening.
//
// Two real bugs shipped through that gap on this branch:
//
//   1. `_graphTimeQuery` was a function private to dashboard-asset-graph.js's IIFE, called from
//      dashboard-evidence-graph.js. Nothing published it. Every Evidence Chain load threw a
//      ReferenceError before either fetch started — for every case, silently, because the call
//      sat inside a .then() chain with a .catch(() => {}).
//
//   2. dashboard-velo-bundles.js read `veloArtifactCache` and `veloEditingId` without declaring
//      them. Non-strict, so the first ASSIGNMENT would have created them — but the render and
//      save paths read first, and a read of an undeclared name is a ReferenceError.
//
// Both are the same shape: a module referencing a name that is not there yet, or not there at all.
import { describe, expect, it } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import {
  dashboardScripts,
  freeIdentifiers,
  implicitGlobals,
  moduleGlobals,
  scriptFromSource,
  topLevelBindings,
  unguardedRefs,
} from "../helpers/dashboardAst";

const isModuleScript = (name: string): boolean => /^js\/[^/]+\.js$/.test(name);
const inlineScripts = () => dashboardScripts().filter((s) => !isModuleScript(s.name));

const JS_DIR = join(process.cwd(), "..", "public", "js");
const moduleFiles = readdirSync(JS_DIR)
  .filter((f) => f.endsWith(".js"))
  .sort();

const scriptFor = (file: string) => scriptFromSource(file, readFileSync(join(JS_DIR, file), "utf8"));

/** Globals the browser provides that the page's own BUILT_INS list does not enumerate. */
const PLATFORM = new Set([
  "window",
  "document",
  "console",
  "fetch",
  "setTimeout",
  "clearTimeout",
  "setInterval",
  "clearInterval",
  "localStorage",
  "sessionStorage",
  "location",
  "navigator",
  "history",
  "JSON",
  "Math",
  "Date",
  "Object",
  "Array",
  "String",
  "Number",
  "Boolean",
  "Promise",
  "Map",
  "Set",
  "WeakMap",
  "WeakSet",
  "RegExp",
  "Error",
  "TypeError",
  "URL",
  "URLSearchParams",
  "FormData",
  "Blob",
  "File",
  "FileReader",
  "Image",
  "Event",
  "CustomEvent",
  "MouseEvent",
  "KeyboardEvent",
  "MutationObserver",
  "IntersectionObserver",
  "ResizeObserver",
  "AbortController",
  "TextEncoder",
  "TextDecoder",
  "Uint8Array",
  "CSS",
  "btoa",
  "atob",
  "alert",
  "confirm",
  "prompt",
  "parseInt",
  "parseFloat",
  "isNaN",
  "isFinite",
  "encodeURIComponent",
  "decodeURIComponent",
  "requestAnimationFrame",
  "cancelAnimationFrame",
  "getComputedStyle",
  "Intl",
  "Symbol",
  "Proxy",
  "Reflect",
  "BigInt",
  "globalThis",
  "structuredClone",
  "queueMicrotask",
  "performance",
  "crypto",
  "DOMParser",
  "Node",
  "Element",
  "HTMLElement",
  "NodeList",
  "undefined",
  "NaN",
  "Infinity",
  "self",
  "top",
  "WebSocket",
  "EventSource",
  "Worker",
  "Notification",
  "matchMedia",
  "scrollTo",
  "print",
  "encodeURI",
  "decodeURI",
  "Function",
  "arguments",
  "AbortSignal",
  "Headers",
  "Response",
  "Request",
  "DataTransfer",
  "Range",
  "Selection",
  "XMLHttpRequest",
  "getSelection",
]);

/**
 * Third-party globals loaded from their own <script> tags. Named individually rather than pattern
 * matched, so adding a vendor dependency is a visible edit to this list.
 */
const VENDOR = new Set([
  "L", // Leaflet — js/vendor/leaflet.js
  "cytoscape", // js/vendor/cytoscape.min.js
]);

describe("every name an extracted module reads resolves to something", () => {
  const published = new Set(moduleGlobals().keys());
  const pageDeclared = new Set<string>();
  for (const s of inlineScripts()) {
    for (const b of topLevelBindings(s)) pageDeclared.add(b.name);
  }
  // Anything assigned onto window anywhere, in a module or the page, is provided at runtime.
  const windowAssigned = new Set<string>();
  const noteWindowWrites = (src: string): void => {
    for (const m of src.matchAll(/window\.([A-Za-z_$][\w$]*)\s*(?:=|\?\?=|\|\|=)/g)) {
      windowAssigned.add(m[1]);
    }
  };
  for (const f of moduleFiles) noteWindowWrites(readFileSync(join(JS_DIR, f), "utf8"));
  noteWindowWrites(readFileSync(join(process.cwd(), "..", "public", "dashboard.html"), "utf8"));

  it("harvests a world to resolve against", () => {
    // A closed-world check whose world is empty passes for the wrong reason.
    expect(moduleFiles.length, "no module files found").toBeGreaterThan(60);
    expect(published.size, "no module publications found").toBeGreaterThan(100);
    expect(pageDeclared.size, "no page bindings found").toBeGreaterThan(50);
  });

  it("leaves no module reading a name nothing provides", () => {
    const unresolved: string[] = [];
    for (const file of moduleFiles) {
      const script = scriptFor(file);
      const own = new Set(topLevelBindings(script).map((b) => b.name));
      for (const name of freeIdentifiers(script).keys()) {
        if (own.has(name) || published.has(name) || windowAssigned.has(name)) continue;
        if (pageDeclared.has(name) || PLATFORM.has(name) || VENDOR.has(name)) continue;
        // `if (typeof refresh === "function") refresh()` is the deliberate optional-dependency
        // form used all over this codebase. A name read ONLY that way cannot throw.
        if (unguardedRefs(script, name).length === 0) continue;
        unresolved.push(`${file}: ${name}`);
      }
    }
    expect(
      unresolved.sort(),
      "a module reads a name that no module publishes, the page does not declare, and the platform " +
        "does not provide — at runtime that is a ReferenceError, and if the call sits inside a " +
        "promise chain with a .catch() the feature just silently never loads",
    ).toEqual([]);
  });

  it("leaves no module creating an implicit global", () => {
    // Distinct from the check above: these names DO resolve once the assigning function has run.
    // The bug is the window before it runs, and it is invisible to a "does this resolve" test.
    //
    // A bare assignment to a name the PAGE declares is NOT this bug. Classic scripts share one
    // global lexical environment, so `activeCaseId = id` in a module writes the page's
    // `let activeCaseId` — that is the mechanism every extraction in #415 leans on. (Whether a
    // module SHOULD write page state is the state-escape question the inventory tracks; it is a
    // design smell, not a ReferenceError.) What is fatal is a name nobody declares at all.
    const pageDeclaredForReal = new Set(pageDeclared);
    for (const s of inlineScripts()) {
      for (const b of implicitGlobals(s)) pageDeclaredForReal.delete(b.name);
    }
    const leaked: string[] = [];
    for (const file of moduleFiles) {
      const script = scriptFor(file);
      const own = new Set(topLevelBindings(script).map((b) => b.name));
      for (const b of implicitGlobals(script)) {
        if (pageDeclaredForReal.has(b.name) || published.has(b.name)) continue;
        // Its own IIFE may declare it even though implicitGlobals (which walks one scope chain)
        // did not see the declaration ahead of the assignment.
        if (own.has(b.name) && !implicitGlobals(script).some((x) => x.name === b.name && x.line === b.line))
          continue;
        leaked.push(`${file}:${b.line} ${b.name}`);
      }
    }
    expect(
      leaked.sort(),
      "a module assigns a name it never declares. Non-strict, that creates the global when the " +
        "assignment runs — so any read that happens FIRST throws. Declare it inside the IIFE, or " +
        "publish it deliberately on window",
    ).toEqual([]);
  });
});

// THE ANALYSIS ITSELF, mutated. Both checks above are closed-world claims about a tree that is
// currently clean, so they return [] whether the analysis works or not. These prove it does.
describe("the analysis behind it", () => {
  const iife = (body: string) => scriptFromSource("m.js", `(function () {\n${body}\n})();`);

  it("sees an undeclared assignment inside an IIFE", () => {
    expect(implicitGlobals(iife("  cache = [];")).map((b) => b.name)).toEqual(["cache"]);
  });

  it("does not flag the same name once it is declared", () => {
    // The complement: without this, the test above passes for any implementation that always
    // reports the first assignment it sees.
    expect(implicitGlobals(iife("  let cache = [];\n  cache = [1];"))).toEqual([]);
  });

  it("does not mistake a window write for an implicit global", () => {
    expect(implicitGlobals(iife("  window.cache = [];"))).toEqual([]);
  });

  it("does not mistake a parameter or a catch binding for one", () => {
    expect(implicitGlobals(iife("  function f(x) { x = 1; }"))).toEqual([]);
    expect(implicitGlobals(iife("  try { f(); } catch (e) { e = 1; }"))).toEqual([]);
  });

  it("catches the compound-assignment forms too", () => {
    expect(implicitGlobals(iife("  cache ||= [];")).map((b) => b.name)).toEqual(["cache"]);
  });

  it("finds a name read in one function and assigned in another", () => {
    // The exact shape of the velo bug: the read is what throws, and it is nowhere near the write.
    const src = iife("  function read() { return cache.length; }\n  function fill() { cache = []; }");
    expect(implicitGlobals(src).map((b) => b.name)).toEqual(["cache"]);
  });
});
