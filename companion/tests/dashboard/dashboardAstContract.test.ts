// The CONTRACT of tests/helpers/dashboardAst.ts, tested directly.
//
// WHY THIS FILE EXISTS. Six holes have been found in these gates across #415, and every one was
// found by a person reading the helper rather than by a test: the `async function` shape, the
// single-file scan, the direct-call-only reachability, the window-rooted namespace, the callback
// loop, and the detached method reference. The gates themselves stayed green throughout, because
// the page happened not to contain the shape being missed.
//
// So the helpers are now exercised on snippets that DO contain those shapes. Each case below is a
// bypass that review found in a real audit, kept as the regression test it should always have been —
// and each has a partner asserting what must NOT be reported, because a check that flags everything
// is as useless as one that flags nothing.

import { describe, expect, it } from "vitest";
import {
  buildCallGraph,
  ownerEscapes,
  calleesInsideLoops,
  commitsInsideLoops,
  ownerCalls,
  reachableFrom,
  scriptFromSource,
  topLevelBindings,
} from "../helpers/dashboardAst.js";

const COMMITS = ["toggle", "addAll", "removeAll", "clear", "showAll", "hideAll"];

describe("the loop rule follows a wrapper, but not a deferred callback", () => {
  it("catches a commit several hops from a loop callee", () => {
    const s = scriptFromSource(
      "p.js",
      `
      function inner(x) { DfirSelection.events.toggle(x, true); }
      function outer(x) { inner(x); }
      function drive(xs) { for (const x of xs) outer(x); }`,
    );
    const committers = new Set(ownerCalls([s], "DfirSelection", COMMITS).map((c) => c.fn));
    const graph = buildCallGraph([s]);
    let caught = false;
    for (const callee of calleesInsideLoops([s])) {
      const reach = new Set([callee, ...reachableFrom(graph, [callee])]);
      for (const c of committers) if (reach.has(c)) caught = true;
    }
    expect(caught, "two-hop wrapper still invisible").toBe(true);
  });

  it("does not count a keystroke handler registered inside a loop", () => {
    const s = scriptFromSource(
      "p.js",
      `
      function commitIt() { DfirSelection.events.clear(); }
      ["a","b"].forEach((id) => document.getElementById(id).addEventListener("click", () => commitIt()));`,
    );
    const committers = new Set(ownerCalls([s], "DfirSelection", COMMITS).map((c) => c.fn));
    const graph = buildCallGraph([s]);
    const hits: string[] = [];
    for (const callee of calleesInsideLoops([s])) {
      const reach = new Set([callee, ...reachableFrom(graph, [callee])]);
      for (const c of committers) if (reach.has(c)) hits.push(`${callee}->${c}`);
    }
    expect(hits, "a keystroke handler is not a per-element commit").toEqual([]);
  });

  it("catches cell.set() inside a bulk operation", () => {
    const s = scriptFromSource(
      "m.js",
      `
      function idSet() {
        const cell = window.DfirState.cell(new Set());
        return { addAll(ids) { for (const id of ids) cell.set(new Set([id])); } };
      }`,
    );
    expect(commitsInsideLoops(s, ["commit", "set"]).map((c) => c.fn)).toContain("addAll");
  });

  it("catches a helper that commits, called from a bulk loop", () => {
    const s = scriptFromSource(
      "m.js",
      `
      function idSet() {
        const cell = window.DfirState.cell(new Set());
        const commit = (n) => cell.set(n);
        function put(x) { commit(new Set([x])); }
        return { hideAll(ids) { for (const id of ids) put(id); } };
      }`,
    );
    const found = commitsInsideLoops(s, ["commit", "set"]);
    expect(found.map((c) => `${c.fn} via ${c.via}`)).toContain("hideAll via put");
  });

  it("reports nothing against the real owner modules", async () => {
    const { readFile } = await import("node:fs/promises");
    for (const f of ["dashboard-selection.js", "dashboard-facets.js"]) {
      const src = await readFile(new URL(`../../../public/js/${f}`, import.meta.url), "utf8");
      expect(commitsInsideLoops(scriptFromSource(f, src), ["commit", "set"])).toEqual([]);
    }
  });

  // Every form review found walking past the gates, each kept as the regression test it should
  // always have been.
  it("catches a commit inside an iteration callback within a bulk operation", () => {
    const s = scriptFromSource(
      "m.js",
      `
      function idSet() {
        const cell = window.DfirState.cell(new Set());
        return { addAll(ids) { ids.forEach((id) => cell.set(new Set([id]))); } };
      }`,
    );
    expect(commitsInsideLoops(s, ["commit", "set"]).map((c) => c.fn)).toContain("addAll");
  });

  it.each([
    [
      "a synchronous IIFE",
      `for (const id of ids) (function () { DfirSelection.events.toggle(id, true); })();`,
    ],
    ["a parenthesised callback", `ids.forEach((id) => { DfirSelection.events.toggle(id, true); });`],
    [
      "one queued commit per item",
      `for (const id of ids) queueMicrotask(() => DfirSelection.events.toggle(id, true));`,
    ],
  ])("still counts %s as per-element", (_label, src) => {
    expect(ownerCalls([scriptFromSource("p.js", src)], "DfirSelection", COMMITS).some((c) => c.inLoop)).toBe(
      true,
    );
  });

  it.each([
    [
      "an inline listener",
      `for (const id of ids) el(id).addEventListener("click", () => DfirSelection.events.clear());`,
    ],
    [
      "a named handler",
      `function h() { DfirSelection.events.clear(); }\nfor (const id of ids) el(id).addEventListener("click", h);`,
    ],
    ["an on* assignment", `for (const id of ids) { el(id).onclick = () => DfirSelection.events.clear(); }`],
  ])("does not count %s, which runs on an event and not per element", (_label, src) => {
    const s = scriptFromSource("p.js", src);
    expect(ownerCalls([s], "DfirSelection", COMMITS).some((c) => c.inLoop)).toBe(false);
    const committers = new Set(
      ownerCalls([s], "DfirSelection", COMMITS)
        .map((c) => c.fn)
        .filter((f) => !f.startsWith("<")),
    );
    const graph = buildCallGraph([s]);
    const viaCallee = [...calleesInsideLoops([s])].some((c) => {
      const reach = new Set([c, ...reachableFrom(graph, [c])]);
      return [...committers].some((x) => reach.has(x));
    });
    expect(viaCallee).toBe(false);
  });

  it.each([
    ["a var in a for-of head", `for (var selectedEvents of sets) {}`],
    ["a logical-assignment global", `window.hiddenSources ??= new Set();`],
    ["a template-literal key", 'globalThis[`searchTerm`] = "";'],
  ])("counts %s as a binding", (_label, src) => {
    const name = ["selectedEvents", "hiddenSources", "searchTerm"].find((n) => src.includes(n))!;
    expect(topLevelBindings(scriptFromSource("p.js", src)).map((b) => b.name)).toContain(name);
  });

  it.each([
    ["a reflective invoke", `DfirSelection.events.toggle.call(null, "x");`],
    ["a method overwrite", `DfirSelection.events.toggle = function () {};`],
  ])("does not let %s past both gates", (_label, src) => {
    const s = scriptFromSource("p.js", src);
    const seen =
      ownerCalls([s], "DfirSelection", COMMITS).length > 0 || ownerEscapes([s], "DfirSelection").length > 0;
    expect(seen, "reaches a writable member and is reported by neither gate").toBe(true);
  });

  it("counts a computed global assignment as a binding", () => {
    for (const [src, name] of [
      [`globalThis["hiddenSources"] = new Set();`, "hiddenSources"],
      [`window["selectedEvents"] = new Set();`, "selectedEvents"],
      [`self["searchTerm"] = "";`, "searchTerm"],
    ] as const) {
      expect(
        topLevelBindings(scriptFromSource("p.js", src)).map((b) => b.name),
        src,
      ).toContain(name);
    }
  });
});
