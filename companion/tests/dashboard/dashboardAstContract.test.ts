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
  calleesInsideLoops,
  commitsInsideLoops,
  ownerCalls,
  reachableWithin,
  scriptFromSource,
  topLevelBindings,
} from "../helpers/dashboardAst.js";

const COMMITS = ["toggle", "addAll", "removeAll", "clear", "showAll", "hideAll"];

describe("the loop rule follows a wrapper, but not a deferred callback", () => {
  it("catches a commit two hops from a loop callee", () => {
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
      const reach = new Set([callee, ...reachableWithin(graph, [callee], 2)]);
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
      const reach = new Set([callee, ...reachableWithin(graph, [callee], 2)]);
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
