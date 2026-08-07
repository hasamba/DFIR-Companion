import { readFile } from "node:fs/promises";
import { runInContext } from "node:vm";
import { describe, expect, it } from "vitest";
import { STATIC_ASSETS } from "../../src/http/staticAssets.js";
import type { FacetsApi, FiltersApi } from "./dashboardApi.js";
import {
  buildCallGraph,
  calleesInsideLoops,
  commitsInsideLoops,
  dashboardScripts,
  functionsOf,
  ownerCalls,
  ownerEscapes,
  reachableFrom,
  scriptFromSource,
  topLevelBindings,
} from "../helpers/dashboardAst.js";
import { globalsAddedBy, loadDashboardModule } from "../helpers/dashboardModule.js";

// public/js/dashboard-facets.js — the first piece of the timeline view (#415 tier 2).
//
// It goes before the rest of that view because the rest cannot be built on what it replaces: FOUR
// RENDERERS wrote these sets while drawing them, so "one coordinated commit per user action" was
// not expressible. The gate at the bottom is therefore the point of the change, not a nicety.

const MODULE = new URL("../../../public/js/dashboard-facets.js", import.meta.url);
const DASHBOARD = new URL("../../../public/dashboard.html", import.meta.url);

const load = () => loadDashboardModule<FacetsApi>("dashboard-facets.js", ["dashboard-state.js"]);
const scripts = dashboardScripts();

describe("a facet filter", () => {
  it("hides nothing to begin with", () => {
    const { DfirFacets } = load();
    expect(DfirFacets.sources.countIn(["velociraptor"])).toBe(0);
    expect(DfirFacets.sources.has("velociraptor")).toBe(false);
  });

  it("toggles one facet with an explicit state, and flips without one", () => {
    const { DfirFacets } = load();
    DfirFacets.sources.toggle("evtx", true);
    expect(DfirFacets.sources.has("evtx")).toBe(true);
    DfirFacets.sources.toggle("evtx");
    expect(DfirFacets.sources.has("evtx")).toBe(false);
  });

  it("hides every facet in one call and shows them all again", () => {
    const { DfirFacets } = load();
    DfirFacets.sources.hideAll(["a", "b", "c"]);
    expect(DfirFacets.sources.countIn(["a", "b", "c"])).toBe(3);
    DfirFacets.sources.showAll();
    expect(DfirFacets.sources.countIn(["a", "b", "c"])).toBe(0);
  });

  it("keeps the four facets independent", () => {
    const { DfirFacets } = load();
    DfirFacets.sources.toggle("x", true);
    for (const other of ["origins", "hosts", "iocTypes"] as const) {
      expect(DfirFacets[other].has("x")).toBe(false);
    }
  });
});

// ── THE DERIVED PRUNE ────────────────────────────────────────────────────────────────────────────
//
// Four renderers used to delete unchecked facets that no longer existed, mid-render and inside a
// loop. The effective set is now `hidden ∩ available`, computed at read time.
describe("the effective set is derived, not stored", () => {
  it("does not count a hidden name that is no longer available", () => {
    const { DfirFacets } = load();
    DfirFacets.sources.hideAll(["evtx", "gone"]);
    expect(DfirFacets.sources.countIn(["evtx", "mft"])).toBe(1);
  });

  // THE DELIBERATE BEHAVIOUR CHANGE, pinned so it is a decision rather than a drift. Today the
  // prune forgot the tick; now it is remembered when the facet comes back.
  it("remembers a hidden facet that disappears and returns", () => {
    const { DfirFacets } = load();
    DfirFacets.sources.toggle("evtx", true);
    expect(DfirFacets.sources.countIn(["mft"])).toBe(0); // evtx absent from this import
    expect(DfirFacets.sources.countIn(["evtx", "mft"])).toBe(1); // …and back, still hidden
    expect(DfirFacets.sources.has("evtx")).toBe(true);
  });

  // renderIocTypeFilter computed `types.length - hiddenIocTypes.size` from the RAW size, which was
  // only right immediately after the prune ran. A derived count cannot be stale.
  it("cannot report more hidden than are actually available", () => {
    const { DfirFacets } = load();
    DfirFacets.iocTypes.hideAll(["ip", "domain", "hash"]);
    expect(DfirFacets.iocTypes.countIn(["ip"])).toBe(1);
    expect(DfirFacets.iocTypes.countIn([])).toBe(0);
  });

  it("tolerates an absent or empty available list", () => {
    const { DfirFacets } = load();
    DfirFacets.sources.hideAll(["a"]);
    expect(DfirFacets.sources.countIn(undefined)).toBe(0);
    DfirFacets.sources.hideAll(undefined);
    expect(DfirFacets.sources.countIn(["a"])).toBe(1);
  });
});

// ── A FILTER THE ANALYST CANNOT SEE ──────────────────────────────────────────────────────────────
//
// The regression review found, and the reason retention needed a guard rather than just a note.
//
// Each facet picker hides itself when there is nothing to choose (`origins.length < 2`, and so on)
// while the FILTER applies regardless. So: hide A, A disappears on re-import, A comes back as the
// only value — every row vanishes and the control that would undo it is not on screen. In a
// forensics tool that is evidence disappearing with no way to get it back.
//
// It is not purely a retention bug either: hide one of two facets, let the other disappear, and the
// same trap springs on code that predates DfirFacets. Both paths are closed by the same rule —
// A CONTROL THE ANALYST CANNOT SEE MUST NOT BE FILTERING — enforced in dashboard.html by keeping
// the picker up whenever the effective count is non-zero, and asserted here on the arithmetic the
// renderers use to decide.
describe("a hidden facet never leaves the analyst without a control", () => {
  it("reports a live filter when the sole remaining facet is the hidden one", () => {
    const { DfirFacets } = load();
    DfirFacets.origins.toggle("A", true);
    // A vanished, then came back alone. The renderer's threshold is `length < 2`, so without the
    // guard the picker hides — and this count is what now keeps it on screen.
    expect(DfirFacets.origins.countIn(["A"])).toBe(1);
  });

  it("reports no filter once the analyst clears it, so the control may hide again", () => {
    const { DfirFacets } = load();
    DfirFacets.origins.toggle("A", true);
    DfirFacets.origins.showAll();
    expect(DfirFacets.origins.countIn(["A"])).toBe(0);
  });

  it("keeps the picker's threshold and the filter's flag reading the SAME number", () => {
    // The two used to disagree: the button used `hidden ∩ available` while the filter used the raw
    // size, which is how a remembered-but-absent facet lit "N of N events" with the button dark.
    const { DfirFacets } = load();
    DfirFacets.hosts.hideAll(["gone-a", "gone-b"]);
    expect(DfirFacets.hosts.countIn(["present"])).toBe(0);
    expect(DfirFacets.hosts.countIn(["present", "gone-a"])).toBe(1);
  });
});

// The one cross-module coupling the census found: realSourceCount(sources, hidden) needs an object
// with `.has()`. The owner satisfies that itself, so no Set is handed out and no adapter is needed —
// which is why the read is named `has` rather than `isHidden`.
describe("the owner can stand in for the hidden set it replaced", () => {
  // No cast: matcher() IS the has-only shape realSourceCount declares. An earlier version passed
  // the owner behind `as unknown as Set<string>`, which hid the fact that the parameter type was
  // wrong AND handed a writable object to a helper that only reads.
  it("works as the `hidden` argument of realSourceCount", () => {
    const { DfirFacets } = load();
    const { realSourceCount } = loadDashboardModule<FiltersApi>("dashboard-filters.js");
    const sources = ["evtx", "mft", "unknown source"];
    expect(realSourceCount(sources)).toBe(2);
    DfirFacets.sources.toggle("evtx", true);
    expect(realSourceCount(sources, DfirFacets.sources.matcher())).toBe(1);
  });

  it("hands out a frozen view that cannot write the facet", () => {
    const { DfirFacets } = load();
    DfirFacets.sources.toggle("evtx", true);
    const view = DfirFacets.sources.matcher();
    expect(Object.isFrozen(view)).toBe(true);
    expect(Object.keys(view)).toEqual(["has"]);
    expect(view.has("evtx")).toBe(true);
  });
});

describe("the container never escapes", () => {
  it("publishes no way to obtain the Set", () => {
    const { DfirFacets } = load();
    expect(Object.keys(DfirFacets.sources).sort()).toEqual([
      "countIn",
      "has",
      "hideAll",
      "matcher",
      "showAll",
      "toggle",
    ]);
  });

  it("adds only DfirFacets to the global object", () => {
    expect(globalsAddedBy("dashboard-facets.js", ["dashboard-state.js"])).toEqual(["DfirFacets"]);
  });

  it("puts the sets out of reach of a second script on the page", () => {
    const api = load();
    api.DfirFacets.sources.toggle("legit", true);
    expect(() => runInContext("facet()", api as object)).toThrow(/facet is not defined/);
    expect(api.DfirFacets.sources.has("legit")).toBe(true);
  });
});

// ── THE GATE ─────────────────────────────────────────────────────────────────────────────────────
describe("no renderer writes a facet", () => {
  const COMMITS = ["toggle", "hideAll", "showAll"] as const;

  // THE WHOLE POINT OF THIS STEP. renderSourceFilter, renderOriginFilter, renderHostFilter and
  // renderIocTypeFilter each edited the filter they were about to read — a write during a render,
  // inside a loop, which no "one commit per user action" API can be layered on top of. A renderer
  // that commits again is that coupling coming back.
  // FOLLOWED THROUGH THE CALL GRAPH, not just the function holding the literal call. Review showed
  // `function renderHosts() { mutate(); }` with the commit one hop away reported no offender at
  // all — the same direct-vs-transitive hole that cleared jumpToEvent earlier in #415. Full
  // reachability is right HERE (unlike the loop rule, which is bounded): the source set is the
  // named render* functions and the target is "commits to DfirFacets", both specific.
  it("has no render* function reaching a commit to DfirFacets", () => {
    const graph = buildCallGraph(scripts);
    const committers = new Set(
      ownerCalls(scripts, "DfirFacets", COMMITS)
        .map((c) => c.fn)
        .filter((f) => !f.startsWith("<")),
    );
    const renderers = scripts.flatMap((s) =>
      functionsOf(s)
        .map((f) => f.name)
        .filter((n) => /^render/i.test(n)),
    );
    const offenders: string[] = [];
    for (const r of new Set(renderers)) {
      if (committers.has(r)) offenders.push(`${r}() commits directly`);
      for (const reached of reachableFrom(graph, [r])) {
        if (committers.has(reached)) offenders.push(`${r}() reaches ${reached}(), which commits`);
      }
    }
    expect(
      [...new Set(offenders)],
      "a renderer that writes the filter it draws is the coupling js/dashboard-facets.js removed; " +
        "derive the effective set with countIn() instead.",
    ).toEqual([]);
  });

  // THE GUARD, PINNED IN THE PAGE. The arithmetic tests above cannot see whether the renderers
  // actually consult it, and that is exactly the gap review flagged: the suite was green while two
  // visible regressions sat in the production renderers.
  it("gates every picker's hide-condition on the effective hidden count", async () => {
    // The four pickers moved to js/dashboard-facet-filters.js (#415); the guard is pinned there now.
    const html = await readFile(
      new URL("../../../public/js/dashboard-facet-filters.js", import.meta.url),
      "utf8",
    );
    expect(html.length, "facet-filters module is empty — has it moved?").toBeGreaterThan(500);
    // Whitespace-tolerant: prettier puts the body on its own line in a module, and the one-line
    // form only held while this lived in dashboard.html — the one file prettier does not format.
    const hides = [...html.matchAll(/if \((\w+)\.length < \d[^)]*\)\s*\{\s*wrap\.style\.display = "none"/g)];
    expect(hides.length, "expected the four facet pickers").toBe(4);
    for (const m of hides) {
      expect(m[0], `${m[1]} hides its picker without checking whether a filter is still live on it`).toMatch(
        /hidden\w* === 0/,
      );
    }
  });

  it("no longer prunes the analyst's choice from inside a render", async () => {
    const html = await readFile(DASHBOARD, "utf8");
    // The exact shape that was deleted, in any of its four spellings.
    expect(html).not.toMatch(/for \(const \w+ of \[\.\.\.hidden\w+\]\)/);
  });

  it("commits to no facet from inside a loop", () => {
    const offenders = ownerCalls(scripts, "DfirFacets", COMMITS)
      .filter((c) => c.inLoop)
      .map((c) => `${c.script}:${c.line} ${c.fn}() -> ${c.path}()`);
    expect(offenders, '"hide none" used to add one facet at a time; hideAll() commits once.').toEqual([]);
  });

  // Two hops, matching the selection owner's rule — a direct-callee check misses
  // `for (…) outer(x)` where outer() calls inner() which commits.
  it("has no function reachable from a loop through any number of hops that commits", () => {
    const committers = new Set(
      ownerCalls(scripts, "DfirFacets", COMMITS)
        .map((c) => c.fn)
        .filter((f) => !f.startsWith("<")),
    );
    const graph = buildCallGraph(scripts);
    const offenders: string[] = [];
    for (const callee of calleesInsideLoops(scripts)) {
      const reach = new Set([callee, ...reachableFrom(graph, [callee])]);
      for (const c of committers) if (reach.has(c)) offenders.push(`${callee}() reaches ${c}()`);
    }
    expect([...new Set(offenders)]).toEqual([]);
  });

  it("is never aliased or reached dynamically", () => {
    expect(ownerEscapes(scripts, "DfirFacets").map((e) => `${e.script}:${e.line} ${e.form}`)).toEqual([]);
  });

  // The same hazard one level down: hideAll() written as a loop of commits is the quadratic cost
  // moved inside the module, where no call-site check sees it. Checked against the AST, because a
  // textual count of `commit(` passes this exact mutation — one call in a loop is one occurrence.
  it("makes no commit once per element, in any spelling", async () => {
    const script = scriptFromSource("dashboard-facets.js", await readFile(MODULE, "utf8"));
    const offenders = commitsInsideLoops(script, ["commit", "set"]).map(
      (c) => `${c.fn}():${c.line} commits per element${c.via ? ` via ${c.via}()` : ""}`,
    );
    expect(offenders).toEqual([]);
  });

  it("actually finds the commits it is checking, so the gate is not vacuous", () => {
    expect(ownerCalls(scripts, "DfirFacets", COMMITS).length).toBeGreaterThan(8);
  });
});

describe("the old bindings are gone", () => {
  it.each(["hiddenSources", "hiddenOrigins", "hiddenHosts", "hiddenIocTypes"])(
    "%s has no binding left in the page",
    (name) => {
      // EVERY script the page loads, not just the inline blocks: a legacy binding re-created in a
      // /js/ module is the same page global, and scoping this to the inline script was a hole.
      const offenders = scripts.flatMap((s) =>
        topLevelBindings(s)
          .filter((b) => b.name === name)
          .map((b) => `${s.name}:${b.line}`),
      );
      expect(offenders).toEqual([]);
    },
  );

  it("leaves the menu-signature locals behind, which are genuinely render-local", () => {
    // Deliberate contrast: `_srcMenuSig` and friends are a renderer's own memo of what it last
    // drew, not shared filter state, so they stay in the page as tier-3 material.
    const inline = scripts.filter((s) => s.name.startsWith("dashboard.html#inline"));
    const names = inline.flatMap((s) => topLevelBindings(s).map((b) => b.name));
    expect(names).toContain("_srcMenuSig");
  });
});

describe("wiring", () => {
  it("is loaded by dashboard.html, ahead of the inline script, and served by the whitelist", async () => {
    const html = await readFile(DASHBOARD, "utf8");
    expect(html).toContain('<script src="/js/dashboard-facets.js"></script>');
    const tag = html.indexOf('src="/js/dashboard-facets.js"');
    expect(html.indexOf('src="/js/dashboard-state.js"')).toBeLessThan(tag);
    const blocks = [...html.matchAll(/<script(?![^>]*\ssrc=)[^>]*>([\s\S]*?)<\/script>/g)];
    const main = blocks.find((m) => /\n\s*function render\s*\(/.test(m[1]));
    expect(main).toBeDefined();
    expect(tag).toBeLessThan(main!.index);
    expect(STATIC_ASSETS["/js/dashboard-facets.js"]).toBe("application/javascript; charset=utf-8");
  });

  it("stays a classic script", async () => {
    const src = await readFile(MODULE, "utf8");
    expect(src).not.toMatch(/^\s*(?:export|import)\s/m);
  });
});
