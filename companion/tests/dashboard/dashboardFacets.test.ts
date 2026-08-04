import { readFile } from "node:fs/promises";
import { runInContext } from "node:vm";
import { describe, expect, it } from "vitest";
import { STATIC_ASSETS } from "../../src/http/staticAssets.js";
import type { FacetsApi, FiltersApi } from "./dashboardApi.js";
import {
  calleesInsideLoops,
  dashboardScripts,
  functionsOf,
  insideLoop,
  ownerCallPositions,
  ownerCalls,
  ownerEscapes,
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
    expect(DfirFacets.sources.any()).toBe(false);
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
    expect(DfirFacets.sources.any()).toBe(false);
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

// The one cross-module coupling the census found: realSourceCount(sources, hidden) needs an object
// with `.has()`. The owner satisfies that itself, so no Set is handed out and no adapter is needed —
// which is why the read is named `has` rather than `isHidden`.
describe("the owner can stand in for the hidden set it replaced", () => {
  it("works as the `hidden` argument of realSourceCount", () => {
    const { DfirFacets } = load();
    const { realSourceCount } = loadDashboardModule<FiltersApi>("dashboard-filters.js");
    const sources = ["evtx", "mft", "unknown source"];
    expect(realSourceCount(sources, undefined)).toBe(2);
    DfirFacets.sources.toggle("evtx", true);
    expect(realSourceCount(sources, DfirFacets.sources as unknown as Set<string>)).toBe(1);
  });
});

describe("the container never escapes", () => {
  it("publishes no way to obtain the Set", () => {
    const { DfirFacets } = load();
    expect(Object.keys(DfirFacets.sources).sort()).toEqual([
      "any",
      "countIn",
      "has",
      "hideAll",
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
  it("has no render* function committing to DfirFacets", () => {
    const offenders = ownerCalls(scripts, "DfirFacets", COMMITS)
      .filter((c) => /^render/i.test(c.fn))
      .map((c) => `${c.script}:${c.line} ${c.fn}() -> ${c.path}()`);
    expect(
      offenders,
      "a renderer that writes the filter it draws is the coupling js/dashboard-facets.js removed; " +
        "derive the effective set with countIn() instead.",
    ).toEqual([]);
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

  it("has no function called from inside a loop that commits", () => {
    const committers = new Set(
      ownerCalls(scripts, "DfirFacets", COMMITS)
        .map((c) => c.fn)
        .filter((f) => !f.startsWith("<")),
    );
    const offenders = [...calleesInsideLoops(scripts)].filter((c) => committers.has(c));
    expect(offenders).toEqual([]);
  });

  it("is never aliased or reached dynamically", () => {
    expect(ownerEscapes(scripts, "DfirFacets").map((e) => `${e.script}:${e.line} ${e.form}`)).toEqual([]);
  });

  // The same hazard one level down: hideAll() written as a loop of commits is the quadratic cost
  // moved inside the module, where no call-site check sees it. Checked against the AST, because a
  // textual count of `commit(` passes this exact mutation — one call in a loop is one occurrence.
  it("has no bulk operation looping around its own commit", async () => {
    const script = scriptFromSource("dashboard-facets.js", await readFile(MODULE, "utf8"));
    const offenders: string[] = [];
    for (const fn of functionsOf(script).filter((f) => ["hideAll", "showAll", "toggle"].includes(f.name))) {
      for (const pos of ownerCallPositions(fn.node, "commit")) {
        if (insideLoop(fn.node, pos)) offenders.push(`${fn.name}() commits inside a loop`);
      }
    }
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
      const offenders = scripts
        .filter((s) => s.name.startsWith("dashboard.html#inline"))
        .flatMap((s) =>
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
