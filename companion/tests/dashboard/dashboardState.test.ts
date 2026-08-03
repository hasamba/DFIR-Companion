import { readFile } from "node:fs/promises";
import { runInContext } from "node:vm";
import { describe, expect, it, vi } from "vitest";
import { STATIC_ASSETS } from "../../src/http/staticAssets.js";
import type { Cell, StateApi } from "./dashboardApi.js";
import {
  buildCallGraph,
  cachedSnapshots,
  callsAfter,
  dashboardScripts,
  dfirStateCalls,
  functionsOf,
  reachableFrom,
  usesAfter,
} from "../helpers/dashboardAst.js";
import { globalsAddedBy, loadDashboardModule } from "../helpers/dashboardModule.js";

// public/js/dashboard-state.js — the store the rest of dashboard.html's 422 top-level bindings are
// meant to migrate onto, and the answer to #415's actual question: who owns `lastState`.
//
// Two kinds of test here, and the second kind is the important one. The first exercises the cell
// mechanism. The second enforces the rule the mechanism exists to express — that these cells have
// ONE writer — as a gate on the source rather than as a runtime check, because a runtime check can
// only fire in a browser after the second writer has already shipped.

const MODULE = new URL("../../../public/js/dashboard-state.js", import.meta.url);
const DASHBOARD = new URL("../../../public/dashboard.html", import.meta.url);

describe("dfirCell", () => {
  const cellOf = <T>(initial?: T): Cell<T | undefined> =>
    loadDashboardModule<StateApi>("dashboard-state.js").DfirState.cell(initial);

  it("holds a value and hands it back", () => {
    const c = cellOf(1);
    expect(c.get()).toBe(1);
    c.set(2);
    expect(c.get()).toBe(2);
  });

  it("returns the value it was given, so a write can be used as an expression", () => {
    expect(cellOf().set("x")).toBe("x");
  });

  // Subscribers exist to re-render FROM the cell, so a subscriber that reads it during
  // notification must see the value that caused the notification, not the one it replaced.
  it("commits before notifying", () => {
    const c = cellOf("before");
    let seen: unknown;
    c.subscribe(() => {
      seen = c.get();
    });
    c.set("after");
    expect(seen).toBe("after");
  });

  it("passes the new value to every subscriber, in subscription order", () => {
    const c = cellOf<string>();
    const calls: string[] = [];
    c.subscribe((v) => calls.push(`a:${v}`));
    c.subscribe((v) => calls.push(`b:${v}`));
    c.set("x");
    expect(calls).toEqual(["a:x", "b:x"]);
  });

  it("stops calling a subscriber that unsubscribes", () => {
    const c = cellOf();
    const fn = vi.fn();
    const off = c.subscribe(fn);
    c.set(1);
    off();
    c.set(2);
    expect(fn).toHaveBeenCalledTimes(1);
  });

  // The array is copied before iterating. Without that, a subscriber unsubscribing itself mid-
  // notification shifts the array under the loop and the NEXT subscriber is silently skipped —
  // a bug that only shows up when two panels are listening and one of them tears down.
  it("still notifies later subscribers when an earlier one unsubscribes itself", () => {
    const c = cellOf();
    const second = vi.fn();
    const off: Array<() => void> = [];
    off.push(c.subscribe(() => off[0]()));
    c.subscribe(second);
    c.set(1);
    expect(second).toHaveBeenCalledTimes(1);
  });
});

describe("activeView", () => {
  const load = () => loadDashboardModule<StateApi>("dashboard-state.js").DfirState;

  it("starts as null, meaning the Custom layout", () => {
    expect(load().activeView()).toBeNull();
  });

  it("round-trips a view and normalises every falsy input to null", () => {
    const s = load();
    const view = { id: "now", name: "Now" };
    expect(s.setActiveView(view)).toBe(view);
    expect(s.activeView()).toBe(view);
    // applyDashboardView(undefined) means "go back to Custom", and so does
    // applyDashboardView(null) — the store answers null to both rather than leaking undefined
    // into the fourteen `!activeView()` checks.
    for (const falsy of [null, undefined, false, 0, ""]) {
      s.setActiveView(falsy);
      expect(s.activeView()).toBeNull();
    }
  });

  it("notifies subscribers of the change", () => {
    const s = load();
    const seen: unknown[] = [];
    s.onActiveViewChange((v: unknown) => seen.push(v));
    s.setActiveView({ id: "now" });
    s.setActiveView(null);
    expect(seen).toEqual([{ id: "now" }, null]);
  });
});

// THE ARCHITECTURAL GATES, AST-BASED.
//
// These started as regexes over public/dashboard.html. An audit of #460 found three holes, all of
// which mattered because #415's next phase moves hundreds of functions into modules:
//
//   - ONE FILE was scanned. The page loads 26 first-party scripts. A function that gained a second
//     writer, or cached a snapshot across a refresh, was simply not in the text being searched.
//   - ONE FUNCTION SHAPE was recognised: four-space-indented `function name(`. An injected
//     `async function` that cached lastState() and called render() passed all 35 tests.
//   - DIRECT CALLS ONLY. jumpToEvent reaches render() three hops away via
//     resetTimelineViewFilters -> setExcludeTerms, and the direct check cleared it — wrongly.
//
// tests/helpers/dashboardAst.ts now parses every script the page tags and walks every function-like
// node. The numbers below are the measure of the difference: 26 scripts, ~3,900 function nodes.
describe("the state gates see the whole client", () => {
  const scripts = dashboardScripts();

  it("scans every first-party script the page loads, not just the page", () => {
    const names = scripts.map((s) => s.name);
    expect(names.filter((n) => n.startsWith("dashboard.html#inline")).length).toBeGreaterThanOrEqual(5);
    // The helpers AND the feature modules AND the a11y layer — the module half was the gap.
    for (const required of [
      "js/dashboard-state.js",
      "js/dashboard-filters.js",
      "js/hunt-workbench.js",
      "js/a11y/modal-autowire.js",
    ]) {
      expect(names, `${required} is loaded by the dashboard but not scanned`).toContain(required);
    }
    expect(names.length).toBeGreaterThanOrEqual(20);
  });

  it("walks every function form, not just top-level declarations", () => {
    // ~3,900 against the ~800 the old four-space regex could see. The difference is arrows,
    // methods, async functions and nested callbacks — where most of the dashboard's logic lives.
    expect(scripts.flatMap(functionsOf).length).toBeGreaterThan(3000);
  });
});

// Each cell has exactly one writer, and that writer is the function that owned the variable.
// Counted from the AST, so a comment quoting the setter cannot be mistaken for a call — which is
// how the regex version first failed.
describe("the single-writer rule", () => {
  const scripts = dashboardScripts();
  const CELLS = [
    { setter: "setActiveView", owner: "applyDashboardView" },
    { setter: "setLastState", owner: "render" },
    { setter: "setLastFt", owner: "render" },
    { setter: "setLastSuperData", owner: "renderSuperTimeline" },
  ] as const;

  it.each(CELLS)("$setter has exactly one call site anywhere in the client", ({ setter }) => {
    const calls = dfirStateCalls(scripts, setter);
    expect(
      calls,
      `${setter} must have exactly one writer across all ${scripts.length} scripts; found ` +
        calls.map((c) => `${c.script}:${c.line}`).join(", "),
    ).toHaveLength(1);
  });

  it.each(CELLS)("$setter is called from $owner", ({ setter, owner }) => {
    const [call] = dfirStateCalls(scripts, setter);
    const script = scripts.find((s) => s.name === call.script);
    const enclosing = functionsOf(script!)
      .filter((f) => {
        const { line } = script!.ast.getLineAndCharacterOfPosition(f.node.getEnd());
        return f.line <= call.line && line + 1 >= call.line;
      })
      .map((f) => f.name);
    expect(enclosing, `${setter} is written outside ${owner}()`).toContain(owner);
  });
});

// NO SNAPSHOT MAY BE CACHED ACROSS SOMETHING THAT CAN REPLACE IT.
//
// 16 of the 84 readers call their own writer. Reading a bare `let` always saw the current value; a
// cached accessor result does not. But "never cache" is the wrong rule and the first draft of this
// gate got it wrong: jumpToEvent reads the timeline once and renders that same array, and a
// consistent snapshot across its body is the point.
//
// So the rule is positional and transitive: a cache is a fault only when something reachable from
// the writer runs AFTER it. That is the real invariant rather than a proxy for it, and it is why
// this flags exactly the functions that are wrong instead of every function that caches.
describe("no snapshot is cached across a refresh", () => {
  const scripts = dashboardScripts();
  const graph = buildCallGraph(scripts);
  const CELLS = [
    { cell: "lastState", writer: "render" },
    { cell: "lastFt", writer: "render" },
    { cell: "lastSuperData", writer: "renderSuperTimeline" },
  ] as const;

  it.each(CELLS)("$cell is never used after a refresh that followed caching it", ({ cell, writer }) => {
    const offenders: string[] = [];
    for (const script of scripts) {
      for (const fn of functionsOf(script)) {
        for (const cached of cachedSnapshots(fn.node, cell)) {
          // A cache is only a fault when the value is READ again after something that can replace
          // it has run. Passing the cached value INTO a refreshing renderer is the intended use —
          // the refresh happens inside the callee, after the argument is already bound — so the
          // rule is cache -> refresh -> use, not merely cache -> refresh.
          const refreshers = callsAfter(fn.node, cached.pos).filter(
            (c) => c.name === writer || reachableFrom(graph, [c.name]).has(writer),
          );
          for (const r of refreshers) {
            if (usesAfter(fn.node, cached.name, r.end).length > 0) {
              offenders.push(
                `${script.name}:${fn.line} ${fn.name} reads \`${cached.name}\` after calling ${r.name}()`,
              );
              break;
            }
          }
        }
      }
    }
    expect(
      offenders,
      `a snapshot cached before a refresh is stale by the time it is used. Read ${cell} after the ` +
        "call that can replace it, or do not cache it.",
    ).toEqual([]);
  });
});

describe("nothing but the namespace escapes", () => {
  it("adds only DfirState to the global object", () => {
    expect(globalsAddedBy("dashboard-state.js")).toEqual(["DfirState"]);
  });

  // The lexical half, which globalsAddedBy() cannot see: a `const` in the shared lexical
  // environment is invisible to Object.keys but perfectly reachable by name. So the bypass is
  // attempted for real, from a second script in the same context, and must not resolve.
  it("puts the cell out of reach of a second script on the page", () => {
    const globals = loadDashboardModule<StateApi>("dashboard-state.js");
    globals.DfirState.setActiveView({ id: "legit" });
    expect(() => runInContext("dfirActiveView.set({ id: 'smuggled' })", globals as object)).toThrow(
      /dfirActiveView is not defined/,
    );
    expect(() => runInContext("dfirCell(0)", globals as object)).toThrow(/dfirCell is not defined/);
    expect(globals.DfirState.activeView()).toEqual({ id: "legit" });
  });
});

describe("wiring", () => {
  it("is loaded by dashboard.html, ahead of the inline script, and served by the whitelist", async () => {
    const html = await readFile(DASHBOARD, "utf8");
    expect(html).toContain('<script src="/js/dashboard-state.js"></script>');
    expect(html.indexOf('src="/js/dashboard-state.js"')).toBeLessThan(html.lastIndexOf("<script nonce="));
    expect(STATIC_ASSETS["/js/dashboard-state.js"]).toBe("application/javascript; charset=utf-8");
  });

  it("stays a classic script, like the helpers the inline script calls by name", async () => {
    expect(await readFile(MODULE, "utf8")).not.toMatch(/^\s*(export|import)\s/m);
  });
});

// ── TIER 1: THE CASE SNAPSHOT ──────────────────────────────────────────────────────────────────
//
// 84 reader functions across three cells, migrated in one change. The mechanism was already proven
// by activeView, so what these tests are for is the migration itself: that each cell still has
// exactly one writer, that the writer is the function that owned the variable, and — the one that
// is genuinely new — that no reader caches the value in a local.

const SNAPSHOT_CELLS = [
  { read: "lastState", write: "setLastState", owner: "render", initial: null },
  { read: "lastFt", write: "setLastFt", owner: "render", initial: [] },
  { read: "lastSuperData", write: "setLastSuperData", owner: "renderSuperTimeline", initial: null },
] as const;

describe("the snapshot cells", () => {
  const load = () => loadDashboardModule<StateApi>("dashboard-state.js").DfirState;

  it.each(SNAPSHOT_CELLS)("$read starts at its pre-migration default", ({ read, initial }) => {
    const s = load() as unknown as Record<string, () => unknown>;
    expect(s[read]()).toEqual(initial);
  });

  // Identity, not equality: 84 readers reach into the object they get back, and a cell that cloned
  // on read would break `lastState().findings === lastState().findings` in ways nothing would catch.
  it.each(SNAPSHOT_CELLS)("$read hands back the very object it was given", ({ read, write }) => {
    const s = load() as unknown as Record<string, (v?: unknown) => unknown>;
    const value = { findings: [{ id: "f1" }] };
    s[write](value);
    expect(s[read]()).toBe(value);
  });

  it("notifies per cell, and only for that cell", () => {
    const s = load();
    const seen: string[] = [];
    s.onLastStateChange(() => seen.push("state"));
    s.onLastFtChange(() => seen.push("ft"));
    s.onLastSuperDataChange(() => seen.push("super"));
    s.setLastFt([{ a: 1 }]);
    expect(seen).toEqual(["ft"]);
  });
});
