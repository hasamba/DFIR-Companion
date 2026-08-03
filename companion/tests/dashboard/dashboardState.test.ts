import { readFile } from "node:fs/promises";
import { runInContext } from "node:vm";
import { describe, expect, it, vi } from "vitest";
import { STATIC_ASSETS } from "../../src/http/staticAssets.js";
import type { Cell, StateApi } from "./dashboardApi.js";
import { dashboardClientSource, globalsAddedBy, loadDashboardModule } from "../helpers/dashboardModule.js";

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

// THE ACTUAL INVARIANT. Tier 1 and tier 2 in the module's header are defined by having very few
// writers — `lastState` has exactly one across 43 readers — and the whole decision rests on that
// staying true. A second writer appearing is the failure this design has to prevent, and the
// cheapest place to prevent it is here, in the PR that would add it.
describe("the single-writer rule", () => {
  // Comment lines are dropped before counting. Not fastidiousness: the first run of this test
  // failed because dashboard-state.js's own header described the rule using the literal string the
  // regex looks for, so the module documenting the invariant counted as a violation of it. A gate
  // that greps source has to decide what counts as source, and prose about the code is not it.
  //
  // Line-based rather than a real parser, because the haystack is HTML, CSS and JS concatenated,
  // and stripping `//` from that would eat every `https://` in the markup.
  const codeOnly = (source: string): string =>
    source
      .split("\n")
      .filter((line) => !/^\s*(\/\/|\*|<!--)/.test(line))
      .join("\n");

  it("has exactly one call site that writes activeView", () => {
    const writes = [...codeOnly(dashboardClientSource()).matchAll(/DfirState\.setActiveView\(/g)];
    expect(
      writes,
      "activeView is owned by applyDashboardView(). A second writer means the cell is shared " +
        "mutable state again, which is the thing js/dashboard-state.js exists to stop.",
    ).toHaveLength(1);
  });

  it("puts that call site inside applyDashboardView", async () => {
    const html = await readFile(DASHBOARD, "utf8");
    const at = html.indexOf("DfirState.setActiveView(");
    const owner = html.lastIndexOf("function applyDashboardView(", at);
    const nextFn = html.indexOf("\n    function ", owner + 1);
    expect(owner, "no applyDashboardView() before the write").toBeGreaterThan(-1);
    expect(at, "the write escaped applyDashboardView()").toBeLessThan(nextFn);
  });

  // The bare identifier is gone from the page: `let activeView` no longer exists, so a stray
  // `activeView = x` would be a ReferenceError rather than a silent second source of truth.
  it("leaves no top-level activeView binding behind in the inline script", async () => {
    const html = await readFile(DASHBOARD, "utf8");
    expect(html).not.toMatch(/^\s*(let|var|const)\s+activeView\b/m);
  });
});

// WHY COUNTING CALL SITES WAS NOT ENOUGH ON ITS OWN.
//
// The first version of this file shipped with the cell as a top-level `const` in a classic script.
// That reads as private — it never appears on the global object — but a classic script's top-level
// `const` goes into the global LEXICAL environment, which every other script on the page shares.
// `dfirActiveView.set(x)` from any later script therefore wrote the cell while the call-site count
// above, which looks for `DfirState.setActiveView(`, stayed at one. The invariant this module's
// whole argument rests on was decorative, and CI would have passed a second writer.
//
// Both halves are now checked: the closure closes the hole, and these two tests are what notices
// if a future edit hoists something back out of it.
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

describe("the snapshot single-writer rule", () => {
  const codeOnly = (source: string): string =>
    source
      .split("\n")
      .filter((line) => !/^\s*(\/\/|\*|<!--)/.test(line))
      .join("\n");

  it.each(SNAPSHOT_CELLS)("$write has exactly one call site", ({ write, read }) => {
    const calls = [...codeOnly(dashboardClientSource()).matchAll(new RegExp(`DfirState\\.${write}\\(`, "g"))];
    expect(calls, `${read} must keep exactly one writer`).toHaveLength(1);
  });

  it.each(SNAPSHOT_CELLS)("$write is called from $owner", async ({ write, owner }) => {
    const html = await readFile(DASHBOARD, "utf8");
    const at = html.indexOf(`DfirState.${write}(`);
    const ownerAt = html.lastIndexOf(`function ${owner}(`, at);
    expect(ownerAt, `no ${owner}() before the write`).toBeGreaterThan(-1);
    const nextFn = html.indexOf("\n    function ", ownerAt + 1);
    expect(at, `the write escaped ${owner}()`).toBeLessThan(nextFn);
  });

  it.each(SNAPSHOT_CELLS)("leaves no top-level $read binding in the inline script", async ({ read }) => {
    const html = await readFile(DASHBOARD, "utf8");
    expect(html).not.toMatch(new RegExp(`^\\s*(let|var|const)\\s+${read}\\b`, "m"));
  });
});

// THE RULE THIS MIGRATION TURNS ON.
//
// 16 of the 84 reader functions call their own writer — setExcludeTerms, loadTags, loadPins,
// patchFindingWorkflow, applyDashboardView and eleven more all reach render() or
// renderSuperTimeline(). Reading a bare `let` always saw the current value. Caching the accessor
// result in a local does not, so `const s = DfirState.lastState()` at the top of one of THOSE
// functions is a behaviour change on exactly the paths where a refetch happens mid-function.
//
// THE GATE IS NOT "NEVER CACHE", and the first draft of it was, which was wrong. jumpToEvent binds
// `const ft = DfirState.lastFt() || []`, computes a page index into that array, and renders the
// same array — a consistent snapshot across its body is the POINT, and re-reading the accessor
// between the index and the render would be the bug. It is safe because nothing it calls reaches
// render(), which was checked rather than assumed.
//
// So the rule is the intersection: do not cache a snapshot in a function that can rewrite it. That
// is computed from the source below rather than from a list of names, because a list of sixteen
// function names is exactly the kind of thing that is right on the day it is written.
describe("no reader caches a snapshot it can invalidate", () => {
  const WRITER_OF: Record<string, string> = {
    lastState: "render",
    lastFt: "render",
    lastSuperData: "renderSuperTimeline",
  };

  /** Top-level functions of the inline script, by the 4-space indentation it is written at. */
  const topLevelFunctions = (html: string): Array<{ name: string; body: string }> => {
    const out: Array<{ name: string; body: string }> = [];
    const re = /\n {4}function (\w+)\s*\([^)]*\)\s*\{/g;
    for (const m of html.matchAll(re)) {
      const from = m.index + m[0].length;
      const end = html.indexOf("\n    }", from);
      out.push({ name: m[1], body: html.slice(from, end < 0 ? undefined : end) });
    }
    return out;
  };

  it("finds the inline script's functions, so the check below is not vacuous", async () => {
    expect(topLevelFunctions(await readFile(DASHBOARD, "utf8")).length).toBeGreaterThan(700);
  });

  it("never binds a snapshot local in a function that calls that cell's writer", async () => {
    const html = await readFile(DASHBOARD, "utf8");
    const offenders: string[] = [];
    for (const fn of topLevelFunctions(html)) {
      for (const [cell, writer] of Object.entries(WRITER_OF)) {
        const binds = new RegExp(`(?:const|let|var)\\s+\\w+\\s*=\\s*DfirState\\.${cell}\\(\\)`).test(fn.body);
        const calls = new RegExp(`(?:^|[^.\\w])${writer}\\(`).test(fn.body);
        if (binds && calls) offenders.push(`${fn.name} caches ${cell} and calls ${writer}()`);
      }
    }
    expect(
      offenders,
      "a cached snapshot goes stale the moment its writer runs. Call the accessor at each use in " +
        "these functions, or stop them re-fetching mid-body.",
    ).toEqual([]);
  });

  // Guards the guard: if the accessors were renamed, both regexes above would match nothing and
  // the check would pass vacuously. There must be reads to police in the first place.
  it("is policing a real population of reads", () => {
    const reads = [...dashboardClientSource().matchAll(/DfirState\.(?:lastState|lastFt|lastSuperData)\(\)/g)];
    expect(reads.length).toBeGreaterThan(100);
  });
});
