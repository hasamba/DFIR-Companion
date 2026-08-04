import { readFile } from "node:fs/promises";
import { runInContext } from "node:vm";
import { describe, expect, it } from "vitest";
import { STATIC_ASSETS } from "../../src/http/staticAssets.js";
import type { SelectionApi } from "./dashboardApi.js";
import { dashboardScripts, ownerCalls, topLevelBindings } from "../helpers/dashboardAst.js";
import { globalsAddedBy, loadDashboardModule } from "../helpers/dashboardModule.js";

// public/js/dashboard-selection.js — tier 2's second and third owners (#415).
//
// The scope window before it was three whole-value writes and zero in-place mutations, so putting
// it behind an accessor was a rename. These four sets are the opposite: 33 in-place mutations, zero
// replacements, and four of those mutations inside a loop. Replace-on-write is therefore a real
// change of mechanism here, and the tests below are aimed at the two things that change can break —
// the SEMANTICS of the bulk gestures, and the COST of committing one id at a time.

const MODULE = new URL("../../../public/js/dashboard-selection.js", import.meta.url);
const DASHBOARD = new URL("../../../public/dashboard.html", import.meta.url);

const load = () => loadDashboardModule<SelectionApi>("dashboard-selection.js", ["dashboard-state.js"]);

describe("a selection set", () => {
  it("starts empty", () => {
    const { DfirSelection } = load();
    expect(DfirSelection.events.count()).toBe(0);
    expect(DfirSelection.events.ids()).toEqual([]);
    expect(DfirSelection.events.has("e1")).toBe(false);
  });

  it("toggles one id on and off with an explicit state", () => {
    const { DfirSelection } = load();
    DfirSelection.events.toggle("e1", true);
    expect(DfirSelection.events.has("e1")).toBe(true);
    DfirSelection.events.toggle("e1", false);
    expect(DfirSelection.events.has("e1")).toBe(false);
  });

  // The swimlane's click-to-select is a genuine flip, unlike the checkboxes which know their state.
  it("flips when no state is given, like classList.toggle", () => {
    const { DfirSelection } = load();
    DfirSelection.events.toggle("e1");
    expect(DfirSelection.events.has("e1")).toBe(true);
    DfirSelection.events.toggle("e1");
    expect(DfirSelection.events.has("e1")).toBe(false);
  });

  it("keeps the three selections independent", () => {
    const { DfirSelection } = load();
    DfirSelection.events.toggle("x", true);
    expect(DfirSelection.iocs.has("x")).toBe(false);
    expect(DfirSelection.findings.has("x")).toBe(false);
  });
});

// THE SEMANTIC THAT REPLACE-ON-WRITE COULD SILENTLY LOSE.
//
// Select-all ticks the RENDERED rows, and the timeline paginates, so rows selected on another page
// have to survive it. The per-row `.add()` loop this replaced did that for free. `replace()` would
// not — which is why select-all uses addAll/removeAll, and why this is a test rather than a comment.
describe("bulk gestures union and subtract rather than replace", () => {
  it("addAll keeps ids that were already selected off-screen", () => {
    const { DfirSelection } = load();
    DfirSelection.events.toggle("offpage", true);
    DfirSelection.events.addAll(["a", "b"]);
    expect(DfirSelection.events.ids().slice().sort()).toEqual(["a", "b", "offpage"]);
  });

  it("removeAll subtracts only the ids it is given", () => {
    const { DfirSelection } = load();
    DfirSelection.events.addAll(["offpage", "a", "b"]);
    DfirSelection.events.removeAll(["a", "b"]);
    expect(DfirSelection.events.ids()).toEqual(["offpage"]);
  });

  it("replace and clear DO drop everything, which is why select-all does not use them", () => {
    const { DfirSelection } = load();
    DfirSelection.events.addAll(["a", "b"]);
    DfirSelection.events.replace(["c"]);
    expect(DfirSelection.events.ids()).toEqual(["c"]);
    DfirSelection.events.clear();
    expect(DfirSelection.events.count()).toBe(0);
  });

  it("tolerates an empty or absent batch", () => {
    const { DfirSelection } = load();
    DfirSelection.events.addAll([]);
    DfirSelection.events.replace(undefined);
    expect(DfirSelection.events.count()).toBe(0);
  });
});

// NO LIVE SET LEAVES THE CLOSURE.
//
// Note what is NOT done here: the internal Set is not frozen, because freezing one would be
// theatre — Object.freeze touches own properties and a Set's contents are internal slots, so a
// "frozen" Set still accepts .add(). The container simply never escapes, and ids() hands back a
// frozen array copy.
describe("the container never escapes", () => {
  it("hands back a frozen array, not the Set", () => {
    const { DfirSelection } = load();
    DfirSelection.events.addAll(["a"]);
    const ids = DfirSelection.events.ids();
    expect(Array.isArray(ids)).toBe(true);
    expect(Object.isFrozen(ids)).toBe(true);
  });

  it("is unaffected by anything done to a previously returned array", () => {
    const { DfirSelection } = load();
    DfirSelection.events.addAll(["a", "b"]);
    const ids = DfirSelection.events.ids();
    try {
      (ids as string[]).push("smuggled");
    } catch {
      // frozen arrays throw in strict mode and no-op otherwise; either is a rejected write
    }
    expect(DfirSelection.events.count()).toBe(2);
    expect(DfirSelection.events.has("smuggled")).toBe(false);
  });

  it("returns a fresh array each time, so callers cannot alias the state", () => {
    const { DfirSelection } = load();
    DfirSelection.events.addAll(["a"]);
    expect(DfirSelection.events.ids()).not.toBe(DfirSelection.events.ids());
  });
});

describe("DfirStarred is a separate owner", () => {
  it("does not share a set with the event selection", () => {
    const { DfirSelection, DfirStarred } = load();
    DfirStarred.toggle("e1", true);
    expect(DfirSelection.events.has("e1")).toBe(false);
    DfirSelection.events.toggle("e2", true);
    expect(DfirStarred.has("e2")).toBe(false);
  });

  // deriveStarred() rebuilds from the server's tags, so it replaces wholesale.
  it("replaces wholesale when re-derived from tags", () => {
    const { DfirStarred } = load();
    DfirStarred.replace(["a", "b"]);
    DfirStarred.replace(["c"]);
    expect(DfirStarred.ids()).toEqual(["c"]);
  });

  // toggleStar flips optimistically and reverts on failure. The revert re-reads the CURRENT set
  // rather than restoring a snapshot, so a concurrent change is not clobbered.
  it("round-trips an optimistic flip and its revert", () => {
    const { DfirStarred } = load();
    DfirStarred.replace(["a"]);
    const wasStarred = DfirStarred.has("a");
    DfirStarred.toggle("a", !wasStarred);
    expect(DfirStarred.has("a")).toBe(false);
    DfirStarred.toggle("a", wasStarred);
    expect(DfirStarred.has("a")).toBe(true);
  });

  it("exposes no way to write it that the selections do not need", () => {
    const { DfirStarred } = load();
    expect(Object.keys(DfirStarred).sort()).toEqual(["count", "has", "ids", "replace", "toggle"]);
  });
});

// ── THE GATE ─────────────────────────────────────────────────────────────────────────────────────
describe("no commit happens inside a loop", () => {
  const scripts = dashboardScripts();
  const COMMITS = ["toggle", "addAll", "removeAll", "replace", "clear"] as const;

  // THE INVARIANT THIS MIGRATION TURNS ON. Replace-on-write is O(n) per commit, so committing per
  // iteration is O(n^2) for the gesture — and `tlPageSize` is analyst-selectable with 0 meaning
  // "every row", so select-all is not bounded by a page. The four sites that used to do this are
  // why addAll/removeAll exist; without this test, the next one reads as perfectly ordinary code.
  // THE ONE DOCUMENTED EXCEPTION, pinned by name rather than by narrowing the gate to miss it.
  //
  // bulkStarIds awaits ONE HTTP REQUEST PER ID — the tags store is read-modify-write on tags.json,
  // which is why the requests are serialised in the first place. A Set copy next to a network
  // round-trip is not the cost, and batching would be actively wrong: each id is applied as its
  // request succeeds, so a failure halfway leaves the successful ones starred, which is what the
  // analyst sees and what loadTags() then reconciles.
  const ALLOWED_IN_LOOP = ["bulkStarIds"];

  it.each(["DfirSelection", "DfirStarred"])("%s is never committed to from within a loop", (ns) => {
    const offenders = ownerCalls(scripts, ns, COMMITS)
      .filter((c) => c.inLoop && !ALLOWED_IN_LOOP.includes(c.fn))
      .map((c) => `${c.script}:${c.line} ${c.fn}() -> ${c.path}()`);
    expect(
      offenders,
      "collect the ids first and commit once — addAll/removeAll/replace exist for this. See " +
        "js/dashboard-selection.js. If the loop awaits a request per id, add it to ALLOWED_IN_LOOP " +
        "with the reason.",
    ).toEqual([]);
  });

  // The allowlist must not outlive what it excuses: an entry that no longer matches anything is a
  // stale exemption that would silently cover a future commit-in-loop in a function of that name.
  it("has no stale entry in the loop allowlist", () => {
    const inLoop = new Set(
      ["DfirSelection", "DfirStarred"].flatMap((ns) =>
        ownerCalls(scripts, ns, COMMITS)
          .filter((c) => c.inLoop)
          .map((c) => c.fn),
      ),
    );
    expect([...ALLOWED_IN_LOOP].filter((f) => !inLoop.has(f))).toEqual([]);
  });

  it("actually finds the commits it is checking, so the gate is not vacuous", () => {
    const found = ownerCalls(scripts, "DfirSelection", COMMITS);
    expect(found.length).toBeGreaterThan(10);
    expect(ownerCalls(scripts, "DfirStarred", COMMITS).length).toBeGreaterThan(2);
  });
});

describe("the old bindings are gone", () => {
  const scripts = dashboardScripts();
  const MOVED = ["selectedEvents", "selectedIocs", "selectedFindings", "starredEvents"];

  it.each(MOVED)("%s has no top-level binding left in the page", (name) => {
    const offenders = scripts
      .filter((s) => s.name.startsWith("dashboard.html#inline"))
      .flatMap((s) =>
        topLevelBindings(s)
          .filter((b) => b.name === name)
          .map((b) => `${s.name}:${b.line}`),
      );
    expect(offenders).toEqual([]);
  });
});

describe("nothing but the namespaces escapes", () => {
  it("adds only DfirSelection and DfirStarred to the global object", () => {
    expect(globalsAddedBy("dashboard-selection.js", ["dashboard-state.js"]).sort()).toEqual([
      "DfirSelection",
      "DfirStarred",
    ]);
  });

  it("puts the sets out of reach of a second script on the page", () => {
    const api = load();
    api.DfirSelection.events.toggle("legit", true);
    expect(() => runInContext("idSet()", api as object)).toThrow(/idSet is not defined/);
    expect(api.DfirSelection.events.has("legit")).toBe(true);
  });

  it("publishes no change subscription", () => {
    const api = load();
    expect(Object.keys(api.DfirSelection).sort()).toEqual(["events", "findings", "iocs"]);
    for (const set of [api.DfirSelection.events, api.DfirSelection.iocs, api.DfirSelection.findings]) {
      expect(Object.keys(set).sort()).toEqual([
        "addAll",
        "clear",
        "count",
        "has",
        "ids",
        "removeAll",
        "replace",
        "toggle",
      ]);
    }
  });
});

describe("wiring", () => {
  it("is loaded by dashboard.html, ahead of the inline script, and served by the whitelist", async () => {
    const html = await readFile(DASHBOARD, "utf8");
    expect(html).toContain('<script src="/js/dashboard-selection.js"></script>');
    const tag = html.indexOf('src="/js/dashboard-selection.js"');
    expect(html.indexOf('src="/js/dashboard-state.js"')).toBeLessThan(tag);
    const blocks = [...html.matchAll(/<script(?![^>]*\ssrc=)[^>]*>([\s\S]*?)<\/script>/g)];
    const main = blocks.find((m) => /\n\s*function render\s*\(/.test(m[1]));
    expect(main, "could not locate the inline dashboard script").toBeDefined();
    expect(tag).toBeLessThan(main!.index);
    expect(STATIC_ASSETS["/js/dashboard-selection.js"]).toBe("application/javascript; charset=utf-8");
  });

  it("stays a classic script", async () => {
    const src = await readFile(MODULE, "utf8");
    expect(src).not.toMatch(/^\s*(?:export|import)\s/m);
  });
});
