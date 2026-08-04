import { readFile } from "node:fs/promises";
import { runInContext } from "node:vm";
import { describe, expect, it } from "vitest";
import { STATIC_ASSETS } from "../../src/http/staticAssets.js";
import type { SelectionApi } from "./dashboardApi.js";
import {
  calleesInsideLoops,
  functionsOf,
  insideLoop,
  ownerCallPositions,
  dashboardScripts,
  ownerCalls,
  ownerEscapes,
  scriptFromSource,
  topLevelBindings,
} from "../helpers/dashboardAst.js";
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

/** Parsed once — the call-site pins and the loop gate both read it. */
const scriptsForPins = dashboardScripts();

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

  it("clear DOES drop everything, which is why select-all does not use it", () => {
    const { DfirSelection } = load();
    DfirSelection.events.addAll(["a", "b"]);
    DfirSelection.events.clear();
    expect(DfirSelection.events.count()).toBe(0);
  });

  // A replace() on a selection could only ever lose an off-page tick, and nothing calls one, so it
  // is not published. Removing the operation is stronger than testing that nobody uses it.
  it("publishes no replace() on a selection, only on the star cache", () => {
    const { DfirSelection, DfirStarred } = load();
    for (const set of [DfirSelection.events, DfirSelection.iocs, DfirSelection.findings]) {
      expect(set).not.toHaveProperty("replace");
    }
    expect(DfirStarred).toHaveProperty("replace");
  });

  it("tolerates an empty or absent batch", () => {
    const { DfirSelection } = load();
    DfirSelection.events.addAll([]);
    DfirSelection.events.removeAll(undefined);
    expect(DfirSelection.events.count()).toBe(0);
  });

  // PIN THE PRODUCTION CALL SITES, not just the API. The off-page semantic lives in which operation
  // the three select-all handlers call, and an API-level test alone would pass if one of them were
  // switched to a set-clearing operation.
  it("has all three select-all handlers committing through addAll and removeAll", () => {
    for (const panel of ["events", "iocs", "findings"]) {
      // `events` legitimately has TWO addAll sites — select-all and the swimlane rubber band — so
      // this pins the OPERATIONS each panel reaches for, not how many times.
      const methods = new Set(
        ownerCalls(scriptsForPins, "DfirSelection", ["addAll", "removeAll"])
          .filter((c) => c.path.startsWith(`DfirSelection.${panel}.`))
          .map((c) => c.method),
      );
      expect(
        [...methods].sort(),
        `select-all for ${panel} must union and subtract, never drop the rest`,
      ).toEqual(["addAll", "removeAll"]);
    }
  });

  it("never calls a replace() on a selection anywhere in the page", () => {
    const calls = ownerCalls(scriptsForPins, "DfirSelection", ["replace"]).map(
      (c) => `${c.script}:${c.line} ${c.path}()`,
    );
    expect(calls, "selections publish no replace(); such a call would throw at runtime").toEqual([]);
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

  // A CALLBACK LOOP IS A LOOP, asserted against the analyser directly.
  //
  // The first version of this gate recognised only `for`/`while`, so
  // `ids.forEach(id => DfirSelection.events.toggle(id))` — the exact shape of three of the four
  // sites this migration replaced — reported inLoop: false. The gate could not see the regression
  // it exists to prevent. These cases are the analyser's own contract, and they are here rather
  // than in a page assertion because the page currently contains none of them, so a page-level
  // check would pass whether the analyser worked or not.
  const probe = (body: string) => ownerCalls([scriptFromSource("probe.js", body)], "DfirSelection", COMMITS);

  it.each([
    ["a for-of loop", "for (const id of ids) DfirSelection.events.toggle(id);"],
    ["a while loop", "while (n--) DfirSelection.events.toggle('x');"],
    ["a forEach callback", "ids.forEach((id) => DfirSelection.events.toggle(id));"],
    ["a map callback", "ids.map((id) => DfirSelection.events.toggle(id));"],
    ["a sort comparator", "ids.sort((a, b) => DfirSelection.events.toggle(a));"],
    [
      "a nested callback inside a loop",
      "for (const g of gs) g.ids.forEach((id) => DfirSelection.events.toggle(id));",
    ],
  ])("counts a commit in %s as in-loop", (_label, body) => {
    const [call] = probe(body);
    expect(call, "the analyser did not see the commit at all").toBeDefined();
    expect(call.inLoop).toBe(true);
  });

  it.each([
    ["a plain statement", "DfirSelection.events.toggle('a', true);"],
    ["the receiver of a forEach", "DfirSelection.events.ids().forEach((x) => x);"],
    ["a callback that commits nothing", "ids.forEach((id) => other.toggle(id));"],
  ])("does not count %s as in-loop", (_label, body) => {
    for (const call of probe(body)) expect(call.inLoop).toBe(false);
  });

  it("sees a commit at top level, outside any function", () => {
    expect(probe("DfirSelection.events.clear();")).toHaveLength(1);
  });

  it.each([
    ["an alias", "const evs = DfirSelection.events; evs.toggle('a');"],
    ["a computed member", "DfirSelection.events['toggle']('a');"],
    ["a dynamic member", "DfirSelection.events[m]('a');"],
  ])("reports %s as an escape the loop gate cannot follow", (_label, body) => {
    expect(ownerEscapes([scriptFromSource("probe.js", body)], "DfirSelection").length).toBeGreaterThan(0);
  });

  // Reaching an owner by a name this analysis cannot follow defeats every rule above, so those
  // spellings are rejected outright rather than resolved — the same trade setterRefs makes.
  it.each(["DfirSelection", "DfirStarred"])("%s is never aliased or reached dynamically", (ns) => {
    const escapes = ownerEscapes(scripts, ns).map((e) => `${e.script}:${e.line} (${e.form}) ${e.text}`);
    expect(
      escapes,
      "an alias or a computed member puts the commit beyond the loop gate. Call the owner by name.",
    ).toEqual([]);
  });

  // THE INDIRECT HALF, and its deliberate limit.
  //
  // A commit does not stop being per-iteration because a thin wrapper sits between it and the loop:
  // `for (const id of ids) selectOne(id)` is the shape this catches.
  //
  // ONE HOP, NOT FULL REACHABILITY, and that is a judgement rather than an oversight. Run
  // transitively over this call graph it reports four things today, and not one is a per-element
  // cost: addTag()/deleteTag() reach deriveStarred() only through loadTags(), which is a fetch, so
  // each iteration is already a network round-trip (the same reason bulkStarIds is allowlisted);
  // and createNewCase() reaches proceedConnect(), a whole case connect. In a 19,000-line script
  // with names this generic, "can eventually reach" stops predicting "runs per iteration", and a
  // gate whose output is mostly allowlist teaches people to extend the allowlist. The bound is
  // stated here so the next reader knows what is NOT covered rather than assuming it is.
  it("no function called directly from inside a loop commits", () => {
    const committers = new Set(
      ["DfirSelection", "DfirStarred"]
        .flatMap((ns) => ownerCalls(scriptsForPins, ns, COMMITS))
        .map((c) => c.fn)
        .filter((f) => !f.startsWith("<")),
    );
    const offenders = [...calleesInsideLoops(scriptsForPins)]
      .filter((callee) => committers.has(callee) && !ALLOWED_IN_LOOP.includes(callee))
      .map((callee) => `${callee}() commits and is called from inside a loop`);
    expect(offenders).toEqual([]);
  });

  // THE MODULE'S OWN BULK OPERATIONS MUST NOT LOOP AROUND A COMMIT.
  //
  // `addAll` implemented as `for (const id of ids) commit(...)` is the same quadratic cost moved one
  // level down, where no call-site check sees it: the API would look right and behave exactly as
  // badly as what it replaced. Checked against the AST rather than by counting `commit(` in the
  // text, because the counting version passed this exact mutation — one call, inside a loop, is
  // still one occurrence.
  it("has no bulk operation looping around its own commit", async () => {
    const script = scriptFromSource("dashboard-selection.js", await readFile(MODULE, "utf8"));
    const BULK = ["addAll", "removeAll", "replace", "clear", "toggle"];
    const offenders: string[] = [];
    for (const fn of functionsOf(script).filter((f) => BULK.includes(f.name))) {
      for (const call of ownerCallPositions(fn.node, "commit")) {
        if (insideLoop(fn.node, call)) offenders.push(`${fn.name}() commits inside a loop`);
      }
    }
    expect(offenders).toEqual([]);
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
  const scripts = scriptsForPins;
  const MOVED = ["selectedEvents", "selectedIocs", "selectedFindings", "starredEvents"];

  // THE HELPER'S OWN CONTRACT. "Top level" is not the same as "written at the top": in a classic
  // non-strict script a `var` inside a block hoists to the script, and a bare assignment with no
  // declaration creates a global outright. Both are the binding this migration removed, wearing a
  // different hat, and both were invisible to the first version of this check.
  it.each([
    ["a plain let", "let selectedEvents = new Set();"],
    ["a const", "const selectedEvents = new Set();"],
    ["a bare let", "let selectedEvents;"],
    ["a var in a block", "if (ready) { var selectedEvents = new Set(); }"],
    ["a var in a loop body", "for (;;) { var selectedEvents = new Set(); }"],
    ["an implicit global", "function f() { selectedEvents = new Set(); }"],
  ])("counts %s as a binding", (_label, src) => {
    const found = topLevelBindings(scriptFromSource("probe.js", src)).map((b) => b.name);
    expect(found).toContain("selectedEvents");
  });

  it.each([
    ["a let inside a function", "function f() { let selectedEvents = new Set(); }"],
    ["a parameter", "function f(selectedEvents) { return selectedEvents; }"],
  ])("does not count %s", (_label, src) => {
    const found = topLevelBindings(scriptFromSource("probe.js", src)).map((b) => b.name);
    expect(found).not.toContain("selectedEvents");
  });

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
