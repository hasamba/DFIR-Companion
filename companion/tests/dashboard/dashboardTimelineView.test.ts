import { readFile } from "node:fs/promises";
import { runInContext } from "node:vm";
import { describe, expect, it } from "vitest";
import { STATIC_ASSETS } from "../../src/http/staticAssets.js";
import type { TimelineViewApi } from "./dashboardApi.js";
import { dashboardScripts, ownerEscapes, topLevelBindings } from "../helpers/dashboardAst.js";
import { globalsAddedBy, loadDashboardModule } from "../helpers/dashboardModule.js";

// public/js/dashboard-timeline-view.js — the last tier-2 owner (#415).
//
// THESE TESTS EXIST IN THIS SHAPE BECAUSE OF WHAT THE PREVIOUS ONES MISSED. Every audit of this
// tier landed on the same gap: the suites tested an owner's arithmetic and never the renderer
// interaction, so two analyst-visible regressions sat behind a green suite. The refresh handlers
// here are injected, which makes "which panels did this action repaint, and how many times" an
// assertion rather than something only a browser could tell you — so that is what most of this
// file checks.

const MODULE = new URL("../../../public/js/dashboard-timeline-view.js", import.meta.url);
const DASHBOARD = new URL("../../../public/dashboard.html", import.meta.url);
const PANELS = [
  "timeline",
  "all",
  "superTimeline",
  "falsePositives",
  "derivedViews",
  "excludeChips",
  "searchBox",
  "searchInput",
  "timeInputs",
  "severityBoxes",
  "starButton",
  // The IOC lens has its OWN painter. Routing it to `all` (an earlier draft did) refetched the
  // collection plan, rebuilt every panel and reset the timeline to page one for a change that only
  // affects the IOC list.
  "iocs",
] as const;

/** Load the module with a counting spy registered for every painter. */
function load() {
  const api = loadDashboardModule<TimelineViewApi>("dashboard-timeline-view.js", ["dashboard-state.js"]);
  const painted: Record<string, number> = {};
  const handlers: Record<string, () => void> = {};
  // EVERY spy snapshots the state it can see. Review found that only filterToEventIds checked this,
  // so moving refresh() above the write in any other action left its test green — a painter that
  // runs before the commit repaints the OLD value, which is the whole class of bug this owner
  // exists to prevent.
  const seenDuring: Record<string, unknown[]> = {};
  for (const p of PANELS) {
    painted[p] = 0;
    seenDuring[p] = [];
    handlers[p] = () => {
      painted[p] += 1;
      seenDuring[p].push({
        search: api.DfirTimelineView.search(),
        from: api.DfirTimelineView.from(),
        starred: api.DfirTimelineView.starredOnly(),
        exclude: [...api.DfirTimelineView.excludeTerms()],
        ids: api.DfirTimelineView.eventIdCount(),
        corrobIocs: api.DfirTimelineView.corrobIocs(),
      });
    };
  }
  api.DfirTimelineView.wire(handlers);
  const refreshed = () =>
    Object.entries(painted)
      .filter(([, n]) => n > 0)
      .map(([k]) => k)
      .sort();
  return { view: api.DfirTimelineView, painted, refreshed, seenDuring };
}

describe("reads round-trip what the actions commit", () => {
  it("starts with no filter of any kind", () => {
    const { view } = load();
    expect(view.search()).toBe("");
    expect(view.excludeTerms()).toEqual([]);
    expect(view.from()).toBeNull();
    expect(view.to()).toBeNull();
    expect(view.starredOnly()).toBe(false);
    expect(view.eventIdFilterActive()).toBe(false);
  });

  it("normalises the search term the way the input handler used to", () => {
    const { view } = load();
    view.setSearch("  MiMiKatz  ");
    expect(view.search()).toBe("mimikatz");
  });

  it("hands back a frozen exclude list", () => {
    const { view } = load();
    view.setExcludeTerms(["noisy"]);
    expect(Object.isFrozen(view.excludeTerms())).toBe(true);
  });

  it("exposes id membership without letting the Set out", () => {
    const { view } = load();
    view.filterToEventIds(["e1", "e2"], "anomaly bucket");
    expect(view.eventIdFilterActive()).toBe(true);
    expect(view.eventIdCount()).toBe(2);
    expect(view.hasEventId("e1")).toBe(true);
    expect(view.hasEventId(1)).toBe(false);
    expect(view.eventIdLabel()).toBe("anomaly bucket");
    expect(Object.values(view)).not.toContainEqual(expect.any(Set));
  });
});

// ── THE REFRESH SETS ─────────────────────────────────────────────────────────────────────────────
//
// One commit, one redraw. The set differs per action — that is the whole reason the handlers are
// declared per action rather than one fixed callback — so each is pinned by name.
describe("each action refreshes exactly what it declares, once", () => {
  it("setSearch repaints the page, super-timeline and False Positives ONCE each", () => {
    const { view, painted, refreshed } = load();
    view.setSearch("psexec");
    expect(refreshed()).toEqual(["all", "falsePositives", "searchBox", "superTimeline"]);
    // THE COLLAPSE. This used to render() at its own site and again through renderFalsePositives()'s
    // tail: two full renders, two /collection-plan fetches and four section sweeps per keystroke.
    expect(painted.all).toBe(1);
  });

  it("setExcludeTerms repaints the chips, page, super-timeline and False Positives ONCE each", () => {
    const { view, painted, refreshed } = load();
    view.setExcludeTerms(["noise"]);
    expect(refreshed()).toEqual(["all", "excludeChips", "falsePositives", "superTimeline"]);
    expect(painted.all).toBe(1);
  });

  // The time window reaches further than the other filters: Kill Chain and Attack Phases are derived
  // from the same filtered timeline. It does NOT do a full render.
  it("setTimeWindow reaches the derived views but not the whole page", () => {
    const { view, painted, refreshed } = load();
    view.setTimeWindow("2026-05-01T00:00:00Z", null);
    expect(refreshed()).toEqual(["derivedViews", "superTimeline", "timeInputs", "timeline"]);
    expect(painted.all).toBe(0);
  });

  it("showOnlyStarred stays timeline-local", () => {
    const { view, refreshed } = load();
    view.showOnlyStarred(true);
    expect(refreshed()).toEqual(["starButton", "timeline"]);
  });

  it("clearEventIds repaints the timeline only", () => {
    const { view } = load();
    view.filterToEventIds(["e1"], "");
    const after = load();
    after.view.clearEventIds();
    expect(after.refreshed()).toEqual(["timeline"]);
  });

  // THREE LENSES, THREE COSTS — which is why setCorroboration branches rather than being one
  // setter. Collapsing the IOC lens into the full-page painter (an earlier draft did) refetched the
  // collection plan and reset the timeline to page one for a change that only affects the IOC list.
  it.each([
    ["timeline", ["timeline"]],
    ["iocs", ["iocs"]],
    ["findings", ["all"]],
  ] as const)("routes the %s lens to exactly its own panel", (which, expected) => {
    const { view, refreshed } = load();
    view.setCorroboration(which, 2);
    expect(refreshed()).toEqual([...expected]);
  });

  // "Off" is 0 in the <select> and in localStorage. Normalising it to 1 (an earlier draft did) made
  // `sel.value = String(get())` select an option that does not exist, so all three lenses rendered
  // blank on load.
  it("keeps 0 as off, matching the control's own values", () => {
    const { view } = load();
    expect(view.corrobTimeline()).toBe(0);
    view.setCorroboration("timeline", 2);
    expect(view.corrobTimeline()).toBe(2);
    view.setCorroboration("timeline", 0);
    expect(view.corrobTimeline()).toBe(0);
    view.hydrate({ corroboration: { iocs: 0 } });
    expect(view.corrobIocs()).toBe(0);
  });

  it("ignores an unknown lens rather than committing one", () => {
    const { view, refreshed } = load();
    expect(view.setCorroboration("nonsense", 3)).toBe(0);
    expect(refreshed()).toEqual([]);
  });
});

// EVERY action commits BEFORE it paints, not just the one that had a test for it.
describe("no painter ever runs before the state it is painting", () => {
  it.each([
    ["setSearch", (v: TimelineViewApi["DfirTimelineView"]) => v.setSearch("psexec"), "search", "psexec"],
    [
      "setTimeWindow",
      (v: TimelineViewApi["DfirTimelineView"]) => v.setTimeWindow("2026-05-01T00:00:00Z", null),
      "from",
      "2026-05-01T00:00:00Z",
    ],
    ["showOnlyStarred", (v: TimelineViewApi["DfirTimelineView"]) => v.showOnlyStarred(true), "starred", true],
    [
      "setCorroboration",
      (v: TimelineViewApi["DfirTimelineView"]) => v.setCorroboration("iocs", 2),
      "corrobIocs",
      2,
    ],
  ] as const)("%s", (_label, act, field, expected) => {
    const { view, seenDuring } = load();
    act(view);
    const observations = Object.values(seenDuring).flat() as Array<Record<string, unknown>>;
    expect(observations.length, "the action painted nothing at all").toBeGreaterThan(0);
    for (const seen of observations) {
      expect(seen[field], `a painter ran before ${_label} committed`).toEqual(expected);
    }
  });
});

// ── THE ORDERING BUG THE DESIGN EXISTS TO FIX ────────────────────────────────────────────────────
describe("revealing a group of events paints once, with the filter already applied", () => {
  it("has the id filter committed BEFORE the first repaint", () => {
    const api = loadDashboardModule<TimelineViewApi>("dashboard-timeline-view.js", ["dashboard-state.js"]);
    const view = api.DfirTimelineView;
    const seen: Array<{ active: boolean; count: number }> = [];
    // `all`, not `timeline`: revealing a group clears filters that Findings, IOCs, False Positives
    // and the super-timeline also read, so it refreshes the page — and render() paints the event
    // list. An earlier draft refreshed the timeline alone, leaving every other panel showing
    // filters the controls now said were cleared.
    view.wire({
      all: () => seen.push({ active: view.eventIdFilterActive(), count: view.eventIdCount() }),
    });
    view.filterToEventIds(["e1", "e2", "e3"], "bucket");
    // ONE paint, and it already sees the filter. filterTimelineToEventIds used to render TWICE
    // through its reset — both showing the filter it had just cleared — and only apply the ids on a
    // third paint.
    expect(seen).toEqual([{ active: true, count: 3 }]);
  });

  it("clears the other view filters as part of the same action", () => {
    const { view } = load();
    view.setSearch("noise");
    view.setTimeWindow("2026-05-01T00:00:00Z", null);
    view.showOnlyStarred(true);
    view.filterToEventIds(["e1"], "");
    expect(view.search()).toBe("");
    expect(view.from()).toBeNull();
    expect(view.starredOnly()).toBe(false);
    expect(view.hasEventId("e1")).toBe(true);
  });

  it("does nothing at all when given no ids", () => {
    const { view, refreshed } = load();
    expect(view.filterToEventIds([], "x")).toBe(0);
    expect(refreshed()).toEqual([]);
  });
});

// ── THE PRODUCTION NESTING ───────────────────────────────────────────────────────────────────────
//
// THE TEST THAT SHOULD HAVE EXISTED FIRST. The spies above are independent, which is convenient and
// was, on its own, misleading: in the page `renderFalsePositives()` ends with its own
// `render(lastState())`, so wiring it directly meant `refresh("all", "falsePositives")` ran TWO
// full renders — the very double render this module claims to collapse — while a suite of
// independent spies reported one. Review caught it; this models the nesting instead.
describe("the collapse holds against the page's real handler nesting", () => {
  /** Wire painters the way dashboard.html does, including any nesting the page has. */
  function loadNested(opts: { falsePositivesRedraws: boolean }) {
    const api = loadDashboardModule<TimelineViewApi>("dashboard-timeline-view.js", ["dashboard-state.js"]);
    let renders = 0;
    const all = () => {
      renders += 1;
    };
    api.DfirTimelineView.wire({
      all,
      // The page wires the PANEL-ONLY form. Passing true here reproduces the bug: a False Positives
      // painter that redraws the page behind the action's back.
      falsePositives: () => {
        if (opts.falsePositivesRedraws) all();
      },
      timeline: () => {},
      superTimeline: () => {},
      excludeChips: () => {},
      searchBox: () => {},
      timeInputs: () => {},
      severityBoxes: () => {},
      starButton: () => {},
      derivedViews: () => {},
      iocs: () => {},
    });
    return { view: api.DfirTimelineView, renders: () => renders };
  }

  it.each(["setSearch", "setExcludeTerms"] as const)(
    "%s produces exactly one full render with the page's own wiring",
    (action) => {
      const { view, renders } = loadNested({ falsePositivesRedraws: false });
      if (action === "setSearch") view.setSearch("psexec");
      else view.setExcludeTerms(["noise"]);
      expect(renders()).toBe(1);
    },
  );

  // The bug, reproduced: this is what the page did before the panel-only painter existed.
  it("would render twice if the False Positives painter redrew the page", () => {
    const { view, renders } = loadNested({ falsePositivesRedraws: true });
    view.setSearch("psexec");
    expect(renders()).toBe(2);
  });

  // AND THE PAGE MUST ACTUALLY WIRE THE PANEL-ONLY FORM.
  //
  // The tests above prove the MODULE collapses correctly given a non-redrawing False Positives
  // painter. They cannot prove dashboard.html supplies one — they register their own handlers — so
  // reverting the page to `renderFalsePositives(fpMarkers)` left them green. That is finding 2 over
  // again at one remove, and this is the assertion that closes it.
  it("wires False Positives to the panel-only form, not the redrawing one", async () => {
    const html = await readFile(DASHBOARD, "utf8");
    const wired = html.match(/falsePositives:\s*\(\)\s*=>\s*renderFalsePositives\(([^)]*)\)/);
    expect(wired, "no falsePositives painter registered").not.toBeNull();
    expect(
      wired![1],
      "the painter must suppress renderFalsePositives' own render(), or every search and exclude " +
        "action runs TWO full renders again",
    ).toMatch(/,\s*false\s*$/);
    // ...and the renderer must still HAVE that parameter for the suppression to mean anything.
    // It moved to js/dashboard-exposure-fp.js (#415); the REGISTRATION above stays in the page, so
    // this pair now spans two files and each half is asserted against the right one.
    const fpModule = await readFile(
      new URL("../../../public/js/dashboard-exposure-fp.js", import.meta.url),
      "utf8",
    );
    expect(fpModule.length, "exposure-fp module is empty — has it moved?").toBeGreaterThan(500);
    expect(fpModule).toMatch(/function renderFalsePositives\(markers, redraw\)/);
    // Whitespace-tolerant: prettier wraps this across two lines in the module, and the exact-spacing
    // form only held while it lived in dashboard.html, the one file prettier does not format.
    expect(fpModule).toMatch(/if \(redraw !== false && DfirState\.lastState\(\)\)\s*render\(/);
  });

  it("clearFilters also settles on one full render", () => {
    const { view, renders } = loadNested({ falsePositivesRedraws: false });
    view.clearFilters();
    expect(renders()).toBe(1);
  });
});

// ── resetForCase IS NOT clearFilters ─────────────────────────────────────────────────────────────
//
// Connecting to a case deliberately keeps the id filter, the severity boxes and the analyst's
// exclude terms. Routing both through one helper would wipe persisted exclude terms on every
// connect — the asymmetry the census found, preserved on purpose.
describe("a case connect is not a filter clear", () => {
  it("keeps the analyst's standing preferences", () => {
    const { view } = load();
    // Order matters and is itself behaviour: filterToEventIds clears the exclude terms, exactly as
    // filterTimelineToEventIds does today via resetTimelineViewFilters. So the terms are set AFTER,
    // which is the state a real analyst is in when they connect to another case.
    view.filterToEventIds(["e1"], "bucket");
    view.setExcludeTerms(["keep-me"]);
    view.setSearch("noise");
    view.resetForCase();
    expect(view.search()).toBe("");
    // Exclude terms survive: they are the analyst's standing preference, not this case's.
    expect(view.excludeTerms()).toEqual(["keep-me"]);
  });

  // THE ID FILTER IS DIFFERENT, and an earlier draft of this file asserted the opposite — it
  // documented proceedConnect's omission as intended and pinned it. An id filter is DERIVED FROM A
  // CASE (an anomaly bucket, a session's rows), so carrying it across a case switch either blanks
  // the new timeline or, on an id collision, shows unrelated evidence under the old case's label.
  it("drops the event-group filter, which belongs to the case being left", () => {
    const { view } = load();
    view.filterToEventIds(["e1", "e2"], "anomaly bucket");
    view.resetForCase();
    expect(view.eventIdFilterActive()).toBe(false);
    expect(view.eventIdCount()).toBe(0);
    expect(view.eventIdLabel()).toBe("");
  });

  it("clearFilters DOES drop both, and repaints everything they touch", () => {
    const { view, refreshed } = load();
    view.setExcludeTerms(["drop-me"]);
    view.filterToEventIds(["e1"], "bucket");
    const after = load();
    after.view.setExcludeTerms(["drop-me"]);
    after.view.filterToEventIds(["e1"], "bucket");
    after.view.clearFilters();
    expect(after.view.excludeTerms()).toEqual([]);
    expect(after.view.eventIdFilterActive()).toBe(false);
    expect(after.refreshed()).toContain("all");
    void refreshed;
  });

  it("refreshes NOTHING on a case connect, because proceedConnect paints in its own order", () => {
    const { view, refreshed } = load();
    view.resetForCase();
    expect(refreshed()).toEqual([]);
  });
});

// Restoring persisted state at bootstrap is not a user action: it runs while the script is parsing,
// with no panel on the page to repaint.
describe("hydrate commits without painting", () => {
  it("restores exclude terms and the lenses with no refresh", () => {
    const { view, refreshed } = load();
    view.hydrate({ excludeTerms: ["saved"], corroboration: { timeline: 2, iocs: 3, findings: 2 } });
    expect(view.excludeTerms()).toEqual(["saved"]);
    expect(view.corrobTimeline()).toBe(2);
    expect(view.corrobIocs()).toBe(3);
    expect(refreshed()).toEqual([]);
  });

  it("tolerates a missing or partial payload", () => {
    const { view } = load();
    view.hydrate(undefined);
    view.hydrate({ corroboration: { timeline: 3 } });
    expect(view.corrobTimeline()).toBe(3);
    expect(view.excludeTerms()).toEqual([]);
  });
});

describe("nothing but the namespace escapes", () => {
  it("adds only DfirTimelineView to the global object", () => {
    expect(globalsAddedBy("dashboard-timeline-view.js", ["dashboard-state.js"])).toEqual([
      "DfirTimelineView",
    ]);
  });

  it("puts the cells out of reach of a second script on the page", () => {
    const api = loadDashboardModule<TimelineViewApi>("dashboard-timeline-view.js", ["dashboard-state.js"]);
    api.DfirTimelineView.setSearch("legit");
    expect(() => runInContext("search.set('smuggled')", api as object)).toThrow(/search is not defined/);
    expect(api.DfirTimelineView.search()).toBe("legit");
  });

  it("publishes no change subscription", () => {
    const api = loadDashboardModule<TimelineViewApi>("dashboard-timeline-view.js", ["dashboard-state.js"]);
    expect(Object.keys(api.DfirTimelineView).filter((k) => /^on[A-Z]/.test(k))).toEqual([]);
  });
});

describe("the old bindings are gone", () => {
  const scripts = dashboardScripts();
  const MOVED = [
    "searchTerm",
    "excludeTerms",
    "filterFrom",
    "filterTo",
    "showStarredOnly",
    "evIdFilter",
    "evIdFilterLabel",
    "corrobTimeline",
    "corrobIocs",
    "corrobFindings",
  ];

  it.each(MOVED)("%s has no binding left in any script the page loads", (name) => {
    const offenders = scripts.flatMap((s) =>
      topLevelBindings(s)
        .filter((b) => b.name === name)
        .map((b) => `${s.name}:${b.line}`),
    );
    expect(offenders).toEqual([]);
  });

  it("is never aliased or reached dynamically", () => {
    expect(ownerEscapes(scripts, "DfirTimelineView").map((e) => `${e.script}:${e.line} ${e.form}`)).toEqual(
      [],
    );
  });
});

describe("wiring", () => {
  it("is loaded by dashboard.html, ahead of the inline script, and served by the whitelist", async () => {
    const html = await readFile(DASHBOARD, "utf8");
    expect(html).toContain('<script src="/js/dashboard-timeline-view.js"></script>');
    const tag = html.indexOf('src="/js/dashboard-timeline-view.js"');
    expect(html.indexOf('src="/js/dashboard-state.js"')).toBeLessThan(tag);
    const blocks = [...html.matchAll(/<script(?![^>]*\ssrc=)[^>]*>([\s\S]*?)<\/script>/g)];
    // The main block is the LONGEST one, not "the one containing render()". Anchoring on render
    // tied this assertion to a function #415 is in the business of moving out: the day it goes,
    // five suites fail with "could not locate the inline dashboard script" instead of with
    // whatever actually broke. Length stays true however much comes out of the block.
    const main = blocks.reduce((a, b) => (b[1].length > a[1].length ? b : a));
    expect(tag).toBeLessThan(main.index);
    expect(STATIC_ASSETS["/js/dashboard-timeline-view.js"]).toBe("application/javascript; charset=utf-8");
  });

  // The module is inert without its painters, so a page that forgets to register them would commit
  // filters that never appear. This pins that the registration exists and covers every panel.
  it("registers a painter for every panel the module knows about", async () => {
    const html = await readFile(DASHBOARD, "utf8");
    const src = await readFile(MODULE, "utf8");
    const declared = [...src.matchAll(/^\s{4}(\w+): noop,/gm)].map((m) => m[1]);
    expect(declared.length, "expected the module's painter list").toBeGreaterThan(5);
    const wireBlock = html.slice(html.indexOf("DfirTimelineView.wire({"));
    for (const panel of declared) {
      expect(wireBlock.slice(0, 2000), `dashboard.html registers no painter for "${panel}"`).toContain(
        `${panel}:`,
      );
    }
  });

  // A RUNTIME DEFECT THIS BRANCH FIXES, gated so it cannot come back.
  //
  // setSearch() trims and lower-cases the term. An earlier painter wrote that committed value back
  // into the live <input>, so 300ms after typing "foo " the box read "foo" and the next keystrokes
  // appended to that: "foo " then "bar" produced "foobar", with the caret moved. The original
  // applySearch() read the input and never wrote it.
  it("never rewrites the analyst's search box while they are typing", async () => {
    const html = await readFile(DASHBOARD, "utf8");
    const painter = html.slice(html.indexOf("searchBox: () =>"), html.indexOf("searchInput: () =>"));
    expect(painter, "could not locate the searchBox painter").toContain("clearSearch");
    expect(
      painter,
      "the per-search painter must not assign to #globalSearch — it corrupts what is being typed",
    ).not.toMatch(/globalSearch[\s\S]*?\.value\s*=/);
  });

  it("still empties the box when the analyst clears filters", () => {
    const { view, refreshed } = load();
    view.setSearch("noise");
    const after = load();
    after.view.clearFilters();
    expect(after.refreshed()).toContain("searchInput");
    void refreshed;
    void view;
  });

  it("stays a classic script", async () => {
    const src = await readFile(MODULE, "utf8");
    expect(src).not.toMatch(/^\s*(?:export|import)\s/m);
  });
});
