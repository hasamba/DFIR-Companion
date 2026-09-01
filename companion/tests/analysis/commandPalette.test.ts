import { describe, it, expect } from "vitest";
import { readFile } from "node:fs/promises";
import { loadDashboardModule } from "../helpers/dashboardModule.js";
// The palette module lives outside companion/, next to graph-view.js. It guards its window/document
// access, so importing its pure named exports in node works — same arrangement as graphView.test.ts.
import {
  CATEGORY_ORDER,
  fuzzyScore,
  parseQuery,
  scoreAction,
  isAvailable,
  searchActions,
  bumpRecent,
} from "../../../public/js/command-palette.js";

const LABEL = "Go to Findings";

function action(over: Record<string, unknown> = {}) {
  return { id: "a", label: LABEL, category: "Navigation", keywords: [], run: () => {}, ...over };
}

describe("fuzzyScore tiers", () => {
  it("ranks whole-string over whole-word over word-prefix over string-prefix", () => {
    expect(fuzzyScore("go to findings", LABEL)).toBe(1000);
    expect(fuzzyScore("findings", LABEL)).toBe(800);
    expect(fuzzyScore("find", LABEL)).toBe(600);
    expect(fuzzyScore("go t", LABEL)).toBe(500);
  });

  it("scores an earlier substring hit above a later one", () => {
    expect(fuzzyScore("o to", LABEL)).toBeGreaterThan(fuzzyScore("ings", LABEL));
  });

  it("matches a scattered subsequence", () => {
    expect(fuzzyScore("gtf", LABEL)).toBeGreaterThan(0);
  });

  it("never lets a scattered subsequence outrank a real substring", () => {
    // The substring floor (400-50) must stay above the subsequence ceiling (300), otherwise an
    // incidental letter-scatter can bury the action the analyst actually meant.
    const worstSubstring = fuzzyScore("s", "x".repeat(80) + "s");
    expect(worstSubstring).toBeGreaterThan(300);
    expect(fuzzyScore("gtf", LABEL)).toBeLessThanOrEqual(300);
  });

  it("returns 0 when the characters are not all present, in order", () => {
    expect(fuzzyScore("zzz", LABEL)).toBe(0);
    expect(fuzzyScore("sgnidnif", LABEL)).toBe(0); // right letters, wrong order
  });

  it("treats an empty query as a match and an empty target as a miss", () => {
    expect(fuzzyScore("", LABEL)).toBe(1);
    expect(fuzzyScore("x", "")).toBe(0);
  });
});

describe("parseQuery category filter", () => {
  it("engages on a PARTIAL category name, not only the full word", () => {
    // Regression: matching the exact word only meant ">n", ">na" and ">nav" all returned nothing,
    // so the list stayed empty for every keystroke but the last and read as broken.
    for (const q of [">n", ">na", ">nav", ">navigation"]) {
      expect(parseQuery(q)).toEqual({ category: "Navigation", term: "" });
    }
  });

  it("is case-insensitive and keeps the rest of the line as the search term", () => {
    expect(parseQuery(">Exports csv")).toEqual({ category: "Exports", term: "csv" });
    expect(parseQuery(">exp  stix bundle")).toEqual({ category: "Exports", term: "stix bundle" });
  });

  it("treats a bare '>' as no filter, so everything is still listed", () => {
    expect(parseQuery(">")).toEqual({ category: null, term: "" });
  });

  it("degrades an unrecognised prefix to a plain search rather than a wrong filter", () => {
    expect(parseQuery(">zzz")).toEqual({ category: null, term: "zzz" });
  });

  it("leaves a query without '>' completely alone", () => {
    expect(parseQuery("  findings ")).toEqual({ category: null, term: "findings" });
  });

  it("covers every category", () => {
    for (const c of CATEGORY_ORDER) {
      expect(parseQuery(">" + c.toLowerCase()).category).toBe(c);
    }
  });
});

describe("scoreAction", () => {
  it("prefers a label hit over the identical text sitting in a keyword", () => {
    const byLabel = scoreAction("alpha beta", action({ label: "Alpha Beta" }));
    const byKeyword = scoreAction(
      "alpha beta",
      action({ label: "Something Else", keywords: ["alpha beta"] }),
    );
    expect(byLabel).toBeGreaterThan(byKeyword);
    expect(byKeyword).toBeGreaterThan(0);
  });

  it("still finds an action through a keyword its label never mentions", () => {
    expect(scoreAction("dedupe", action({ label: "Merge IOCs", keywords: ["dedupe"] }))).toBeGreaterThan(0);
  });

  it("matches everything on an empty term", () => {
    expect(scoreAction("", action())).toBe(1);
  });
});

describe("isAvailable", () => {
  it("offers an action with no predicate", () => {
    expect(isAvailable(action(), null)).toBe(true);
  });

  it("honours the predicate and passes it the case state", () => {
    const a = action({ available: (s: { findings: unknown[] } | null) => !!s && s.findings.length > 0 });
    expect(isAvailable(a, null)).toBe(false);
    expect(isAvailable(a, { findings: [] })).toBe(false);
    expect(isAvailable(a, { findings: [{ id: "f1" }] })).toBe(true);
  });

  it("hides an action whose predicate throws instead of taking the palette down", () => {
    const a = action({
      available: () => {
        throw new Error("boom");
      },
    });
    expect(isAvailable(a, null)).toBe(false);
  });
});

describe("searchActions", () => {
  const nav = action({
    id: "nav.findings",
    label: "Go to Findings",
    category: "Navigation",
    keywords: ["findings"],
  });
  const exp = action({ id: "exp.stix", label: "STIX 2.1 bundle", category: "Exports", keywords: ["export"] });
  const act = action({ id: "act.merge", label: "Merge IOCs", category: "Actions", keywords: ["dedupe"] });
  const all = [nav, exp, act];

  it("filters to one category, including from a partial prefix", () => {
    expect(searchActions(">exports", all, null, []).map((r) => r.action.id)).toEqual(["exp.stix"]);
    expect(searchActions(">e", all, null, []).map((r) => r.action.id)).toEqual(["exp.stix"]);
  });

  it("combines a category filter with a search term", () => {
    expect(searchActions(">nav findings", all, null, []).map((r) => r.action.id)).toEqual(["nav.findings"]);
    expect(searchActions(">nav stix", all, null, [])).toEqual([]);
  });

  it("drops actions that are unavailable for the current state", () => {
    const gated = [
      nav,
      action({ id: "gone", label: "Go to Nowhere", category: "Navigation", available: () => false }),
    ];
    expect(searchActions("", gated, null, []).map((r) => r.action.id)).toEqual(["nav.findings"]);
  });

  it("drops non-matching actions entirely rather than ranking them last", () => {
    expect(searchActions("zzzzznomatch", all, null, [])).toEqual([]);
  });

  it("lists everything in category order on an empty query", () => {
    expect(searchActions("", all, null, []).map((r) => r.action.category)).toEqual([
      "Navigation",
      "Actions",
      "Exports",
    ]);
  });

  it("floats recently-run actions to the top of an unfiltered list", () => {
    expect(searchActions("", all, null, ["exp.stix"]).map((r) => r.action.id)[0]).toBe("exp.stix");
    expect(searchActions("", all, null, ["act.merge", "exp.stix"]).map((r) => r.action.id)).toEqual([
      "act.merge",
      "exp.stix",
      "nav.findings",
    ]);
  });

  it("never lets recency outrank a genuine match", () => {
    // "findings" is an exact word hit on nav.findings; act.merge is merely recent and only matches
    // as a scattered subsequence. Recency is a tie-breaker, not a score bonus.
    const res = searchActions("findings", all, null, ["act.merge"]);
    expect(res[0].action.id).toBe("nav.findings");
  });

  it("survives missing inputs", () => {
    expect(searchActions("", undefined, null, undefined)).toEqual([]);
    expect(searchActions("", all, null, null).length).toBe(3);
  });
});

describe("bumpRecent", () => {
  it("moves an id to the front without duplicating it", () => {
    expect(bumpRecent(["a", "b", "c"], "c")).toEqual(["c", "a", "b"]);
    expect(bumpRecent(["a", "b"], "z")).toEqual(["z", "a", "b"]);
  });

  it("caps the list and leaves the input untouched", () => {
    const before = ["a", "b", "c", "d", "e"];
    expect(bumpRecent(before, "f")).toEqual(["f", "a", "b", "c", "d"]);
    expect(before).toEqual(["a", "b", "c", "d", "e"]);
  });

  it("copes with no history yet", () => {
    expect(bumpRecent(undefined, "a")).toEqual(["a"]);
  });
});

describe("dashboard.html palette wiring", () => {
  // The palette registry and the section order/visibility code moved to their own modules
  // (#415 tier 3); the page still carries the markup and the <script> tags these tests also assert
  // on. Reading all three keeps every assertion in this describe working from one source, which is
  // what it did when the three lived in one file.
  const html = async () =>
    (
      await Promise.all([
        readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8"),
        readFile(new URL("../../../public/js/dashboard-palette-registry.js", import.meta.url), "utf8"),
        readFile(new URL("../../../public/js/dashboard-section-order.js", import.meta.url), "utf8"),
      ])
    ).join("\n");
  // Whitespace-collapsed view of the same source. Everything that moved into a module has been
  // reformatted by prettier — one-line object literals became four, arrow bodies wrapped — and the
  // assertions below are about WHAT is wired, not how it is laid out.
  const flat = async () => (await html()).replace(/\s+/g, " ");

  it("loads the module and publishes the registry the module reads", async () => {
    const h = await html();
    expect(h).toContain('<script type="module" src="/js/command-palette.js"></script>');
    // Thunks, not snapshots — #pushSelect is populated asynchronously and toolbar buttons come and
    // go as the case loads, so a registry captured once would be wrong within seconds.
    //
    // The state thunk reads DfirState.lastState() since #415 moved the case snapshot into the
    // store. Still a thunk, so still live: what would break the palette is the arrow disappearing
    // and a value being captured here, which is what the shape below pins.
    expect((await flat()).replace(/, \}/g, " }")).toContain(
      "window.DfirPaletteConfig = { actions: buildPaletteActions, state: () => DfirState.lastState() };",
    );
  });

  it("carries the overlay markup the module binds to", async () => {
    const h = await html();
    for (const id of ["cmdpOverlay", "cmdpInput", "cmdpList", "cmdpEmpty"]) {
      expect(h).toContain(`id="${id}"`);
    }
  });

  it("derives Navigation from SECTION_DEFS rather than a hand-copied panel list", async () => {
    const h = await flat();
    expect(h).toMatch(/const nav = SECTION_DEFS\.map\(/);
    // The gate on a nav entry is "does this section exist, and has its evidence arrived" — NOT
    // "is it visible in the current layout", which is what hid the super-timeline behind the Now
    // profile. What the entries DO is pinned by the behavioural describe at the bottom of this file.
    expect(h).toMatch(
      /const el = document\.getElementById\(s\.id\); return !!el && isSectionDataOpen\(el\);/,
    );
  });

  it("drives the export selects through their own change handler", async () => {
    const h = await flat();
    expect(h).toMatch(/sel\.value = o\.value; sel\.dispatchEvent\(new Event\("change"\)\)/);
    // prettier broke both calls across lines when the registry became a module, so the select id
    // no longer sits on the same line as the call. Collapsed, the pairing is still exact.
    expect(h).toContain('paletteSelectActions( "exportSelect"');
    expect(h).toContain('paletteSelectActions( "pushSelect"');
  });

  // The clear sits on applyDashboardView(), NOT applyViewLayout(), and that placement is the whole
  // point: applyViewLayout() is skipped when the view is null, and null is exactly "Custom". Two
  // paths reach Custom — the view menu, and applySavedViewForCase() restoring a case whose saved
  // preference is Custom — and a reveal left standing across the second follows the analyst into
  // the next case. The drag handlers opt out by name because they pass null for a REORDER.
  // Asserted as source: the triggers are a menu click handler built from innerHTML and a drag
  // handler, and what the reveal set itself does is covered by the describe below.
  it("ends a palette reveal wherever a layout is applied, Custom and per-case restore included", async () => {
    const presets = (
      await readFile(new URL("../../../public/js/dashboard-view-presets.js", import.meta.url), "utf8")
    ).replace(/\s+/g, " ");
    expect(presets).toMatch(
      /function applyDashboardView\(view, opts\) \{ opts = opts \|\| \{\};.*?if \(!opts\.keepReveals && typeof clearSectionReveals === "function"\) clearSectionReveals\(\);/,
    );
    // And NOT on applyViewLayout, which Custom never reaches.
    expect(presets).not.toMatch(/function applyViewLayout\(view\) \{[^}]*clearSectionReveals\(\)/);
    // The two reorder handlers opt out, so a drag never yanks the panel being dragged.
    for (const f of ["dashboard-collapsible.js", "dashboard-section-order.js"]) {
      const src = (await readFile(new URL(`../../../public/js/${f}`, import.meta.url), "utf8")).replace(
        /\s+/g,
        " ",
      );
      expect(src, f).toMatch(
        /applyDashboardView\(null, \{ persist: true, rerender: false,.*?keepReveals: true, \}\)/,
      );
    }
  });

  // Connecting to a case is an INVESTIGATION boundary, not a layout change, and it gets its own
  // clear rather than relying on the seam above. applySavedViewForCase() returns early when no view
  // has loaded, and loadDashboardViews() ends in .catch(() => {}) — so after one failed
  // /dashboard-views request it would never reach applyDashboardView(), and a panel revealed in one
  // case would follow the analyst through every later one.
  it("drops palette reveals when a different case is connected", async () => {
    const connect = (
      await readFile(new URL("../../../public/js/dashboard-case-connect.js", import.meta.url), "utf8")
    ).replace(/\s+/g, " ");
    expect(connect).toMatch(/clearSectionReveals\(\); applySavedViewForCase\(\);/);
  });

  it("documents the shortcut in the existing cheat sheet", async () => {
    const h = await html();
    expect(h).toMatch(/Ctrl\+K \/ ⌘K<\/td><td[^>]*>Command palette/);
  });
});

// ── Navigation entries vs the active view profile ─────────────────────────────────────────────
//
// A view profile writes `false` into SECTIONS_VIS_KEY for every section it omits — the SAME store
// the Settings section list uses (see applyViewLayout in js/dashboard-view-presets.js). The palette
// used to filter its "Go to …" entries by that store, so from the default Now profile, whose list
// is two sections long, the palette offered two jumps and the analyst could not reach the
// super-timeline from it at all. The palette is the escape hatch FROM a narrow profile, so a
// section the profile hides has to stay listed.
//
// AND THE REVEAL MUST NOT WRITE THAT KEY BACK. The key cannot record intent — saveSettings()
// stamps an explicit true/false on EVERY section on any Settings save, whatever the analyst was
// changing, and applyViewLayout() stamps `false` on everything a view omits — so neither an
// explicit `false` nor an absent entry means anyone chose to hide that panel. A reveal that wrote
// to it would edit a preference nobody expressed, permanently and across every case, because one
// key covers them all and no later write undoes a data-gated entry. It is held in memory instead.
//
// The real js/dashboard-section-order.js is loaded alongside the registry rather than stubbed, so
// these run the actual reveal set and the actual applySectionsVis() that reads it.
describe("palette navigation reaches sections the active view hides", () => {
  const SECTION_DEFS = [
    { id: "sec-now", label: "Now" },
    { id: "sec-super-timeline", label: "Super-Timeline" },
    { id: "sec-gated", label: "Memory Next Steps" },
    // Gated AND defaultHidden, exactly like the real Related Cases panel.
    { id: "sec-gate-dflt", label: "Related Cases", defaultHidden: true },
    { id: "sec-absent", label: "Not In This Build" },
  ];

  type PaletteAction = {
    id: string;
    label: string;
    category: string;
    available?: () => boolean;
    run: () => void;
  };
  type RegistryApi = {
    buildPaletteActions: () => PaletteAction[];
    clearSectionReveals: () => void;
    applySectionsVis: () => void;
  };

  function fakeSection(gateOpen?: string) {
    return {
      dataset: gateOpen === undefined ? {} : { gateOpen },
      style: { display: "" },
      classList: { remove: () => {} },
      scrollIntoView: () => {},
    };
  }

  /**
   * The registry's world: the five sections above, a localStorage, and the two visibility helpers.
   *
   * loadSectionsVis/isSectionVisible are RESTATED here rather than loaded, because they are
   * declared in dashboard.html's inline script and no test can import that. They are copied from it
   * verbatim. Everything else — the reveal set, applySectionsVis() — is the real module.
   *
   * `document.querySelector` returns null so applySecOrder() takes its own early return; the
   * subject here is visibility, not order.
   */
  function sandbox(vis: Record<string, boolean>) {
    const store = new Map<string, string>([["dfir.sectionsVis", JSON.stringify(vis)]]);
    const writes: string[] = [];
    const els: Record<string, ReturnType<typeof fakeSection>> = {
      "sec-now": fakeSection(),
      "sec-super-timeline": fakeSection(),
      "sec-gated": fakeSection(""), // gate present and CLOSED
      "sec-gate-dflt": fakeSection("1"), // gate OPEN, and defaultHidden above
    };
    const globals = {
      document: {
        getElementById: (id: string) => els[id] ?? null,
        querySelector: () => null,
      },
      localStorage: {
        getItem: (k: string) => store.get(k) ?? null,
        setItem: (k: string, v: string) => {
          writes.push(k);
          store.set(k, v);
        },
      },
      SECTION_DEFS,
      SECTIONS_VIS_KEY: "dfir.sectionsVis",
      SECTIONS_ORDER_KEY: "dfir.sectionsOrder",
      loadSectionsVis: () => {
        try {
          return JSON.parse(store.get("dfir.sectionsVis") || "{}");
        } catch {
          return {};
        }
      },
      isSectionVisible: (id: string, v: Record<string, boolean>) => {
        if (v[id] === undefined) {
          const d = SECTION_DEFS.find((s) => s.id === id);
          return !(d && (d as { defaultHidden?: boolean }).defaultHidden);
        }
        return v[id] !== false;
      },
      kbdOpenHelp: () => {},
      esc: (x: string) => x,
    };
    const api = loadDashboardModule<RegistryApi>(
      "dashboard-palette-registry.js",
      ["dashboard-values.js", "dashboard-section-order.js"],
      globals,
    );
    return {
      api,
      els,
      writes,
      storedVis: () => JSON.parse(store.get("dfir.sectionsVis") || "{}"),
      jump: (id: string) => {
        const go = api.buildPaletteActions().find((a) => a.id === "nav." + id) as PaletteAction;
        go.run();
      },
    };
  }

  // The Now profile: one section on, the rest written off. The gated pair is absent, which is what
  // applyViewLayout() really leaves behind — it never writes a gated section's visibility.
  const NOW = { "sec-now": true, "sec-super-timeline": false };

  function navLabels(actions: PaletteAction[]) {
    return actions
      .filter((a) => a.category === "Navigation" && a.id.startsWith("nav.sec-"))
      .filter((a) => (a.available ? a.available() : true))
      .map((a) => a.label);
  }

  it("offers a section the profile switched off", () => {
    const { api } = sandbox(NOW);
    expect(navLabels(api.buildPaletteActions())).toContain("Go to Super-Timeline");
  });

  it("shows that section without writing the stored layout at all", () => {
    const { els, writes, storedVis, jump } = sandbox(NOW);
    jump("sec-super-timeline");
    expect(els["sec-super-timeline"].style.display).toBe("");
    // The whole point of the in-memory reveal: nothing in localStorage moved.
    expect(writes).toEqual([]);
    expect(storedVis()).toEqual(NOW);
  });

  it("leaves every other section the profile hid alone, so the layout stays Now", () => {
    const { els, jump } = sandbox({ ...NOW, "sec-timeline": false });
    jump("sec-super-timeline");
    expect(els["sec-now"].style.display).toBe("");
    expect(els["sec-gated"].style.display).toBe("none");
  });

  it("ends the detour when an explicit layout decision clears the reveals", () => {
    // Switching view, saving Settings and connecting a case all call this. Clearing REPAINTS on its
    // own — no applySectionsVis() from the caller — because two callers had no repaint to give: the
    // case-connect boundary called none, and the per-case restore passes rerender:false.
    const { api, els, jump } = sandbox(NOW);
    jump("sec-super-timeline");
    expect(els["sec-super-timeline"].style.display).toBe("");
    api.clearSectionReveals();
    expect(els["sec-super-timeline"].style.display).toBe("none");
  });

  it("does nothing at all when no reveal is standing", () => {
    // The common case — every view switch and Settings save calls this. A section left mid-flight by
    // another writer must not be repainted out from under it.
    const { api, els } = sandbox(NOW);
    els["sec-now"].style.display = "sentinel";
    api.clearSectionReveals();
    expect(els["sec-now"].style.display).toBe("sentinel");
  });

  it("still omits a section whose evidence gate is closed", () => {
    // Revealing it would not show it — applySectionsVis() keeps a closed gate hidden either way —
    // so offering the jump would produce an action that silently does nothing.
    const { api, els } = sandbox(NOW);
    expect(navLabels(api.buildPaletteActions())).not.toContain("Go to Memory Next Steps");
    // Asserted against a real visibility pass, not the fixture's initial value: the closed gate is
    // what holds it at none, even though nothing in the store hides it.
    api.applySectionsVis();
    expect(els["sec-gated"].style.display).toBe("none");
  });

  it("still omits a section this build does not render", () => {
    const { api } = sandbox(NOW);
    expect(navLabels(api.buildPaletteActions())).not.toContain("Go to Not In This Build");
  });

  // The real Related Cases panel: gated AND defaultHidden, so nothing is stored for it and it reads
  // as hidden while nobody has decided anything.
  it("reaches a gated, default-hidden section once its evidence lands", () => {
    const { api, els, writes, jump } = sandbox(NOW);
    expect(navLabels(api.buildPaletteActions())).toContain("Go to Related Cases");
    jump("sec-gate-dflt");
    expect(els["sec-gate-dflt"].style.display).toBe("");
    expect(writes).toEqual([]);
  });

  // An explicit `false` is NOT evidence the analyst unticked anything: saveSettings() stamps one on
  // every section on any Settings save, whatever was actually being changed. Reading it as intent
  // is what left this panel unreachable in an earlier round of this fix.
  it("reaches a gated section carrying an explicit false from an unrelated Settings save", () => {
    const vis = { ...NOW, "sec-gate-dflt": false };
    const { api, els, writes, storedVis, jump } = sandbox(vis);
    expect(navLabels(api.buildPaletteActions())).toContain("Go to Related Cases");
    jump("sec-gate-dflt");
    expect(els["sec-gate-dflt"].style.display).toBe("");
    // Still no write — the stored value stays exactly as the Settings save left it.
    expect(writes).toEqual([]);
    expect(storedVis()).toEqual(vis);
  });
});
