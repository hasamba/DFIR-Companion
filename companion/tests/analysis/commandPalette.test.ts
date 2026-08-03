import { describe, it, expect } from "vitest";
import { readFile } from "node:fs/promises";
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
    expect(fuzzyScore("sgnidnif", LABEL)).toBe(0);   // right letters, wrong order
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
    const byKeyword = scoreAction("alpha beta", action({ label: "Something Else", keywords: ["alpha beta"] }));
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
    const a = action({ available: () => { throw new Error("boom"); } });
    expect(isAvailable(a, null)).toBe(false);
  });
});

describe("searchActions", () => {
  const nav = action({ id: "nav.findings", label: "Go to Findings", category: "Navigation", keywords: ["findings"] });
  const exp = action({ id: "exp.stix", label: "STIX 2.1 bundle", category: "Exports", keywords: ["export"] });
  const act = action({ id: "act.merge", label: "Merge IOCs", category: "Actions", keywords: ["dedupe"] });
  const all = [nav, exp, act];

  it("filters to one category, including from a partial prefix", () => {
    expect(searchActions(">exports", all, null, []).map(r => r.action.id)).toEqual(["exp.stix"]);
    expect(searchActions(">e", all, null, []).map(r => r.action.id)).toEqual(["exp.stix"]);
  });

  it("combines a category filter with a search term", () => {
    expect(searchActions(">nav findings", all, null, []).map(r => r.action.id)).toEqual(["nav.findings"]);
    expect(searchActions(">nav stix", all, null, [])).toEqual([]);
  });

  it("drops actions that are unavailable for the current state", () => {
    const gated = [nav, action({ id: "gone", label: "Go to Nowhere", category: "Navigation", available: () => false })];
    expect(searchActions("", gated, null, []).map(r => r.action.id)).toEqual(["nav.findings"]);
  });

  it("drops non-matching actions entirely rather than ranking them last", () => {
    expect(searchActions("zzzzznomatch", all, null, [])).toEqual([]);
  });

  it("lists everything in category order on an empty query", () => {
    expect(searchActions("", all, null, []).map(r => r.action.category))
      .toEqual(["Navigation", "Actions", "Exports"]);
  });

  it("floats recently-run actions to the top of an unfiltered list", () => {
    expect(searchActions("", all, null, ["exp.stix"]).map(r => r.action.id)[0]).toBe("exp.stix");
    expect(searchActions("", all, null, ["act.merge", "exp.stix"]).map(r => r.action.id))
      .toEqual(["act.merge", "exp.stix", "nav.findings"]);
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
  const html = () => readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");

  it("loads the module and publishes the registry the module reads", async () => {
    const h = await html();
    expect(h).toContain('<script type="module" src="/js/command-palette.js"></script>');
    // Thunks, not snapshots — #pushSelect is populated asynchronously and toolbar buttons come and
    // go as the case loads, so a registry captured once would be wrong within seconds.
    //
    // The state thunk reads DfirState.lastState() since #415 moved the case snapshot into the
    // store. Still a thunk, so still live: what would break the palette is the arrow disappearing
    // and a value being captured here, which is what the shape below pins.
    expect(h).toContain(
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
    const h = await html();
    expect(h).toMatch(/const nav = SECTION_DEFS\.map\(/);
    expect(h).toMatch(/available: \(\) => !!document\.getElementById\(s\.id\) && isSectionVisible\(s\.id, vis\)/);
  });

  it("drives the export selects through their own change handler", async () => {
    const h = await html();
    expect(h).toMatch(/sel\.value = o\.value; sel\.dispatchEvent\(new Event\("change"\)\)/);
    expect(h).toContain('paletteSelectActions("exportSelect"');
    expect(h).toContain('paletteSelectActions("pushSelect"');
  });

  it("documents the shortcut in the existing cheat sheet", async () => {
    const h = await html();
    expect(h).toMatch(/Ctrl\+K \/ ⌘K<\/td><td[^>]*>Command palette/);
  });
});
