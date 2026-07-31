import { describe, it, expect } from "vitest";
import { readFile } from "node:fs/promises";
// The module lives outside companion/, next to command-palette.js and graph-view.js. Its pure
// exports touch no DOM, so importing them in node works — same arrangement as commandPalette.test.ts,
// but with a .d.ts alongside so this file stays inside `npm run typecheck` instead of joining the
// exclude list in tsconfig.test.json.
import {
  normalize,
  matchTokens,
  landingTab,
  searchMessage,
} from "../../../public/js/settings-search.js";

/** Real haystacks, assembled the way buildIndex() assembles them (see fieldText): the label text,
 *  the hint text, then the input id, joined with spaces. */
const LEAKCHECK = "LeakCheck key DFIR_LEAKCHECK_KEY env-DFIR_LEAKCHECK_KEY";
const MAX_EVENTS = "Max events per import DFIR_MAX_EVENTS env-DFIR_MAX_EVENTS 2000";

describe("normalize", () => {
  it("lowercases, turns _ and - into spaces, and collapses whitespace", () => {
    expect(normalize("DFIR_MAX_EVENTS")).toBe("dfir max events");
    expect(normalize("  Report-Templates\n")).toBe("report templates");
  });

  it("survives null and undefined", () => {
    expect(normalize(null)).toBe("");
    expect(normalize(undefined)).toBe("");
  });
});

describe("matchTokens", () => {
  it("requires every token, in any order", () => {
    expect(matchTokens("leakcheck key", LEAKCHECK)).toBe(true);
    expect(matchTokens("key leakcheck", LEAKCHECK)).toBe(true);
    expect(matchTokens("leakcheck shodan", LEAKCHECK)).toBe(false);
  });

  it("finds an env key by its human wording and by the key itself", () => {
    // The whole point of normalize(): DFIR_MAX_EVENTS becomes "dfir max events" on both sides.
    expect(matchTokens("max events", MAX_EVENTS)).toBe(true);
    expect(matchTokens("DFIR_MAX_EVENTS", MAX_EVENTS)).toBe(true);
    expect(matchTokens("dfir-max-events", MAX_EVENTS)).toBe(true);
  });

  it("is case insensitive", () => {
    expect(matchTokens("LEAKCHECK", LEAKCHECK)).toBe(true);
  });

  it("matches inside a word, not just at boundaries", () => {
    expect(matchTokens("check", LEAKCHECK)).toBe(true);
  });

  it("treats an empty query as a vacuous AND", () => {
    // Callers short-circuit before this, but the identity has to be the harmless one: a matcher
    // that returned false on "" would blank the modal for one frame on every clear.
    expect(matchTokens("", LEAKCHECK)).toBe(true);
    expect(matchTokens("   ", LEAKCHECK)).toBe(true);
  });
});

describe("landingTab", () => {
  it("stays on the current tab when it has hits", () => {
    expect(landingTab(["general", "ai", "tools"], "ai")).toBe("ai");
  });

  it("falls to the first hit tab when the current one has none", () => {
    expect(landingTab(["ai", "tools"], "general")).toBe("ai");
  });

  it("returns null when nothing matched", () => {
    expect(landingTab([], "general")).toBe(null);
  });

  it("copes with no active tab", () => {
    expect(landingTab(["ai"], null)).toBe("ai");
    expect(landingTab([], null)).toBe(null);
  });
});

describe("searchMessage", () => {
  it("reports fields and tabs, with agreeing plurals", () => {
    expect(searchMessage({ tabs: 3, fields: 12, query: "key" })).toBe("12 fields in 3 tabs");
    expect(searchMessage({ tabs: 1, fields: 1, query: "vt" })).toBe("1 field in 1 tab");
  });

  it("reports tabs alone for a name-only match", () => {
    // Typing "kev" hits the KEV tab, whose pane is filled by JS at click time and holds no .sfield.
    expect(searchMessage({ tabs: 1, fields: 0, query: "kev" })).toBe("1 tab");
    expect(searchMessage({ tabs: 2, fields: 0, query: "template" })).toBe("2 tabs");
  });

  it("names the query when nothing matched", () => {
    expect(searchMessage({ tabs: 0, fields: 0, query: " nope " })).toBe('No settings match "nope"');
  });
});

const dashboard = () => readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");

describe("dashboard.html search markup", () => {
  it("carries the input and message span the module binds to", async () => {
    const h = await dashboard();
    expect(h).toContain('id="settingsSearch"');
    expect(h).toContain('aria-label="Search settings"');
    expect(h).toContain('id="settingsSearchMsg"');
  });
});

describe("dashboard.html search CSS", () => {
  it("hides tabs, pane children and row siblings that are not hits", async () => {
    const h = await dashboard();
    expect(h).toContain('.settings-modal[data-searching] .stab:not([data-hit]) { display: none !important; }');
    expect(h).toContain('.settings-modal[data-searching] .stab-pane:not([data-hit="pane"]) > *:not([data-hit]) { display: none !important; }');
    expect(h).toContain('.settings-modal[data-searching] :is(.sfield-row, .sfield-row3, .sgrid) > .sfield:not([data-hit]) { display: none !important; }');
  });

  it("renders the tab match count from the attribute", async () => {
    const h = await dashboard();
    expect(h).toContain('.settings-modal[data-searching] .stab[data-hit-count]::after');
    expect(h).toContain("content: attr(data-hit-count)");
  });

  it("steps the Essential/All toggle aside while searching", async () => {
    const h = await dashboard();
    expect(h).toContain('.settings-modal[data-searching] .settings-mode { display: none; }');
  });

  // THE REGRESSION GUARD. Search spans All by suspending Essential wholesale, which only works
  // while EVERY Essential rule opts out of it. A fourth rule added later without the opt-out would
  // keep hiding fields mid-search and silently re-break cross-tab search — with no failing test
  // anywhere else, because Essential mode itself would still look perfect.
  it("suspends every Essential rule while a search is active", async () => {
    const h = await dashboard();
    const rules = h.match(/^\s*\.settings-modal\[data-mode="essential"\].*$/gm) ?? [];
    expect(rules.length).toBeGreaterThanOrEqual(3);
    for (const rule of rules) expect(rule).toContain(":not([data-searching])");
  });
});

describe("dashboard.html search wiring", () => {
  it("loads the module", async () => {
    const h = await dashboard();
    expect(h).toContain('<script type="module" src="/js/settings-search.js"></script>');
  });

  // The server serves public/js by an EXACT-PATH whitelist (`STATIC_ASSETS` in
  // src/http/staticAssets.ts), not a static directory. A module that is not named there 404s, and
  // the only symptom in the browser is the feature silently not existing — no console error the
  // dashboard surfaces, nothing failing in any other suite. Written as "every module the dashboard
  // loads" rather than naming this one file, so the next /js/ module is covered the day it is added.
  it("whitelists every /js/ module the dashboard loads", async () => {
    const [h, server] = await Promise.all([
      dashboard(),
      readFile(new URL("../../src/http/staticAssets.ts", import.meta.url), "utf8"),
    ]);
    const loaded = [...h.matchAll(/<script type="module" src="(\/js\/[^"]+)"><\/script>/g)].map((m) => m[1]);
    expect(loaded).toContain("/js/settings-search.js");
    for (const path of loaded) {
      expect(server, `${path} is loaded by dashboard.html but not in STATIC_ASSETS (src/http/staticAssets.ts)`)
        .toContain(`"${path}": "application/javascript; charset=utf-8"`);
    }
  });

  it("publishes the config the module reads, and resets the box on open", async () => {
    const h = await dashboard();
    // Live references, not snapshots: the module calls applyMode() on clear so a tab Essential
    // hides falls back through the inline script's own path rather than a copy of it.
    expect(h).toContain("window.DfirSettingsSearchConfig = { applyMode: applySettingsMode, mode: settingsMode };");
    // Optional chaining: openSettingsModal is defined in a classic inline script, which runs
    // BEFORE the module that publishes window.DfirSettingsSearch.
    expect(h).toContain("window.DfirSettingsSearch?.reset();");
  });
});
