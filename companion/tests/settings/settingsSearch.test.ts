import { describe, it, expect } from "vitest";
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
