// #1914: the search prefilter is worked out from the term, and it must never drop a row the matcher
// (searchFilter.ts eventMatchesSearch) accepts. These assertions walk ALL of Unicode rather than a
// list of examples: the claim "only these characters can fold into the term" is a claim about every
// code point, so it is checked against every code point.
import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { loadDatabaseSync } from "../../src/analysis/sqliteRuntime.js";
import { StateStore, type EntityQuery } from "../../src/analysis/stateStore.js";
import { searchForensicTimeline } from "../../src/analysis/forensicSearch.js";
import {
  charsFoldingTo,
  READ_TIME_EDGE_OBSERVED,
  searchPrefilterPlan,
} from "../../src/analysis/searchFoldPrefilter.js";
import { eventMatchesSearch } from "../../src/analysis/searchFilter.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

function* foldingCodePoints(): Generator<[string, string]> {
  for (let code = 0x80; code <= 0x10ffff; code++) {
    if (code >= 0xd800 && code <= 0xdfff) continue;
    const char = String.fromCodePoint(code);
    const lower = char.toLowerCase();
    if (lower !== char) yield [char, lower];
  }
}

describe("searchPrefilterPlan over all of Unicode (#1914)", () => {
  it("offers every character whose lowercase form holds a character of the term", () => {
    let checked = 0;
    for (const [char, lower] of foldingCodePoints()) {
      for (const target of lower) {
        const plan = searchPrefilterPlan(target);
        expect(plan.scanAll).toBe(false);
        expect(plan.foldChars, `${JSON.stringify(char)} folds into ${JSON.stringify(target)}`).toContain(
          char,
        );
        checked++;
      }
    }
    expect(checked).toBeGreaterThan(1000);
  });

  it("knows exactly two characters that fold into ASCII", () => {
    const crossing = [...foldingCodePoints()]
      .filter(([, lower]) => /[\u0000-\u007f]/.test(lower))
      .map(([c]) => c);
    expect(crossing).toEqual(["\u0130", "\u212a"]);
    expect(searchPrefilterPlan("admin").foldChars).toEqual(["\u0130"]);
    expect(searchPrefilterPlan("keylogger").foldChars).toEqual(["\u212a"]);
    expect(searchPrefilterPlan("kill").foldChars).toEqual(["\u0130", "\u212a"]);
  });

  it("adds no fold check to an ASCII term without i or k: LIKE alone decides", () => {
    const plan = searchPrefilterPlan("zzzzqq");
    expect(plan.like).toBe("%zzzzqq%");
    expect(plan.foldChars).toEqual([]);
  });

  it("drops LIKE for a term that stays non-ASCII, and offers the term's own character", () => {
    const plan = searchPrefilterPlan("évil");
    expect(plan.like).toBeUndefined();
    expect(plan.foldChars).toEqual(["É", "é"].sort());
  });

  it("treats the three sigmas as one letter, because lowercasing picks one by context", () => {
    for (const sigma of ["σ", "ς", "Σ"]) expect(charsFoldingTo(sigma)).toEqual(["Σ", "σ", "ς"]);
    expect(searchPrefilterPlan("οδος").foldNeedle).toBe("οδοσ");
  });

  it("encodes the needle the way the payload stores it", () => {
    expect(searchPrefilterPlan('c:\\temp\\"a"').foldNeedle).toBe('c:\\\\temp\\\\\\"a\\"');
  });

  it("scans every row for a lone surrogate, high or low, alone or between ASCII", () => {
    for (const term of ["\ud800", "\udc00", "ab\ud83dcd", "ab\ude00cd"]) {
      expect(searchPrefilterPlan(term).scanAll, JSON.stringify(term)).toBe(true);
    }
  });

  it("flags a term the read-time edge-observed restamp could match, and only such a term", () => {
    for (const term of ["edge-observed", "observed", "e-o", "d"])
      expect(searchPrefilterPlan(term).edgeObserved).toBe(true);
    for (const term of ["mimikatz", "edge observed", "é"])
      expect(searchPrefilterPlan(term).edgeObserved).toBe(false);
  });

  it("keeps a paired astral character on the narrow path", () => {
    const plan = searchPrefilterPlan("🔥");
    expect(plan.scanAll).toBe(false);
    expect(plan.foldChars).toEqual(["🔥"]);
    const deseret = searchPrefilterPlan("\u{10428}"); // DESERET SMALL LONG I; capital is U+10400
    expect(deseret.foldChars).toContain("\u{10400}");
  });
});

// ---------------------------------------------------------------------------
// The measured failure: a Hayabusa import writes an em dash into every description, so the old
// "any non-ASCII row is a candidate" fallback offered EVERY row, and the search parsed them all
// twice. Wall time is machine-dependent, so the guard counts the rows the store hands back.
// ---------------------------------------------------------------------------
describe("search prefilter on a case where every row holds non-ASCII text (#1914)", () => {
  let stateStore: StateStore;
  let handedBack: number;
  let scans: number;
  const ROWS = 3000;

  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-search-fold-"));
    const caseStore = new CaseStore(root);
    await caseStore.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    stateStore = new StateStore(caseStore);
    const state = emptyState("c1");
    state.forensicTimeline = Array.from({ length: ROWS }, (_, index) => ({
      id: `e${index}`,
      timestamp: "2026-01-01T00:00:00.000Z",
      description: `Hayabusa: Suspicious Process (EID 1 Sysmon) — Proc=C:\\Temp\\p${index}.exe`,
      severity: "Low" as const,
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
      sources: ["Hayabusa"],
    }));
    await stateStore.save(state);
    const query = stateStore.queryForensicTimeline.bind(stateStore);
    handedBack = 0;
    scans = 0;
    stateStore.queryForensicTimeline = async (caseId: string, q?: EntityQuery) => {
      const page = await query(caseId, q);
      handedBack += page.entities.length;
      scans++;
      return page;
    };
  }, 60_000);

  it("hands back no rows for a term no event carries", async () => {
    const started = performance.now();
    const page = await searchForensicTimeline(stateStore, "c1", "zzzzqq", { limit: 10_000 });
    const ms = Math.round(performance.now() - started);
    expect(page.entities).toEqual([]);
    expect(page.total).toBe(0);
    expect(handedBack).toBe(0); // was 2 × ROWS: every row parsed by the page pass and the count pass
    console.info(`[#1914] absent term over ${ROWS} non-ASCII rows: ${ms} ms, ${scans} store query`);
  });

  it("hands back only the matching row for a rare term", async () => {
    const page = await searchForensicTimeline(stateStore, "c1", "p2999.exe", { limit: 10_000 });
    expect(page.entities.map((e) => e.id)).toEqual(["e2999"]);
    expect(page.total).toBe(1);
    expect(handedBack).toBe(1);
  });

  it("answers a first request with one scan for both the page and the count", async () => {
    const page = await searchForensicTimeline(stateStore, "c1", "hayabusa", { limit: 50 });
    expect(page.entities).toHaveLength(50);
    expect(page.total).toBe(ROWS);
    expect(handedBack).toBe(ROWS); // one pass, not page + count
  });

  it("still finds the em dash itself, and a folded non-ASCII term", async () => {
    expect((await searchForensicTimeline(stateStore, "c1", "—", { limit: 5 })).total).toBe(ROWS);
    expect(
      (
        await searchForensicTimeline(stateStore, "c1", "HAYABUSA: SUSPICIOUS PROCESS (EID 1 SYSMON) —", {
          limit: 5,
        })
      ).total,
    ).toBe(ROWS);
  });
});

// One scan answering both questions must give the same answers the two-pass path gives.
describe("one-pass page and count agree with the two-pass path (#1914)", () => {
  let stateStore: StateStore;

  async function seed(events: Partial<ForensicEvent>[]) {
    const root = await mkdtemp(join(tmpdir(), "dfir-search-pass-"));
    const caseStore = new CaseStore(root);
    await caseStore.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    stateStore = new StateStore(caseStore);
    const state = emptyState("c1");
    state.forensicTimeline = events.map((event, index) => ({
      id: `e${index}`,
      timestamp: "2026-01-01T00:00:00.000Z",
      description: "routine",
      severity: "Low" as const,
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
      sources: [],
      ...event,
    }));
    await stateStore.save(state);
  }

  it("returns the page, cursor and total the cursor path continues from", async () => {
    await seed(
      Array.from({ length: 300 }, (_, i) => ({ description: i % 7 === 0 ? "beacon ÉVIL" : "routine" })),
    );
    const first = await searchForensicTimeline(stateStore, "c1", "évil", { limit: 10 });
    const twoPass = await searchForensicTimeline(stateStore, "c1", "évil", {
      limit: 10,
      includeTotal: false,
    });
    expect(first.entities.map((e) => e.id)).toEqual(twoPass.entities.map((e) => e.id));
    expect(first.nextCursor).toBe(twoPass.nextCursor);
    expect(first.total).toBe(43);

    const all = (await stateStore.queryForensicTimeline("c1", { limit: 1000 })).entities;
    const expected = all.filter((e) => eventMatchesSearch(e, "évil")).map((e) => e.id);
    const seen = [...first.entities.map((e) => e.id)];
    let cursor = first.nextCursor ?? undefined;
    while (cursor !== undefined) {
      const page = await searchForensicTimeline(stateStore, "c1", "évil", { limit: 10, cursor });
      expect(page.total).toBe(43); // the cursor path still counts from the top
      seen.push(...page.entities.map((e) => e.id));
      cursor = page.nextCursor ?? undefined;
    }
    expect(seen).toEqual(expected);
  });

  it("keeps a zero-row page cheap but still counted", async () => {
    await seed(Array.from({ length: 20 }, () => ({ description: "beacon" })));
    const page = await searchForensicTimeline(stateStore, "c1", "beacon", { limit: 0 });
    expect(page.entities).toEqual([]);
    expect(page.nextCursor).toBeNull();
    expect(page.total).toBe(20);
  });

  it("fills a page larger than the count ceiling while the count stops at its floor", async () => {
    await seed(Array.from({ length: 10_003 }, () => ({ description: "beacon" })));
    const page = await searchForensicTimeline(stateStore, "c1", "beacon", { limit: 10_002 });
    expect(page.entities).toHaveLength(10_002);
    expect(page.total).toBe(10_000);
    expect(page.totalIsLowerBound).toBe(true);
    expect(page.nextCursor).not.toBeNull();
  }, 120_000);
});

// ---------------------------------------------------------------------------
// The matcher sees an event AFTER the read-time upgrade (upgradeForensicEvent), not the stored JSON.
// Two upgrades add searchable text the payload does not hold. Rows written that way are planted here
// straight into the database, the way an older build left them, each with an em dash so the old
// "any non-ASCII row" fallback would have kept them and the new prefilter must not lose them.
// ---------------------------------------------------------------------------
describe("rows the read-time upgrade adds searchable text to (#1914)", () => {
  let stateStore: StateStore;

  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-search-upgrade-"));
    const caseStore = new CaseStore(root);
    await caseStore.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    stateStore = new StateStore(caseStore);
    const state = emptyState("c1");
    state.forensicTimeline = ["legacy", "edge", "plain"].map((id) => ({
      id,
      timestamp: "2026-01-01T00:00:00.000Z",
      description: `logon — ${id}`,
      severity: "Low" as const,
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
      sources: [],
      processName: "svc.exe",
    }));
    await stateStore.save(state);
    const db = new (loadDatabaseSync())(stateStore.databasePath("c1"));
    try {
      const rows = db.prepare("SELECT row_id, payload FROM entities WHERE kind='forensicTimeline'").all();
      for (const row of rows as { row_id: number; payload: string }[]) {
        const event = JSON.parse(row.payload) as ForensicEvent & { canonical?: Record<string, unknown> };
        if (event.id === "legacy") delete event.canonical;
        if (event.id === "edge" && event.canonical) {
          event.canonical = {
            ...event.canonical,
            producer: { importer: "network", parserVersion: "1", mappingVersion: "t" },
            network: { source: { address: "203.0.113.9" } },
          };
        }
        db.prepare("UPDATE entities SET payload=? WHERE row_id=?").run(JSON.stringify(event), row.row_id);
      }
    } finally {
      db.close();
    }
  });

  it("finds exactly what the matcher finds on the upgraded rows", async () => {
    const upgraded = (await stateStore.queryForensicTimeline("c1", { limit: 100 })).entities;
    const edge = upgraded.find((e) => e.id === "edge");
    expect(edge?.canonical?.network?.source?.provenance, "the restamp the test relies on").toBe(
      READ_TIME_EDGE_OBSERVED,
    );
    expect(upgraded.find((e) => e.id === "legacy")?.canonical, "the legacy synthesis").toBeTruthy();
    for (const term of [
      "edge-observed",
      "OBSERVED",
      "process",
      "observation",
      "svc.exe",
      "logon —",
      "zzzzqq",
    ]) {
      const expected = upgraded
        .filter((e) => eventMatchesSearch(e, term))
        .map((e) => e.id)
        .sort();
      const page = await searchForensicTimeline(stateStore, "c1", term, { limit: 100 });
      expect(page.entities.map((e) => e.id).sort(), JSON.stringify(term)).toEqual(expected);
      expect(page.total, `total for ${JSON.stringify(term)}`).toBe(expected.length);
    }
  });
});
