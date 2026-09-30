import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { loadDatabaseSync } from "../../src/analysis/sqliteRuntime.js";
import { emptyState, type ForensicEvent, type IOC } from "../../src/analysis/stateTypes.js";
import { mergeIocs } from "../../src/analysis/stateMerge.js";
import { clampOutlierYears, clampToYear, dominantYear, yearOf } from "../../src/analysis/timeYearClamp.js";
import { correlationGroups } from "../../src/analysis/correlate.js";
import { correlationKeys, mergeLoadAlways, mergeTrigger } from "../../src/analysis/mergeIndex.js";
import { mergeIndexStamp, mergeIntoCase } from "../../src/analysis/caseMerge.js";
import { mergeDelta } from "../../src/analysis/stateMerge.js";
import { deltaSchema } from "../../src/analysis/responseSchema.js";

// #1874: the pieces the incremental importer merge stands on, each against the code it must agree with.

function ev(id: string, timestamp: string, p: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp,
    description: `row ${id}`,
    severity: "Low",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...p,
  };
}

// A small seeded generator, so a failure names a seed that reproduces it.
function rng(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s / 2 ** 32;
  };
}

describe("mergeIocs' first-match index", () => {
  // The lookup it replaced: the first IOC in list order matching by value or by alias-target id.
  function linearTarget(iocs: IOC[], value: string, alias?: string): string | undefined {
    const lower = value.toLowerCase();
    return iocs.find((i) => i.value.toLowerCase() === lower || (alias !== undefined && i.id === alias))?.id;
  }

  it("picks the same stored IOC as the linear scan, for values, case variants and aliases", () => {
    for (let seed = 1; seed <= 200; seed++) {
      const r = rng(seed);
      const pool = ["a.example.com", "A.Example.com", "10.0.0.1", "B.example.COM", "c.example.com"];
      const existing: IOC[] = Array.from({ length: 6 }, (_, i) => ({
        id: `i${String(i + 1).padStart(3, "0")}`,
        type: "domain",
        value: pool[Math.floor(r() * pool.length)],
        firstSeen: "t",
      }));
      const value = pool[Math.floor(r() * pool.length)];
      const alias = r() < 0.5 ? existing[Math.floor(r() * existing.length)].id : undefined;
      const aliases = alias ? { [value.toLowerCase()]: alias } : undefined;
      const { iocs } = mergeIocs(
        existing,
        { iocs: [{ id: "n1", type: "domain", value, extractedFrom: ["ev1"] }] },
        { timestamp: "t", iocAliases: aliases },
        [],
      );
      const target = linearTarget(existing, value, alias) ?? alias;
      if (target && existing.some((i) => i.id === target)) {
        expect(iocs.find((i) => i.id === target)?.extractedFrom, `seed ${seed}`).toContain("ev1");
        expect(iocs, `seed ${seed}`).toHaveLength(existing.length);
      } else {
        expect(iocs, `seed ${seed}`).toHaveLength(existing.length + 1);
      }
    }
  });

  it("continues the sequence from a case-wide start when given one", () => {
    const { iocs } = mergeIocs(
      [],
      { iocs: [{ id: "x", type: "ip", value: "10.9.9.9" }] },
      { timestamp: "t" },
      [],
      42,
    );
    expect(iocs.map((i) => i.id)).toEqual(["i042"]);
  });
});

describe("the dominant year from a histogram", () => {
  it("clamps exactly as clampOutlierYears does over the whole timeline", () => {
    for (let seed = 1; seed <= 150; seed++) {
      const r = rng(seed);
      const events = Array.from({ length: 5 + Math.floor(r() * 40) }, (_, i) => {
        const year = r() < 0.92 ? 2026 : 2020 + Math.floor(r() * 10);
        return ev(`e${i}`, `${year}-0${1 + Math.floor(r() * 9)}-1${Math.floor(r() * 9)}T10:00:00Z`, {
          yearInferred: r() < 0.3,
        });
      });
      const hist = new Map<number, number>();
      for (const e of events) {
        const y = yearOf(e.timestamp);
        if (y !== null) hist.set(y, (hist.get(y) ?? 0) + 1);
      }
      expect(clampToYear(events, dominantYear(hist)), `seed ${seed}`).toEqual(clampOutlierYears(events));
    }
  });
});

describe("correlation bucket keys", () => {
  // Every group correlation forms must be connected through shared keys: then a set closed under the
  // keys holds every group touching it whole.
  it("connect every pair correlation folds together", () => {
    const hosts = ["WS1", "ws1.corp.example.com", "WS2", ""];
    const paths = ["C:\\Temp\\a.exe", "c:\\temp\\A.EXE", "C:\\Temp\\b.exe", undefined];
    const hashes = ["a".repeat(64), "b".repeat(64), undefined];
    for (let seed = 1; seed <= 120; seed++) {
      const r = rng(seed);
      const pick = <T>(xs: T[]): T => xs[Math.floor(r() * xs.length)];
      const events = Array.from({ length: 12 }, (_, i) =>
        ev(`e${i}`, `2026-07-01T10:00:0${Math.floor(r() * 6)}Z`, {
          description: pick([
            `copied ${pick(paths) ?? "x"}`,
            "same text",
            `LEAPP usage [origin: x]`,
            "LEAPP usage",
          ]),
          asset: pick(hosts) || undefined,
          path: pick(paths),
          sha256: pick(hashes),
          sources: [pick(["THOR", "Sysmon", "EDR"])],
          ...(r() < 0.3
            ? { pid: 100 + Math.floor(r() * 2), commandLine: "x.exe -a", processName: "x.exe" }
            : {}),
          ...(r() < 0.2 ? { sourceRecordId: "Security:42" } : {}),
        }),
      );
      for (const group of correlationGroups(events)) {
        if (group.length < 2) continue;
        const keys = group.map((e) => new Set(correlationKeys(e)));
        const reached = new Set([0]);
        for (let grew = true; grew;) {
          grew = false;
          for (let i = 0; i < group.length; i++) {
            if (reached.has(i)) continue;
            if ([...reached].some((j) => [...keys[i]].some((k) => keys[j].has(k)))) {
              reached.add(i);
              grew = true;
            }
          }
        }
        expect(reached.size, `seed ${seed}`).toBe(group.length);
      }
    }
  });
});

describe("merge triggers and always-read rows", () => {
  it("names the pass that could act, and leaves ordinary rows alone", () => {
    expect(mergeTrigger(ev("a", "2026-01-01T00:00:00Z", { description: "Service installed x" }))).toBeNull();
    expect(mergeTrigger(ev("a", "2026-01-01T00:00:00Z", { sources: ["Email"] }))).toBe("email delivery");
    expect(mergeTrigger(ev("a", "2026-01-01T00:00:00Z", { canonical: { defender: {} } as never }))).toBe(
      "Defender record",
    );
    expect(mergeTrigger(ev("a", "t", { description: "x [after Defender: y]" }))).toBe("a correlation note");
    expect(mergeTrigger(ev("a", "t", { description: "x [unexpected parent: y]" }))).toBeNull();
    expect(mergeLoadAlways(ev("a", "2026-01-01T00:00:00Z", { asset: "H", mitreTechniques: ["T1490"] }))).toBe(
      true,
    );
    expect(
      mergeLoadAlways(ev("a", "2026-01-01T00:00:00Z", { asset: "H", mitreTechniques: ["T1560.001"] })),
    ).toBe(true);
    expect(mergeLoadAlways(ev("a", "2026-01-01T00:00:00Z", { mitreTechniques: ["T1490"] }))).toBe(false);
  });
});

describe("ordinals: a save keeps every row it can where it is", () => {
  const DatabaseSync = loadDatabaseSync();
  let dir: string;
  let store: StateStore;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "dfir-ordinals-"));
    const cases = new CaseStore(dir);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new StateStore(cases);
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });
  function ordinals(): Map<string, number> {
    const db = new DatabaseSync(store.databasePath("c1"), { readOnly: true });
    try {
      const rows = db
        .prepare("SELECT entity_id, ordinal FROM entities WHERE kind='forensicTimeline' ORDER BY ordinal")
        .all() as { entity_id: string; ordinal: number }[];
      return new Map(rows.map((r) => [r.entity_id, Number(r.ordinal)]));
    } finally {
      db.close();
    }
  }

  it("inserts between stored rows without moving them, and keeps the value index in step", async () => {
    const base = Array.from({ length: 6 }, (_, i) => ev(`r${i}`, `2026-01-0${i + 1}T00:00:00Z`));
    await store.save({ ...emptyState("c1"), forensicTimeline: base });
    expect([...ordinals().values()]).toEqual([0, 1, 2, 3, 4, 5]); // a first save: 0..n-1, as always
    // A row at the front has no room below row 0: the timeline is respaced once, with room.
    const front = ev("front", "2025-12-31T00:00:00Z");
    await store.save({ ...emptyState("c1"), forensicTimeline: [front, ...base] });
    const spaced = ordinals();
    expect((await store.load("c1")).forensicTimeline.map((e) => e.id)).toEqual([
      "front",
      ...base.map((e) => e.id),
    ]);
    // The next insert lands in a gap: nothing else moves.
    const mid = ev("mid", "2026-01-03T12:00:00Z");
    const next = [front, ...base.slice(0, 3), mid, ...base.slice(3)];
    await store.save({ ...emptyState("c1"), forensicTimeline: next });
    const after = ordinals();
    for (const [id, o] of spaced) expect(after.get(id)).toBe(o);
    expect((await store.load("c1")).forensicTimeline.map((e) => e.id)).toEqual(next.map((e) => e.id));
    const page = await store.queryForensicTimeline("c1", { limit: 3 });
    const rest = await store.queryForensicTimeline("c1", { cursor: page.nextCursor ?? undefined, limit: 50 });
    expect([...page.entities, ...rest.entities].map((e) => e.id)).toEqual(next.map((e) => e.id));
  });
});

describe("the merge index across a settle stamp", () => {
  let dir: string;
  let store: StateStore;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "dfir-carry-"));
    const cases = new CaseStore(dir);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new StateStore(cases);
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("stays current when only the import stamp changed, and goes stale when anything else did", async () => {
    const d = deltaSchema.parse({
      findings: [],
      iocs: [],
      mitreTechniques: [],
      forensicEvents: [ev("a", "2026-01-01T00:00:00Z"), ev("b", "2026-01-02T00:00:00Z")],
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: "",
      summary: "",
    });
    const ctx = { windowSequence: -1, timestamp: "2026-09-30T00:00:00Z", sourceScreenshots: ["x"] };
    await mergeIntoCase(store, "c1", d, ctx, (s) => mergeDelta(s, d, ctx));
    expect((await store.mergeSnapshot("c1"))?.meta?.stamp).toBe(mergeIndexStamp());
    expect((await store.mergeSnapshot("c1"))?.stale).toEqual([]);
    const [a, b] = await store.forensicRowsById("c1", ["a", "b"]);
    await store.updateForensicRows("c1", [
      { ...a, event: { ...a.event, importedAt: "T", importBatchId: "B" } },
      { ...b, event: { ...b.event, importedAt: "T", severity: "High" } },
    ]);
    expect((await store.mergeSnapshot("c1"))?.stale).toEqual([b.rowId]);
  });

  it("is rebuilt whole by the first merge of a new build, however clean it looked", async () => {
    const d = deltaSchema.parse({
      findings: [],
      iocs: [],
      mitreTechniques: [],
      forensicEvents: [ev("a", "2026-01-01T00:00:00Z")],
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: "",
      summary: "",
    });
    const ctx = { windowSequence: -1, timestamp: "2026-09-30T00:00:00Z", sourceScreenshots: ["x"] };
    await mergeIntoCase(store, "c1", d, ctx, (s) => mergeDelta(s, d, ctx));
    // What an older build left: a stamp of its own, and an entry this build would not have written.
    const snap = await store.mergeSnapshot("c1");
    await store.mergeIndexWrite(
      "c1",
      snap!.generation,
      [
        {
          position: 0,
          index: { timeMs: null, year: null, yearInferred: false, keys: [], flags: 1, clean: true },
        },
      ],
      { stamp: "0:older-build", stable: true },
    );
    const next = { ...d, forensicEvents: [ev("b", "2026-01-02T00:00:00Z")] } as typeof d;
    const out = await mergeIntoCase(store, "c1", next, ctx, (s) => mergeDelta(s, next, ctx));
    expect(out.complete).toBe(true); // the stamp sent it down the full path
    const after = await store.mergeSnapshot("c1");
    expect(after?.meta?.stamp).toBe(mergeIndexStamp());
    expect(after?.clean.trigger).toBe(0); // the older entry was rewritten
    expect(after?.clean.rows).toBe(2);
  });
});
