import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { mergeDelta } from "../../src/analysis/stateMerge.js";
import type { ImportContext } from "../../src/analysis/ingest/importContext.js";
import type { ForensicEvent, Severity } from "../../src/analysis/stateTypes.js";
import {
  bulkPathApplies,
  importVelociraptorBulk,
  readBulkBatchRows,
  readBulkMinBytes,
  runVelociraptorBulk,
  type BulkImportSink,
  type BulkRollbackSummary,
  type BulkRunHandle,
  type BulkRunSummary,
} from "../../src/analysis/ingest/velociraptorBulk.js";

// The batched Velociraptor driver (#1439). Every fixture is synthetic; the sink is in memory so the
// assertions are about the driver's contract — what it writes where, in what order, and what it
// says about it — not about sqlite.

const IMPORTED_AT = "2026-09-20T07:00:00.000Z";
const PROMOTED_PATH = "\\\\.\\C:\\Windows\\Temp\\dropper.ps1";

// Letters only: the MFT agg key folds digits, so "file1" and "file2" would collapse into one group.
function name(n: number): string {
  return n.toString(26).replace(/[0-9]/g, (d) => "qrstuvwxyz"[Number(d)]); // base 26 uses a–p
}

// One $MFT entry with ONE distinct MACB time and a distinct path → exactly one Info event per row.
function mftRow(n: number, path = `\\\\.\\C:\\Users\\u\\${name(n)}.txt`) {
  const t = new Date(Date.UTC(2026, 0, 1, 0, 0, n % 60000)).toISOString();
  return {
    EntryNumber: n,
    InUse: true,
    OSPath: path,
    FileName: path.slice(path.lastIndexOf("\\") + 1),
    FileSize: 10,
    IsDir: false,
    Created0x10: t,
    LastModified0x10: t,
    LastRecordChange0x10: t,
    LastAccess0x10: t,
  };
}

function mftEvent(id: string): ForensicEvent {
  return {
    id,
    timestamp: "2026-01-01T00:00:00.000Z",
    description: `row ${id}`,
    severity: "Info",
    sources: ["Velociraptor"],
  } as ForensicEvent;
}

function artifactMap(rows: object[]): string {
  return JSON.stringify({ "Windows.NTFS.MFT": rows });
}

interface MemorySink extends BulkImportSink {
  forensic: ForensicEvent[];
  superRows: ForensicEvent[];
  logs: string[];
  runs: BulkRunSummary[];
  taggerOpened: number;
  rollbacks: BulkRunHandle[];
}

// `promote` names the paths the stub tagger raises to High — the deterministic content tagger's
// job, stood in for by a predicate so the test does not depend on the shipped ruleset.
function memorySink(
  opts: {
    batchRows?: number;
    minBytes?: number;
    gate?: Severity;
    promote?: (e: ForensicEvent) => boolean;
    taggerOff?: boolean;
  } = {},
): MemorySink {
  let seq = 0;
  const seqOf = new WeakMap<ForensicEvent, number>();
  const sink: MemorySink = {
    minBytes: opts.minBytes ?? 0,
    batchRows: opts.batchRows ?? 5000,
    forensic: [],
    superRows: [],
    logs: [],
    runs: [],
    taggerOpened: 0,
    rollbacks: [],
    // The fence is an append sequence number; a rollback keeps every row at or below it and every
    // row above it that another run stamped — the worker op's contract (#1480), in memory.
    async beginRun() {
      return seq;
    },
    async rollback(_caseId, run) {
      sink.rollbacks.push(run);
      const forensicBefore = sink.forensic.length;
      const superBefore = sink.superRows.length;
      const keep = (e: ForensicEvent) =>
        (seqOf.get(e) ?? 0) <= run.fence || e.importBatchId !== run.importBatchId;
      if (run.mode === "forensic") sink.forensic = sink.forensic.filter(keep);
      sink.superRows = sink.superRows.filter(keep);
      return {
        forensic: forensicBefore - sink.forensic.length,
        super: superBefore - sink.superRows.length,
        tags: 0,
      } satisfies BulkRollbackSummary;
    },
    async appendForensic(_caseId, events) {
      for (const e of events) seqOf.set(e, ++seq);
      sink.forensic.push(...events);
      return events.length;
    },
    async appendSuper(_caseId, events) {
      const seen = new Set(sink.superRows.map((e) => e.id));
      const fresh = events.filter((e) => !seen.has(e.id));
      for (const e of fresh) seqOf.set(e, ++seq);
      sink.superRows.push(...fresh);
      return fresh.length;
    },
    async openTagger() {
      sink.taggerOpened++;
      if (opts.taggerOff) return null;
      return {
        rulesHash: "stub",
        async apply(_caseId, events) {
          let matched = 0;
          const out = events.map((e) => {
            if (opts.promote?.(e)) {
              matched++;
              return {
                ...e,
                severity: "High" as const,
                mitreTechniques: [...e.mitreTechniques, "T1059.001"],
              };
            }
            return e;
          });
          return { events: out, matched };
        },
      };
    },
    async forensicMinSeverity() {
      return opts.gate ?? "Low";
    },
    log(msg) {
      sink.logs.push(msg);
    },
    async recordRun(_caseId, summary) {
      sink.runs.push(summary);
    },
  };
  return sink;
}

async function contextWithStore() {
  const root = await mkdtemp(join(tmpdir(), "dfir-bulk-"));
  const caseStore = new CaseStore(root);
  await caseStore.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
  const stateStore = new StateStore(caseStore);
  const ctx: ImportContext = {
    opts: { stateStore },
    withStateLock: (_caseId, fn) => fn(),
    mergeWithAliases: async (state, delta, c) => mergeDelta(state, delta, c),
  };
  return { ctx, stateStore };
}

const baseOpts = (label = "0018_velo-flow_Windows.NTFS.MFT.json") => ({
  label,
  idPrefix: "18",
  importedAt: IMPORTED_AT,
});

describe("runVelociraptorBulk — forensic mode", () => {
  it("writes per batch: tagged rows to the forensic table, every row to the super-timeline, one log line each", async () => {
    const rows = Array.from({ length: 12_000 }, (_, i) => mftRow(i + 1));
    rows[7_777] = mftRow(7_778, PROMOTED_PATH); // one promotable row deep in batch 2
    const sink = memorySink({
      batchRows: 5000,
      promote: (e) => (e.path ?? "").endsWith("dropper.ps1"),
    });
    const progress: [number, number][] = [];
    const res = await runVelociraptorBulk(
      sink,
      "c1",
      artifactMap(rows),
      { ...baseOpts(), onProgress: (d, t) => progress.push([d, t]) },
      "forensic",
    );
    expect(res).not.toBeNull();
    expect(res!.rows).toBe(12_000);
    expect(res!.batches).toBe(3);
    expect(res!.events).toBe(12_000);
    // Every row is Info telemetry except the one the tagger raised → forensic holds exactly that one.
    expect(sink.forensic).toHaveLength(1);
    expect(sink.forensic[0].severity).toBe("High");
    expect(sink.forensic[0].path).toBe(PROMOTED_PATH);
    expect(sink.forensic[0].mitreTechniques).toContain("T1059.001");
    expect(res!.forensicKept).toBe(1);
    // The dual-write is complete: every event reached the raw record.
    expect(sink.superRows).toHaveLength(12_000);
    expect(res!.superAppended).toBe(12_000);
    // Ids continue across batches with no gaps, in the whole-file driver's shape.
    expect(sink.superRows[0].id).toBe("18e1");
    expect(sink.superRows[11_999].id).toBe("18e12000");
    // Each row carries the import stamp the settle seam would have added.
    expect(sink.superRows[0].importedAt).toBe(IMPORTED_AT);
    expect(sink.superRows[0].importBatchId).toBe(sink.superRows[11_999].importBatchId);
    expect(sink.superRows[0].sourceScreenshots).toEqual([baseOpts().label]);
    // One INFO line per batch, after the write, with the counts — the user's explicit ask.
    const batchLines = sink.logs.filter((l) => /batch \d+ rows/.test(l));
    expect(batchLines).toHaveLength(3);
    expect(batchLines[0]).toMatch(
      /batch 1 rows 1–5000 → 5000 event\(s\); forensic \+0, super \+5000 \(\d+ ms, rss \d+ MB\)/,
    );
    expect(batchLines[1]).toMatch(/batch 2 rows 5001–10000 → 5000 event\(s\); forensic \+1, super \+5000/);
    expect(batchLines[2]).toMatch(/batch 3 rows 10001–12000 → 2000 event\(s\); forensic \+0, super \+2000/);
    expect(sink.logs[0]).toMatch(/bulk path \(forensic\), \d+ MB, artifact-map, batches of 5000 rows/);
    expect(sink.logs[sink.logs.length - 1]).toMatch(
      /bulk done — 12000 row\(s\) → 12000 event\(s\) in 3 batch\(es\); forensic \+1, super \+12000, tagger matched 1/,
    );
    // Progress is monotone in rows done and ends at (rows, rows).
    for (let i = 1; i < progress.length; i++)
      expect(progress[i][0]).toBeGreaterThanOrEqual(progress[i - 1][0]);
    expect(progress[progress.length - 1]).toEqual([12_000, 12_000]);
    // The tagger ruleset is loaded once per import, not once per batch.
    expect(sink.taggerOpened).toBe(1);
    // One run record for the whole import, not one per event id.
    expect(sink.runs).toHaveLength(1);
    expect(sink.runs[0]).toMatchObject({
      path: "bulk",
      mode: "forensic",
      rows: 12_000,
      batches: 3,
      tagged: 1,
      rulesHash: "stub",
    });
  });

  it("respects the forensic event cap across batches and reports what it dropped", async () => {
    // Every row is High (the stub promotes all) so the cap is what limits the forensic table.
    const rows = Array.from({ length: 30 }, (_, i) => mftRow(i + 1));
    const sink = memorySink({ batchRows: 10, promote: () => true });
    const res = await runVelociraptorBulk(
      sink,
      "c1",
      artifactMap(rows),
      { ...baseOpts(), velociraptor: { maxEvents: 15 } },
      "forensic",
    );
    expect(sink.forensic).toHaveLength(15);
    expect(sink.forensic.map((e) => e.id)).toEqual(Array.from({ length: 15 }, (_, i) => `18e${i + 1}`));
    expect(res!.dropped).toBe(15);
    expect(sink.superRows).toHaveLength(30); // the raw record keeps every row regardless
    expect(sink.logs[sink.logs.length - 1]).toMatch(/15 graded row\(s\) over the event cap/);
  });

  it("honours the analyst floor and the case gate", async () => {
    const rows = Array.from({ length: 20 }, (_, i) => mftRow(i + 1));
    // Gate Medium: the stub raises to High, so with no floor everything promoted is kept…
    let sink = memorySink({
      batchRows: 10,
      gate: "Medium",
      promote: (e) => (e.path ?? "").endsWith(`${name(3)}.txt`),
    });
    await runVelociraptorBulk(sink, "c1", artifactMap(rows), baseOpts(), "forensic");
    expect(sink.forensic.map((e) => e.path)).toEqual([`\\\\.\\C:\\Users\\u\\${name(3)}.txt`]);
    // …the analyst import floor is gate-aware exactly as on the whole-file path: an all-Info batch has
    // nothing to discriminate on, so it imports whole…
    sink = memorySink({ batchRows: 10, gate: "Low", promote: () => true });
    let res = await runVelociraptorBulk(
      sink,
      "c1",
      artifactMap(rows),
      { ...baseOpts(), minSeverity: "Medium" },
      "forensic",
    );
    expect(res!.events).toBe(20);
    // …while the parser-level floor is a hard cut that drops Info before anything is written.
    sink = memorySink({ batchRows: 10, gate: "Low", promote: () => true });
    res = await runVelociraptorBulk(
      sink,
      "c1",
      artifactMap(rows),
      { ...baseOpts(), velociraptor: { minSeverity: "Low" } },
      "forensic",
    );
    expect(res!.events).toBe(0);
    expect(sink.forensic).toHaveLength(0);
    expect(sink.superRows).toHaveLength(0);
  });

  it("with the automatic tagger off, Info rows go to the super-timeline only", async () => {
    const rows = Array.from({ length: 5 }, (_, i) => mftRow(i + 1, PROMOTED_PATH));
    const sink = memorySink({ taggerOff: true, gate: "Low" });
    const res = await runVelociraptorBulk(sink, "c1", artifactMap(rows), baseOpts(), "forensic");
    expect(sink.forensic).toHaveLength(0);
    expect(sink.superRows.length).toBeGreaterThan(0);
    expect(res!.forensicKept).toBe(0);
    expect(sink.runs[0].rulesHash).toBeNull();
  });

  it("returns null for a shape the row reader cannot stream", async () => {
    const sink = memorySink();
    expect(await runVelociraptorBulk(sink, "c1", "Name,Value\na,1\n", baseOpts(), "forensic")).toBeNull();
    expect(sink.logs).toHaveLength(0);
  });
});

describe("runVelociraptorBulk — super-only mode", () => {
  it("never touches the forensic table, uses the stable idBase id shape, and still tags", async () => {
    const rows = Array.from({ length: 7 }, (_, i) => mftRow(i + 1, i === 3 ? PROMOTED_PATH : undefined));
    const sink = memorySink({ batchRows: 3, promote: (e) => (e.path ?? "").endsWith("dropper.ps1") });
    const res = await runVelociraptorBulk(
      sink,
      "c1",
      artifactMap(rows),
      { ...baseOpts(), idPrefix: "F.ABC-Windows.NTFS.MFT" },
      "super-only",
    );
    expect(sink.forensic).toHaveLength(0);
    expect(sink.superRows).toHaveLength(7);
    expect(sink.superRows[0].id).toBe("F.ABC-Windows.NTFS.MFT-e1");
    expect(res!.batches).toBe(3);
    expect(res!.batches).toBe(3);
    expect(sink.runs[0].tagged).toBe(1);
    expect(sink.logs.filter((l) => /batch \d+ rows/.test(l))).toHaveLength(3);
    // A re-import of the same flow dedups by id on the store: the sink saw no new rows.
    const again = await runVelociraptorBulk(
      sink,
      "c1",
      artifactMap(rows),
      { ...baseOpts(), idPrefix: "F.ABC-Windows.NTFS.MFT" },
      "super-only",
    );
    expect(again!.superAppended).toBe(0);
    expect(sink.superRows).toHaveLength(7);
  });
});

describe("importVelociraptorBulk — the forensic entry", () => {
  it("records the note and IOCs with one small whole-state merge and keeps the appended rows", async () => {
    const { ctx, stateStore } = await contextWithStore();
    const rows = Array.from({ length: 40 }, (_, i) => mftRow(i + 1));
    rows[10] = mftRow(11, PROMOTED_PATH);
    const sink = memorySink({ batchRows: 10, promote: (e) => (e.path ?? "").endsWith("dropper.ps1") });
    // Route the sink's forensic append at the real store so the final save is tested against it.
    sink.appendForensic = (caseId, events) => stateStore.appendForensicEvents(caseId, events);
    const state = await importVelociraptorBulk(ctx, sink, "c1", artifactMap(rows), baseOpts());
    expect(state).not.toBeNull();
    const reloaded = await stateStore.load("c1");
    expect(reloaded.forensicTimeline.map((e) => e.path)).toEqual([PROMOTED_PATH]);
    expect(reloaded.forensicTimeline[0].severity).toBe("High");
    const note = reloaded.timeline.at(-1)?.description ?? "";
    expect(note).toMatch(
      /Velociraptor import \(artifact-map, bulk path: 4 batch\(es\) of 10 rows\): 40 event\(s\) from 40 row\(s\); 1 kept in the forensic timeline, 40 in the super-timeline/,
    );
  });
});

describe("runVelociraptorBulk — a failed run rolls back its own rows (#1480)", () => {
  // A JSON array export cut short: the row reader throws on the unterminated last element after
  // every earlier batch has landed.
  function truncatedArray(n: number): string {
    const full = JSON.stringify(Array.from({ length: n }, (_, i) => mftRow(i + 1)));
    return full.slice(0, full.length - 40);
  }

  it("a truncated array throws after batches landed, and the run's rows are gone", async () => {
    // Batch 3 holds rows 21–29 when row 30 fails to parse; the message names the row.
    const sink = memorySink({ batchRows: 10, gate: "Info" });
    await expect(
      runVelociraptorBulk(
        sink,
        "c1",
        truncatedArray(30),
        baseOpts("0018_velo-flow_Windows.NTFS.MFT.json"),
        "forensic",
      ),
    ).rejects.toThrow(/row 30: unterminated array element/);
    expect(sink.rollbacks).toHaveLength(1);
    expect(sink.rollbacks[0].mode).toBe("forensic");
    expect(sink.forensic).toEqual([]);
    expect(sink.superRows).toEqual([]);
    expect(sink.logs.at(-1)).toMatch(
      /bulk FAILED at batch 3 \(rows 21–29\): row 30: unterminated array element — rolled back 20 forensic \/ 20 super row\(s\)/,
    );
    expect(sink.runs).toEqual([]); // no run record for a run that did not finish
  });

  it("rows another run owns, and rows from before the fence, survive the rollback", async () => {
    const sink = memorySink({ batchRows: 10, gate: "Info" });
    sink.superRows.push({ ...mftEvent("older"), importBatchId: "run-old" });
    // Another run's row above the fence, appended while this one ran (simulated by the first append).
    let injected = false;
    const append = sink.appendSuper;
    sink.appendSuper = async (caseId, events) => {
      const n = await append(caseId, events);
      if (!injected) {
        injected = true;
        sink.superRows.push({ ...mftEvent("theirs"), importBatchId: "run-theirs" });
      }
      return n;
    };
    await expect(
      runVelociraptorBulk(sink, "c1", truncatedArray(30), baseOpts(), "forensic"),
    ).rejects.toThrow();
    expect(sink.superRows.map((e) => e.id)).toEqual(["older", "theirs"]);
  });

  it("super-only mode rolls back the super-timeline only", async () => {
    const sink = memorySink({ batchRows: 10 });
    await expect(
      runVelociraptorBulk(
        sink,
        "c1",
        truncatedArray(30),
        { ...baseOpts(), idPrefix: "H.1-Windows.NTFS.MFT" },
        "super-only",
      ),
    ).rejects.toThrow();
    expect(sink.rollbacks[0].mode).toBe("super-only");
    expect(sink.rollbacks[0].fence).toBe(0);
    expect(sink.superRows).toEqual([]);
    expect(sink.logs.at(-1)).toMatch(/rolled back 0 forensic \/ 20 super row\(s\)/);
  });

  it("an append that throws after the forensic write still rolls back the forensic rows", async () => {
    const sink = memorySink({ batchRows: 10, gate: "Info" });
    let calls = 0;
    sink.appendSuper = async () => {
      if (++calls === 2) throw new Error("disk full");
      return 0;
    };
    await expect(
      runVelociraptorBulk(
        sink,
        "c1",
        artifactMap(Array.from({ length: 30 }, (_, i) => mftRow(i + 1))),
        baseOpts(),
        "forensic",
      ),
    ).rejects.toThrow(/disk full/);
    expect(sink.forensic).toEqual([]);
    expect(sink.logs.at(-1)).toMatch(
      /bulk FAILED at batch 2 \(rows 11–20\): disk full — rolled back 20 forensic/,
    );
  });

  it("a rollback that itself fails is logged and the original error still surfaces", async () => {
    const sink = memorySink({ batchRows: 10, gate: "Info" });
    sink.rollback = async () => {
      throw new Error("worker gone");
    };
    await expect(runVelociraptorBulk(sink, "c1", truncatedArray(30), baseOpts(), "forensic")).rejects.toThrow(
      /unterminated array element/,
    );
    expect(sink.logs.at(-1)).toMatch(/rollback FAILED: worker gone — the run's rows remain/);
  });

  it("the forensic entry rolls back when the final merge or save fails", async () => {
    const { ctx, stateStore } = await contextWithStore();
    const rows = Array.from({ length: 40 }, (_, i) => mftRow(i + 1));
    rows[10] = mftRow(11, PROMOTED_PATH);
    const sink = memorySink({ batchRows: 10, promote: (e) => (e.path ?? "").endsWith("dropper.ps1") });
    sink.appendForensic = (caseId, events) => stateStore.appendForensicEvents(caseId, events);
    sink.beginRun = () => stateStore.importRowIdMark("c1");
    sink.rollback = async (caseId, run) => {
      sink.rollbacks.push(run);
      const undone = await stateStore.rollbackImportBatch(caseId, run.fence, run.importBatchId, [
        "forensicTimeline",
      ]);
      sink.superRows = [];
      return { forensic: undone.forensicTimeline.deleted, super: 0, tags: 0 };
    };
    ctx.mergeWithAliases = async () => {
      throw new Error("merge exploded");
    };
    await expect(importVelociraptorBulk(ctx, sink, "c1", artifactMap(rows), baseOpts())).rejects.toThrow(
      /merge exploded/,
    );
    expect(sink.rollbacks).toHaveLength(1);
    expect((await stateStore.load("c1")).forensicTimeline).toEqual([]);
    expect(sink.logs.at(-1)).toMatch(
      /bulk FAILED after the batches, in the final merge: merge exploded — rolled back 1 forensic/,
    );
  });
});

describe("bulk path switches", () => {
  it("applies only with a sink and at or above the byte threshold", () => {
    const sink = memorySink({ minBytes: 100 });
    expect(bulkPathApplies(undefined, "x".repeat(1000))).toBe(false);
    expect(bulkPathApplies(sink, "x".repeat(99))).toBe(false);
    expect(bulkPathApplies(sink, "x".repeat(100))).toBe(true);
  });

  it("reads the two settings with safe defaults", () => {
    expect(readBulkBatchRows({})).toBe(5000);
    expect(readBulkBatchRows({ DFIR_IMPORT_BATCH_ROWS: "250" })).toBe(250);
    expect(readBulkBatchRows({ DFIR_IMPORT_BATCH_ROWS: "0" })).toBe(5000);
    expect(readBulkBatchRows({ DFIR_IMPORT_BATCH_ROWS: "abc" })).toBe(5000);
    expect(readBulkMinBytes({})).toBe(8 * 1024 * 1024);
    expect(readBulkMinBytes({ DFIR_IMPORT_BULK_MIN_MB: "0" })).toBe(0);
    expect(readBulkMinBytes({ DFIR_IMPORT_BULK_MIN_MB: "1.5" })).toBe(1.5 * 1024 * 1024);
    expect(readBulkMinBytes({ DFIR_IMPORT_BULK_MIN_MB: "-1" })).toBe(8 * 1024 * 1024);
  });
});

describe("memory bound", () => {
  it("holds well under the whole-file expansion for 60k MFT rows", async () => {
    // Deliberately loose: the whole-file path would hold ~60k rows + 60k mapped + 60k grouped +
    // 60k forensic copies at once (hundreds of MB); a batched run of 5000 must stay far below.
    const rows = Array.from({ length: 60_000 }, (_, i) => mftRow(i + 1));
    const text = artifactMap(rows);
    rows.length = 0;
    const sink = memorySink({ batchRows: 5000, taggerOff: true });
    sink.appendSuper = async (_c, events) => events.length; // do not retain: the store would not either
    global.gc?.();
    const before = process.memoryUsage().heapUsed;
    let peak = before;
    const origLog = sink.log;
    sink.log = (m) => {
      peak = Math.max(peak, process.memoryUsage().heapUsed);
      origLog(m);
    };
    const res = await runVelociraptorBulk(sink, "c1", text, baseOpts(), "forensic");
    expect(res!.rows).toBe(60_000);
    expect(res!.batches).toBe(12);
    expect(peak - before).toBeLessThan(300 * 1024 * 1024);
  }, 60_000);
});
