import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { mergeDelta } from "../../src/analysis/stateMerge.js";
import type { ImportContext } from "../../src/analysis/ingest/importContext.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import {
  createImportMemoryGuard,
  ImportMemoryRefusedError,
  type SectionMemoryCheck,
} from "../../src/analysis/importMemoryGuard.js";
import { ImportLock } from "../../src/analysis/importLock.js";
import { buildBulkImportSink } from "../../src/composition/bulkImportSink.js";
import type { StateStore as StateStoreApi } from "../../src/analysis/stateStore.js";
import type { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import {
  importVelociraptorBulk,
  runVelociraptorBulk,
  type BulkImportSink,
  type BulkRunHandle,
  type BulkRunSummary,
} from "../../src/analysis/ingest/velociraptorBulk.js";

// The bulk importer re-checks the import memory guard as it keeps rows (#2812). Its admission was
// capped by DFIR_MAX_EVENTS, but this path keeps every graded row — so a file whose rows are all
// graded can double the case, and the merge + settle after the batches ran the server out of memory.
// Every fixture is synthetic; the memory reading is stubbed, so no test needs a large file.

const IMPORTED_AT = "2026-09-20T07:00:00.000Z";
const GB = 1024 ** 3;

function name(n: number): string {
  return n.toString(26).replace(/[0-9]/g, (d) => "qrstuvwxyz"[Number(d)]);
}

// One $MFT entry → one Info event; the case gate "Info" keeps every one, so every row is "graded".
function mftRow(n: number) {
  const path = `\\\\.\\C:\\Users\\u\\${name(n)}.txt`;
  const t = new Date(Date.UTC(2026, 0, 1, 0, 0, n)).toISOString();
  return {
    EntryNumber: n,
    InUse: true,
    OSPath: path,
    FileName: `${name(n)}.txt`,
    FileSize: 10,
    IsDir: false,
    Created0x10: t,
    LastModified0x10: t,
    LastRecordChange0x10: t,
    LastAccess0x10: t,
  };
}

const mftMap = (n: number): string =>
  JSON.stringify({ "Windows.NTFS.MFT": Array.from({ length: n }, (_, i) => mftRow(i + 1)) });

interface MemorySink extends BulkImportSink {
  forensic: ForensicEvent[];
  superRows: ForensicEvent[];
  logs: string[];
  runs: BulkRunSummary[];
  rollbacks: BulkRunHandle[];
  checked: number[];
}

function memorySink(check?: (caseId: string) => Promise<SectionMemoryCheck | null>): MemorySink {
  const sink: MemorySink = {
    minBytes: 0,
    batchRows: 10,
    forensic: [],
    superRows: [],
    logs: [],
    runs: [],
    rollbacks: [],
    checked: [],
    async beginRun() {
      return 0;
    },
    async rollback(_caseId, run) {
      sink.rollbacks.push(run);
      const f = sink.forensic.length;
      const s = sink.superRows.length;
      sink.forensic = sink.forensic.filter((e) => e.importBatchId !== run.importBatchId);
      sink.superRows = sink.superRows.filter((e) => e.importBatchId !== run.importBatchId);
      return { forensic: f - sink.forensic.length, super: s - sink.superRows.length, tags: 0 };
    },
    async appendForensic(_caseId, events) {
      sink.forensic.push(...events);
      return events.length;
    },
    async appendSuper(_caseId, events) {
      sink.superRows.push(...events);
      return { retained: events.length, evicted: { count: 0, setAside: 0, from: "", to: "" } };
    },
    async openTagger() {
      return null;
    },
    async forensicMinSeverity() {
      return "Info";
    },
    log(msg) {
      sink.logs.push(msg);
    },
    async recordRun(_caseId, summary) {
      sink.runs.push(summary);
    },
  };
  if (check) {
    sink.openMemoryCheck = async (caseId) => {
      const inner = await check(caseId);
      return inner
        ? (added) => {
            sink.checked.push(added);
            inner(added);
          }
        : null;
    };
  }
  return sink;
}

const opts = { label: "0018_velo-flow_Windows.NTFS.MFT.json", idPrefix: "18", importedAt: IMPORTED_AT };
const refuseOver = (limit: number) => async (): Promise<SectionMemoryCheck> => (added) => {
  if (added > limit) throw new ImportMemoryRefusedError("Import refused to protect the server: synthetic");
};

async function contextWithStore() {
  const root = await mkdtemp(join(tmpdir(), "dfir-bulk-guard-"));
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

describe("runVelociraptorBulk — the memory guard's re-check (#2812)", () => {
  it("re-checks with the rows kept so far after every batch", async () => {
    const sink = memorySink(async () => () => {});
    const res = await runVelociraptorBulk(sink, "c1", mftMap(25), opts, "forensic");
    expect(res?.forensicKept).toBe(25);
    expect(sink.checked).toEqual([10, 20, 25]);
  });

  it("a refusal mid-run rolls the run back and surfaces the guard's own message", async () => {
    const sink = memorySink(refuseOver(15));
    await expect(runVelociraptorBulk(sink, "c1", mftMap(40), opts, "forensic")).rejects.toThrow(
      /^Import refused to protect the server/,
    );
    expect(sink.checked).toEqual([10, 20]); // stopped at the batch that crossed the limit
    expect(sink.rollbacks).toHaveLength(1);
    expect(sink.forensic).toEqual([]);
    expect(sink.superRows).toEqual([]);
    expect(sink.runs).toEqual([]);
    // Asked before batch 2 wrote anything: only batch 1's rows existed to roll back.
    expect(sink.logs.at(-1)).toMatch(
      /bulk FAILED at batch 2 \(rows 11–20\): Import refused to protect the server: synthetic — rolled back 10 forensic \/ 10 super row\(s\)/,
    );
  });

  it("a run that fits is unchanged by the check", async () => {
    const plain = memorySink();
    const checked = memorySink(refuseOver(1_000));
    const a = await runVelociraptorBulk(plain, "c1", mftMap(25), opts, "forensic");
    const b = await runVelociraptorBulk(checked, "c1", mftMap(25), opts, "forensic");
    expect(b?.forensicKept).toBe(a?.forensicKept);
    expect(b?.superAppended).toBe(a?.superAppended);
    expect(checked.forensic.map((e) => e.description)).toEqual(plain.forensic.map((e) => e.description));
    expect(checked.rollbacks).toEqual([]);
  });

  it("nothing to re-check (guard off, unsized section) means no refusal", async () => {
    const sink = memorySink(async () => null);
    const res = await runVelociraptorBulk(sink, "c1", mftMap(25), opts, "forensic");
    expect(res?.forensicKept).toBe(25);
    expect(sink.checked).toEqual([]);
  });

  it("a super-only run is never re-checked: it adds nothing to the forensic table", async () => {
    let opened = 0;
    const sink = memorySink(async () => {
      opened++;
      return () => {
        throw new ImportMemoryRefusedError("should not run");
      };
    });
    await runVelociraptorBulk(sink, "c1", mftMap(25), opts, "super-only");
    expect(opened).toBe(0);
  });
});

describe("importVelociraptorBulk — refused mid-run through the real guard (#2812)", () => {
  // The issue's shape, scaled down: a case of 70,000 events is admitted for 70,000 + 2,000 (the
  // DFIR_MAX_EVENTS cap), and the server can take about 73,000. The import keeps every row it reads.
  const probe = () => ({ availableBytes: 73_000 * 128 * 1024, rssBytes: 0, heapLimitBytes: 64 * GB });

  async function run(rows: number, env?: string) {
    const saved = process.env.DFIR_IMPORT_MEMORY_GUARD;
    if (env === undefined) delete process.env.DFIR_IMPORT_MEMORY_GUARD;
    else process.env.DFIR_IMPORT_MEMORY_GUARD = env;
    try {
      const { ctx, stateStore } = await contextWithStore();
      const guard = createImportMemoryGuard({
        countEvents: async () => 70_000,
        probe,
        maxEvents: () => 2_000,
      });
      const sink = memorySink((caseId) => guard.openSectionCheck(caseId));
      sink.batchRows = 500;
      // The forensic table and its rollback are the real store's, so "unchanged" is checked on disk.
      sink.beginRun = (caseId) => stateStore.importRowIdMark(caseId);
      sink.appendForensic = (caseId, events) => stateStore.appendForensicEvents(caseId, events);
      sink.rollback = async (caseId, r) => {
        const undone = await stateStore.rollbackImportBatch(caseId, r.fence, r.importBatchId, [
          "forensicTimeline",
        ]);
        return { forensic: undone.forensicTimeline.deleted, super: 0, tags: 0 };
      };
      const lock = new ImportLock(guard);
      const outcome = await lock
        .runSized("c1", { incomingBytes: rows * 300 }, () =>
          importVelociraptorBulk(ctx, sink, "c1", mftMap(rows), opts),
        )
        .then(
          () => null,
          (e: unknown) => e,
        );
      return { outcome, state: await stateStore.load("c1"), guard, sink };
    } finally {
      if (saved === undefined) delete process.env.DFIR_IMPORT_MEMORY_GUARD;
      else process.env.DFIR_IMPORT_MEMORY_GUARD = saved;
    }
  }

  it("refuses once the kept rows outgrow the server, and the case is unchanged", async () => {
    const { outcome, state, guard } = await run(4_000);
    expect(outcome).toBeInstanceOf(ImportMemoryRefusedError);
    expect((outcome as Error).message).toMatch(
      /^Import refused to protect the server: this case holds 70,000 events, .*The file is saved in the case and nothing was changed\./,
    );
    expect(state.forensicTimeline).toEqual([]);
    expect(state.timeline).toEqual([]); // the final merge never ran: no import note
    expect(guard.reservedBytes()).toBe(0);
  });

  it("an import that fits imports as before", async () => {
    const { outcome, state } = await run(2_500);
    expect(outcome).toBeNull();
    expect(state.forensicTimeline.filter((e) => /^18e\d+$/.test(e.id))).toHaveLength(2_500);
  });

  it("with DFIR_IMPORT_MEMORY_GUARD=off nothing is refused", async () => {
    const { outcome, state } = await run(4_000, "off");
    expect(outcome).toBeNull();
    expect(state.forensicTimeline.filter((e) => /^18e\d+$/.test(e.id))).toHaveLength(4_000);
  });
});

describe("buildBulkImportSink — the guard's re-check is wired through (#2812)", () => {
  const base = {
    stateStore: {} as StateStoreApi,
    superTimelineStore: {} as SuperTimelineStore,
    log: () => {},
  };

  it("forwards to the guard's section check when a guard is given", async () => {
    const asked: string[] = [];
    const check: SectionMemoryCheck = () => {};
    const sink = buildBulkImportSink({
      ...base,
      importMemory: {
        openSectionCheck: async (caseId) => {
          asked.push(caseId);
          return check;
        },
      },
    });
    expect(await sink?.openMemoryCheck?.("c9")).toBe(check);
    expect(asked).toEqual(["c9"]);
  });

  it("has no re-check without a guard", () => {
    expect(buildBulkImportSink(base)?.openMemoryCheck).toBeUndefined();
  });
});
