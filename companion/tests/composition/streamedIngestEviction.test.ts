import { describe, expect, it } from "vitest";
import { mkdtemp, open, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createImportIngest, type ImportIngestDeps } from "../../src/composition/importIngest.js";
import { ImportLock } from "../../src/analysis/importLock.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { ForensicGateControlStore } from "../../src/analysis/forensicGateControl.js";
import { SuperTimelineStore, type SuperEviction } from "../../src/analysis/superTimelineStore.js";
import { buildRuntimePipeline } from "../../src/server.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { BulkImportSink } from "../../src/analysis/ingest/velociraptorBulk.js";

// #2831: the imports that never pass through the Import button — the drop folder, /push, the MCP
// ingest, the Velociraptor monitors — go through ingestStreamed or ingestDiskFile. A large
// Velociraptor file there is imported in batches, and the rows its cap passes push out of the
// super-timeline must be on the import record like the Import button's (#2816), also when the
// import kept nothing in the forensic timeline. Every fixture is synthetic.

const DROPPED: SuperEviction = {
  count: 14,
  setAside: 2,
  from: "2025-01-01T00:00:00Z",
  to: "2025-01-02T00:00:00Z",
};

// Letters only: the MFT aggregation key folds digits.
const letters = (n: number): string => n.toString(26).replace(/[0-9]/g, (d) => "qrstuvwxyz"[Number(d)]);

// One $MFT entry with one distinct time and path: exactly one Info event per row.
function mftRow(n: number): Record<string, unknown> {
  const t = new Date(Date.UTC(2026, 0, 1, 0, 0, n)).toISOString();
  const path = `\\\\.\\C:\\Users\\u\\${letters(n)}.txt`;
  return {
    EntryNumber: n,
    InUse: true,
    OSPath: path,
    FileName: `${letters(n)}.txt`,
    FileSize: 10,
    IsDir: false,
    Created0x10: t,
    LastModified0x10: t,
    LastRecordChange0x10: t,
    LastAccess0x10: t,
  };
}
const mftRows = (count: number, from = 1) => Array.from({ length: count }, (_, i) => mftRow(from + i));
const NAME = "velo-flow_Windows.NTFS.MFT.json";

/** A batched sink that keeps nothing forensic (every row is below the gate) and reports DROPPED at commit. */
function droppingSink(): BulkImportSink & { superRows: number } {
  const sink = {
    minBytes: 1, // every Velociraptor import is "large"
    batchRows: 2000,
    superRows: 0,
    beginRun: async () => 0,
    rollback: async () => ({ forensic: 0, super: 0, tags: 0 }),
    appendForensic: async (_c: string, events: ForensicEvent[]) => events.length,
    appendSuper: async (_c: string, events: ForensicEvent[]) => {
      sink.superRows += events.length;
      return { retained: events.length, evicted: { count: 0, setAside: 0, from: "", to: "" } };
    },
    commitSuperCap: async () => DROPPED,
    openTagger: async () => null,
    forensicMinSeverity: async () => "Critical" as const,
    log: () => {},
  };
  return sink;
}

async function world(opts: { sink?: BulkImportSink; superCap?: number } = {}) {
  const root = await mkdtemp(join(tmpdir(), "dfir-streamed-evict-"));
  const store = new CaseStore(join(root, "cases"));
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(store);
  const importMetaStore = new ImportMetaStore(store);
  const superTimelineStore = new SuperTimelineStore(store, opts.superCap);
  const forensicGateControlStore = new ForensicGateControlStore(store); // the gate: Info leaves at the settle
  const bulk = opts.sink ? { bulkImportSink: opts.sink } : {};
  const pipeline = buildRuntimePipeline({
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    ...bulk,
  });
  const ingest = createImportIngest({
    store,
    options: { pipeline, stateStore, importMetaStore, superTimelineStore, forensicGateControlStore, ...bulk },
    runStateExclusive: async (_caseId: string, fn: () => Promise<unknown>) => fn(),
    importLock: new ImportLock(),
    recordImporterRun: () => {},
    redactErr: (err: unknown) => String((err as Error).message ?? err),
    autoTagImported: async () => {},
    getControl: async () => ({ enabled: true }),
    applyWhitelistToCase: async () => ({ matched: 0, added: 0 }),
    applyNsrlToCase: async () => ({ matchedIocs: 0, matchedEvents: 0, added: 0 }),
    applyDeobfuscationToCase: async () => ({ deobfuscated: 0, newIocs: 0, reanalyzed: 0 }),
    resynthesizeInBackground: () => {},
  } as unknown as ImportIngestDeps);
  return { root, ingest, stateStore, importMetaStore, superTimelineStore };
}

describe("streamed imports — the rows a batched import pushed out are on the import record (#2831)", () => {
  it("ingestStreamed (/push, MCP, monitors, a drop file read whole): recorded, with nothing forensic kept", async () => {
    const sink = droppingSink();
    const w = await world({ sink });
    const text = JSON.stringify({ "Windows.NTFS.MFT": mftRows(12) });

    const r = await w.ingest.ingestStreamed("c1", "velociraptor", text, NAME);

    expect(sink.superRows).toBeGreaterThan(0); // the batched path ran
    expect(r.addedEvents).toBe(0);
    const meta = await w.importMetaStore.load("c1");
    expect(meta.lastImportFile).toBe(r.storedName);
    expect(meta.addedCount).toBe(0);
    expect(meta.superTimelineEvicted).toEqual(DROPPED);
  });

  it("ingestDiskFile (a drop file streamed from disk): recorded, with nothing forensic kept", async () => {
    const sink = droppingSink();
    const w = await world({ sink });
    const src = join(w.root, NAME);
    await writeFile(
      src,
      mftRows(12)
        .map((row) => JSON.stringify(row))
        .join("\n") + "\n",
      "utf8",
    );
    const handle = await open(src, "r");
    let r;
    try {
      r = await w.ingest.ingestDiskFile("c1", "velociraptor", handle, NAME, undefined);
    } finally {
      await handle.close();
    }

    expect(sink.superRows).toBeGreaterThan(0);
    const meta = await w.importMetaStore.load("c1");
    expect(meta.lastImportFile).toBe(r.storedName);
    expect(meta.addedCount).toBe(0);
    expect(meta.superTimelineEvicted).toEqual(DROPPED);
  });

  // The quiet-poll rule: a monitor polls every 30 seconds, and an import that changed nothing must
  // not take over the import card or clear its "NEW since last import" marks.
  it("an import that changes nothing and pushes nothing out writes no record", async () => {
    const w = await world();
    const text = JSON.stringify({ "Windows.NTFS.MFT": mftRows(6) });
    const r = await w.ingest.ingestStreamed("c1", "velociraptor", text, NAME);
    expect(r.addedEvents).toBe(0);
    expect((await w.superTimelineStore.meta("c1")).rows).toBe(6);
    expect((await w.importMetaStore.load("c1")).lastImportedAt).toBe("");
  });

  // The narrow rule, pinned: only a BATCHED import's pushed-out rows open the record. A small import
  // read whole, whose settle pushes rows out of a full super-timeline, still writes none — on a
  // monitored case with a full super-timeline every quiet poll would otherwise take over the card.
  it("a small Info-only import whose settle pushes rows out still writes no record", async () => {
    const CAP = 5;
    const w = await world({ superCap: CAP });
    const append = w.superTimelineStore.appendReporting.bind(w.superTimelineStore);
    let pushedOut = 0;
    w.superTimelineStore.appendReporting = async (...args) => {
      const result = await append(...args);
      pushedOut += result.evicted.count;
      return result;
    };
    await w.ingest.ingestStreamed(
      "c1",
      "velociraptor",
      JSON.stringify({ "Windows.NTFS.MFT": mftRows(5) }),
      NAME,
    );
    expect(pushedOut).toBe(0);

    const text = JSON.stringify({ "Windows.NTFS.MFT": mftRows(4, 100) });
    const r = await w.ingest.ingestStreamed("c1", "velociraptor", text, NAME);

    expect(r.addedEvents).toBe(0);
    expect(pushedOut).toBe(4); // the settle's own append did push rows out
    expect((await w.superTimelineStore.meta("c1")).rows).toBe(CAP);
    expect((await w.importMetaStore.load("c1")).lastImportedAt).toBe("");
  });
});
