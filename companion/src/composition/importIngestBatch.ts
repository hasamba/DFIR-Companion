/**
 * A drop-folder batch (#2540): several small gzip CloudTrail files imported as ONE merge-and-settle
 * step. The plan (which files, in which order) is composition/dropBatchPlan.ts; the shared tail is
 * composition/importIngestBatchTail.ts; this file is the import section in between.
 *
 * PER FILE, EXACTLY AS ONE AT A TIME (composition/importIngestDisk.ts): the file is opened with
 * O_NOFOLLOW and re-sniffed from that handle (it must still be a small gzip of the batch's kind),
 * copied and hashed from the same handle into its own stored evidence file — its own custody record,
 * `imports.jsonl` line, sequence number and row ids — then parsed and, when it adds anything,
 * merged, before the next file starts. The stream importer's cross-upload passes (precursor
 * promotion, the dedup ledger) read the case per file, so the order and the per-file merge are what
 * keep the forensic timeline equal to one-at-a-time. What a file would have done AFTER its merge is
 * collected through the cloud import's batch hooks (CloudBatchHooks) and done once in the tail.
 *
 * SUPER-TIMELINE ROOM. A file's streamed rows are budgeted by the room left in the super-timeline.
 * One-at-a-time, an earlier file's settle has already dual-written its forensic rows; in a batch it
 * has not. So before each file the batch requires room for a whole per-import budget on top of the
 * rows it has merged but not yet dual-written: then both ways give every file the full budget and
 * nothing reaches the cap. When that fails the batch ends there and the rest import one at a time.
 *
 * FALLBACK. Anything that fails before the first file touches the case — admission, the import
 * memory guard sizing the section, the baseline snapshot — hands every file back to be imported one
 * by one through today's path (after the section is released). Once a file has started, a failure
 * is that file's alone; the tail's failures are warnings (see the tail's header).
 */
import type { FileHandle } from "node:fs/promises";
import { basename } from "node:path";
import { withIngestAdmission, statusFromStore } from "../analysis/caseIngestAdmission.js";
import { createImportDebugRecorder, type ImportDebugRecorder } from "../analysis/importDebug.js";
import {
  captureImportBaseline,
  releaseImportBaseline,
  type ImportBaseline,
} from "../analysis/importBaseline.js";
import type { ImporterRegistry } from "../analysis/importerStore.js";
import { streamProvider, type StreamKind } from "../analysis/ingest/cloudStreamProviders.js";
import type { CloudBatchHooks } from "../analysis/ingest/cloudStreamImport.js";
import { SUPER_ROWS_PER_IMPORT_MAX } from "../analysis/cloudStreamLimits.js";
import { DEFAULT_SUPER_MAX } from "../analysis/superTimelineStore.js";
import { describeCloudStreamDisclosure } from "../analysis/cloudStreamDisclosure.js";
import { getServerLogger } from "../logging/serverLogger.js";
import { openNoFollow } from "../storage/noFollowRead.js";
import { sniffImportFileHeadDetail } from "../routes/importFileHead.js";
import { consumeCloudStreamDisclosure, runDiskImport } from "../routes/importCloudStream.js";
import type { DiskIngestDeps } from "./importIngestDisk.js";
import { DROP_BATCH_FILE_MAX_BYTES } from "./dropBatchPlan.js";
import { createDropBatchMarker, type DropBatchMarker } from "./dropBatchMarker.js";
import { runBatchTail, type BatchCollect, type BatchTailDeps } from "./importIngestBatchTail.js";

/** Super rows held for the batch's one tagger call before an interim flush (bounds memory). */
export const BATCH_SUPER_TAG_FLUSH_ROWS = 20_000;

export interface DiskBatchDeps extends DiskIngestDeps {
  /** Test seam; production writes `state/drop-batch-pending.jsonl` (composition/dropBatchMarker.ts). */
  marker?: DropBatchMarker;
  resolveImportKind: (filename: string, text: string, debug?: ImportDebugRecorder) => string;
  importerRegistry: () => ImporterRegistry;
  pushImportCheckpoint: BatchTailDeps["pushImportCheckpoint"];
}

export interface BatchFile {
  relpath: string;
  fullPath: string;
}

export interface BatchFileResult {
  relpath: string;
  ok: boolean;
  reason?: string;
  warning?: string;
  /** A failed file's error and recorder, for the sweep's import-failure record. */
  error?: unknown;
  debug?: ImportDebugRecorder;
}

export interface DiskBatchResult {
  /** One per file the batch took, in order. */
  results: BatchFileResult[];
  /** The files it did not take, in order, from the first one it stopped at. */
  rest: BatchFile[];
  /** Why it stopped early: a file no longer fits the batch, the super-timeline is near its cap, or the batch never started. */
  stop?: "mismatch" | "capacity" | "fallback";
}

export interface DropBatchRequest {
  kind: string;
  assetHost: string;
  files: BatchFile[];
  /** Bytes on disk, summed — sizes the import memory guard. */
  bytes: number;
}

export type IngestDiskBatch = (
  caseId: string,
  batch: DropBatchRequest,
  onFileDone: (relpath: string) => void,
) => Promise<DiskBatchResult>;

export interface DiskBatchIngest {
  ingestDiskBatch: IngestDiskBatch;
  /** Settle the rows of a batch a crash interrupted (composition/dropBatchMarker.ts). */
  recoverDropBatch: (caseId: string) => Promise<void>;
}

/** One file's step: it ran (and reached the crash marker, or not), or the batch must stop before it. */
type FileStep =
  { stop: "mismatch" | "fallback" } | { stop?: undefined; result: BatchFileResult; marked: boolean };

/** One file's hook output; it joins the batch only once that file's import succeeded. */
interface FileHookOutput {
  empties: BatchCollect["empties"];
  folds: BatchCollect["folds"];
  rows: number[];
}

const sum = (xs: readonly number[]): number => xs.reduce((n, x) => n + x, 0);

/** One file of the batch past its crash-marker line, with what it reports into. */
interface StoredFile {
  caseId: string;
  batch: DropBatchRequest;
  file: BatchFile;
  handle: FileHandle;
  collect: BatchCollect;
  owe: (rows: number) => void;
  debug: ImportDebugRecorder;
  own: FileHookOutput;
  seq: number;
  storedName: string;
}

export function createDiskBatchIngest(deps: DiskBatchDeps): DiskBatchIngest {
  const { store, options, importLock } = deps;
  const marker = deps.marker ?? createDropBatchMarker(store);
  const diskCtx = {
    options,
    store,
    runStateExclusive: deps.runStateExclusive,
    serverLogger: getServerLogger(),
    demoteForensic: deps.demoteForensic,
  };
  const tailDeps: BatchTailDeps = {
    runCtx: {
      options,
      store,
      runStateExclusive: deps.runStateExclusive,
      importerRegistry: deps.importerRegistry,
    },
    settleDeps: deps.settleDeps,
    pushImportCheckpoint: deps.pushImportCheckpoint,
  };

  async function admitted(caseId: string, batch: DropBatchRequest, onFileDone: (r: string) => void) {
    const stateStore = options.stateStore;
    if (!options.pipeline || !stateStore) return fallback(batch, "no pipeline or state store");
    // An earlier batch's rows still wait for their settle: never write over (or clear) its marker.
    const pending = await marker.read(caseId).catch(() => ["unreadable"]);
    if (pending) return fallback(batch, "an earlier batch is not settled yet");
    let outcome: DiskBatchResult | null = null;
    let baselineTaken = false;
    try {
      await importLock.runSized(caseId, { incomingBytes: batch.bytes }, async () => {
        const baseline = await captureImportBaseline(stateStore, caseId);
        baselineTaken = true;
        try {
          outcome = await section(caseId, batch, baseline, onFileDone);
        } finally {
          await releaseImportBaseline(stateStore, baseline);
        }
      });
    } catch (err) {
      if (baselineTaken) throw new BatchStartedError(err); // never import a started file a second time
      return fallback(batch, err instanceof Error ? err.message : String(err));
    }
    const done = outcome as DiskBatchResult | null;
    // Never thrown out of here: past this point every file has run, and a throw would reach the
    // fallback below and import the whole batch a second time.
    if (done?.results.some((r) => r.ok))
      await deps.afterImport(caseId).catch((e: unknown) =>
        getServerLogger().warn(`[drop] ${caseId}: post-import marks failed — ${(e as Error).message}`, {
          caseId,
        }),
      );
    return done ?? fallback(batch, "the import section did not run");
  }

  function fallback(batch: DropBatchRequest, reason: string): DiskBatchResult {
    getServerLogger().info(
      `[drop] batch of ${batch.files.length} not started (${reason}) — importing one by one`,
    );
    return { results: [], rest: batch.files, stop: "fallback" };
  }

  async function section(
    caseId: string,
    batch: DropBatchRequest,
    baseline: ImportBaseline,
    onFileDone: (relpath: string) => void,
  ): Promise<DiskBatchResult> {
    const kind = batch.kind as StreamKind;
    const startedAt = new Date().toISOString();
    const collect: BatchCollect = { imported: [], empties: [], folds: [], superPending: [] };
    const results: BatchFileResult[] = [];
    let reserve = 0; // forensic rows merged, not yet dual-written by the settle
    let stop: DiskBatchResult["stop"];
    let marked = false; // a file of this batch is in the crash marker
    let settleFailed = false;
    let i = 0;
    options.onImport?.(caseId);
    for (; i < batch.files.length; i++) {
      if (!(await roomFor(caseId, reserve))) {
        stop = "capacity";
        break;
      }
      const file = batch.files[i];
      status(caseId, `drop batch: ${kind} file ${i + 1}/${batch.files.length}`);
      const step = await importOne(caseId, batch, file, collect, (n) => (reserve += n));
      if (step.stop) {
        stop = step.stop;
        break;
      }
      marked ||= step.marked;
      results.push(step.result);
      onFileDone(file.relpath);
    }
    options.onAiStatus?.(caseId, { status: "idle", at: new Date().toISOString() });
    if (collect.imported.length) {
      const source = streamProvider(kind).source;
      const tail = await runBatchTail(tailDeps, {
        caseId,
        kind,
        source,
        label: `${source} drop batch (${collect.imported.length} files)`, // the Undo entry names the count
        assetHost: batch.assetHost,
        startedAt,
        baseline,
        collect,
      });
      if (tail.warnings.length) addWarnings(results, tail.warnings.join(" "));
      settleFailed = tail.settleFailed;
    }
    // Kept when the settle failed, or when a file that reached its import was never settled (none
    // imported): the next sweep's recovery settles those rows before any other batch runs.
    if (marked && (settleFailed || !collect.imported.length)) {
      getServerLogger().warn(`[drop] ${caseId}: batch not settled — the next sweep settles its rows`, {
        caseId,
      });
    } else await marker.clear(caseId).catch(() => undefined);
    logBatch(caseId, batch, results, startedAt);
    return { results, rest: batch.files.slice(i), ...(stop ? { stop } : {}) };
  }

  /** Room for a whole per-import budget on top of what the batch still owes the super-timeline. */
  async function roomFor(caseId: string, reserve: number): Promise<boolean> {
    const superStore = options.superTimelineStore;
    if (!superStore) return true;
    const cap = Number(process.env.DFIR_SUPERTIMELINE_MAX) || DEFAULT_SUPER_MAX;
    // Unreadable room is no room: the batch ends here and the rest import one at a time.
    const rows = await superStore.meta(caseId).then(
      (m) => m.rows,
      () => Infinity,
    );
    return rows + reserve + SUPER_ROWS_PER_IMPORT_MAX <= cap;
  }

  function status(caseId: string, detail: string): void {
    options.onAiStatus?.(caseId, {
      status: "analyzing",
      phase: "extracting",
      at: new Date().toISOString(),
      detail,
    });
  }

  /** One file: re-sniff, store, parse + merge. A mismatch hands the file back untouched. */
  async function importOne(
    caseId: string,
    batch: DropBatchRequest,
    file: BatchFile,
    collect: BatchCollect,
    owe: (rows: number) => void,
  ): Promise<FileStep> {
    const debug = createImportDebugRecorder();
    const handle = await openNoFollow(file.fullPath).catch(() => null);
    if (!handle) return { stop: "mismatch" }; // the solo path names the refusal (link, gone, …)
    try {
      if (!(await stillFits(handle, batch.kind, basename(file.relpath), debug))) return { stop: "mismatch" };
      return await storeAndImport(caseId, batch, file, handle, collect, owe, debug);
    } finally {
      await handle.close().catch(() => undefined);
    }
  }

  async function stillFits(handle: FileHandle, kind: string, name: string, debug: ImportDebugRecorder) {
    try {
      const { size } = await handle.stat();
      const { sample, gzip } = await sniffImportFileHeadDetail(handle);
      return (
        gzip &&
        size <= DROP_BATCH_FILE_MAX_BYTES &&
        deps.resolveImportKind(name.replace(/\.gz$/i, ""), sample, debug) === kind
      );
    } catch {
      return false;
    }
  }

  async function storeAndImport(
    caseId: string,
    batch: DropBatchRequest,
    file: BatchFile,
    handle: FileHandle,
    collect: BatchCollect,
    owe: (rows: number) => void,
    debug: ImportDebugRecorder,
  ): Promise<FileStep> {
    const name = basename(file.relpath);
    // This file's hook output joins the batch only once its import succeeded.
    const own: FileHookOutput = { empties: [], folds: [], rows: [] };
    let storedName: string;
    let seq: number;
    try {
      seq = await store.nextImportSeq(caseId);
      const safe = name.replace(/[^\w.\-]+/g, "_").slice(0, 80) || "import.dat";
      storedName = `${String(seq).padStart(4, "0")}_${safe}`;
      // The crash marker FIRST: a file whose settle is deferred must be recoverable, so a marker that
      // cannot be written ends the batch before this file touches the case (one by one from here).
      await marker.add(caseId, storedName);
    } catch (e) {
      getServerLogger().warn(`[drop] ${caseId}: batch stopped — ${(e as Error).message}`, { caseId });
      return { stop: "fallback" };
    }
    const f: StoredFile = { caseId, batch, file, handle, collect, owe, debug, own, seq, storedName };
    return { result: await importStored(f), marked: true };
  }

  /** Copy, record and import one file whose crash-marker line is written. */
  async function importStored(f: StoredFile): Promise<BatchFileResult> {
    const { caseId, batch, file, handle, collect, owe, debug, own, seq, storedName } = f;
    const name = basename(file.relpath);
    try {
      const importedAt = new Date().toISOString();
      const saved = await store.saveImportFromHandle(caseId, storedName, handle);
      await store.appendImport(caseId, {
        caseId,
        sequenceNumber: seq,
        importedAt,
        filename: storedName,
        originalName: name,
        rows: 0,
        bytes: saved.bytes,
      });
      const hooks = batchHooks(caseId, storedName, own, collect);
      await runDiskImport(diskCtx, batch.kind, caseId, saved.path, storedName, {
        label: storedName,
        idPrefix: `${seq}`,
        importedAt,
        debug,
        cloudBatch: hooks,
        ...(batch.assetHost ? { assetHost: batch.assetHost } : {}),
      });
      const disclosure = consumeCloudStreamDisclosure(caseId, storedName);
      collect.imported.push({ relpath: file.relpath, storedName, disclosure });
      collect.empties.push(...own.empties);
      collect.folds.push(...own.folds);
      owe(sum(own.rows));
      const sentences = disclosure ? describeCloudStreamDisclosure(disclosure) : [];
      return {
        relpath: file.relpath,
        ok: true,
        ...(sentences.length ? { warning: sentences.join(" ") } : {}),
      };
    } catch (err) {
      owe(sum(own.rows)); // a merge that failed after committing still owes its rows (upper bound)
      return {
        relpath: file.relpath,
        ok: false,
        reason: (err as Error)?.message ?? String(err),
        error: err,
        debug,
      };
    }
  }

  function batchHooks(
    caseId: string,
    storedName: string,
    own: FileHookOutput,
    collect: BatchCollect,
  ): CloudBatchHooks {
    return {
      emptyNote: ({ records }) => own.empties.push({ storedName, records }),
      deltaRows: (rows) => own.rows.push(rows),
      folds: (coverage, weaknesses, coverageStore) => {
        own.folds.push({ coverage, weaknesses, at: new Date().toISOString(), coverageStore });
      },
      superRows: async (rows) => {
        collect.superPending.push(...rows);
        if (collect.superPending.length < BATCH_SUPER_TAG_FLUSH_ROWS) return;
        const tag = deps.settleDeps.autoTagImported;
        await tag(caseId, collect.superPending.splice(0)).catch(() => undefined);
      },
    };
  }

  async function recoverDropBatch(caseId: string): Promise<void> {
    const labels = await marker.read(caseId);
    if (!labels) return;
    await importLock.runExclusive(caseId, async () => {
      const stateStore = options.stateStore;
      if (stateStore && labels.length) {
        const named = new Set(labels);
        const state = await stateStore.load(caseId);
        const rows = state.forensicTimeline.filter((e) => e.sourceScreenshots.some((s) => named.has(s)));
        if (rows.length) {
          await options.superTimelineStore?.appendReporting(caseId, rows); // dedups by id
          await deps.settleDeps.autoTagImported(caseId, rows);
        }
        await deps.demoteForensic(caseId);
        getServerLogger().warn(
          `[drop] ${caseId}: settled ${rows.length} row(s) of an interrupted drop batch (${labels.length} file(s))`,
          { caseId },
        );
      }
      await marker.clear(caseId);
    });
  }

  const statusOf = statusFromStore(store);
  return {
    ingestDiskBatch: (caseId, batch, onFileDone) =>
      withIngestAdmission(store.casesRoot, caseId, () => admitted(caseId, batch, onFileDone), statusOf).catch(
        (err: unknown) => {
          // Refused before anything ran (an archive holds the case, …): one by one, as today.
          if (err instanceof BatchStartedError) throw err.original;
          return fallback(batch, err instanceof Error ? err.message : String(err));
        },
      ),
    recoverDropBatch,
  };
}

/** A failure after a file of the batch started: it must propagate, never fall back. */
class BatchStartedError extends Error {
  constructor(readonly original: unknown) {
    super(original instanceof Error ? original.message : String(original));
  }
}

function addWarnings(results: BatchFileResult[], text: string): void {
  for (const r of results) if (r.ok) r.warning = r.warning ? `${r.warning} ${text}` : text;
}

function logBatch(
  caseId: string,
  batch: DropBatchRequest,
  results: BatchFileResult[],
  startedAt: string,
): void {
  const ok = results.filter((r) => r.ok).length;
  const ms = Date.now() - Date.parse(startedAt);
  getServerLogger().info(
    `[drop] ${caseId}: batch of ${batch.files.length} ${batch.kind} file(s) — ${ok} imported, ${results.length - ok} failed, ${batch.files.length - results.length} handed back, in ${(ms / 1000).toFixed(2)} s`,
    { caseId },
  );
}
