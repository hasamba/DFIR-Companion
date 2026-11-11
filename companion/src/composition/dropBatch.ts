/**
 * The drop-folder sweep's work loop (#2540): the ready files in one order (sorted by relpath), as
 * batches of small same-importer files (composition/dropBatchPlan.ts → importIngestBatch.ts) and
 * single files (composition/dropFolder.ts `processDropFile`, up to DROP_CONCURRENCY at once), and
 * every file's outcome recorded the same way whichever path imported it: one move to `_processed/`
 * or `_failed/`, one drop-log entry, one Jobs-row progress tick.
 *
 * Lifted out of dropFolder.ts, which sits at the 800-line limit.
 */
import { join } from "node:path";
import type { FileHandle } from "node:fs/promises";
import type { DropFailure, PendingRawInput } from "../analysis/dropStatus.js";
import type { DropFileStat } from "../analysis/dropScan.js";
import { stuckMoveNote } from "../analysis/dropScan.js";
import { assetHostFromDropRelpath } from "../analysis/assetHost.js";
import { isGzipMagic } from "../analysis/cloudStreamReader.js";
import type { ImportDebugRecorder } from "../analysis/importDebug.js";
import { logLine } from "../logging/serverLogger.js";
import { openNoFollow } from "../storage/noFollowRead.js";
import { sniffImportFileHeadDetail } from "../routes/importFileHead.js";
import { joinReasons, type ProcessedVersion } from "./dropStuck.js";
import {
  DROP_BATCH_FILE_MAX_BYTES,
  DROP_BATCH_KINDS,
  planDropWork,
  sortByRelpath,
  type DropSniff,
  type DropWorkItem,
} from "./dropBatchPlan.js";
import type { BatchFileResult, DiskBatchIngest } from "./importIngestBatch.js";

/** Single files imported at once (imports still serialize on the case's import lock). */
export const DROP_CONCURRENCY = 4;

/** What one file's import told the sweep (composition/dropFolder.ts `processDropFile`). */
export interface DropOutcome {
  ok: boolean;
  reason?: string;
  pending?: PendingRawInput;
  submitted?: string;
  warning?: string;
}

export interface SweepTally {
  imported: string[];
  submitted: { relpath: string; reason: string }[];
  failed: DropFailure[];
  warned: DropFailure[];
  pendingRawInputs: PendingRawInput[];
}

export interface DropSweepDeps {
  caseId: string;
  dropDir: string;
  processFile: (file: DropFileStat) => Promise<DropOutcome>;
  moveDropFile: (
    dropDir: string,
    relpath: string,
    ok: boolean,
    processed?: ProcessedVersion,
  ) => Promise<void>;
  /** The file left the watched area: forget its settle memory and its PENDING mark. */
  forget: (relpath: string) => void;
  /** One Jobs-row tick: files done / total. */
  progress: (relpath: string) => void;
  resolveImportKind: (filename: string, text: string, debug?: ImportDebugRecorder) => string;
  recordImportFailure: (name: string, err: unknown, debug?: ImportDebugRecorder) => void;
  /** Absent in wirings without the batch path (tests): every file imports on its own. */
  dropBatch?: DiskBatchIngest;
}

/** Import `ready` in relpath order, batching what may batch; every file's outcome is recorded. */
export async function runDropSweep(ready: readonly DropFileStat[], d: DropSweepDeps): Promise<SweepTally> {
  const tally: SweepTally = { imported: [], submitted: [], failed: [], warned: [], pendingRawInputs: [] };
  const ordered = sortByRelpath(ready);
  const sniffs = d.dropBatch ? await sniffAll(ordered, d) : new Map<string, DropSniff>();
  let work: DropWorkItem[] = planDropWork(ordered, sniffs);
  let batching = !!d.dropBatch;
  while (work.length) {
    const head = work[0];
    if (head.type === "solo" || !batching || !d.dropBatch) {
      const segment: DropFileStat[] = [];
      while (work.length && (work[0].type === "solo" || !batching)) {
        const item = work.shift()!;
        segment.push(...(item.type === "solo" ? [item.file] : item.files));
      }
      await runSolos(segment, d, tally);
      continue;
    }
    work.shift();
    if (head.type !== "batch") continue;
    const stats = new Map(head.files.map((f) => [f.relpath, f]));
    const r = await d.dropBatch.ingestDiskBatch(
      d.caseId,
      {
        kind: head.kind,
        assetHost: head.assetHost,
        files: head.files.map((f) => ({ relpath: f.relpath, fullPath: join(d.dropDir, f.relpath) })),
        bytes: head.files.reduce((n, f) => n + f.size, 0),
      },
      d.progress,
    );
    for (const res of r.results) await recordBatchResult(stats.get(res.relpath)!, res, d, tally);
    const rest = r.rest.map((f) => stats.get(f.relpath)!);
    if (!rest.length) continue;
    if (r.stop === "mismatch") {
      // The file that no longer fits imports on its own, in place; the rest is planned again.
      work = [{ type: "solo", file: rest[0] }, ...planDropWork(rest.slice(1), sniffs), ...work];
    } else {
      batching = false; // near the super-timeline cap, or the batch could not start: one by one
      work = [...rest.map((file): DropWorkItem => ({ type: "solo", file })), ...work];
    }
  }
  return tally;
}

/** The head sniff of every file that could batch (small, gzip magic) — advisory; the batch re-checks. */
async function sniffAll(files: readonly DropFileStat[], d: DropSweepDeps): Promise<Map<string, DropSniff>> {
  const out = new Map<string, DropSniff>();
  for (const f of files) {
    if (f.size > DROP_BATCH_FILE_MAX_BYTES) continue;
    const sniff = await sniffDropFile(join(d.dropDir, f.relpath), f.relpath, d.resolveImportKind);
    if (sniff && DROP_BATCH_KINDS.has(sniff.kind)) out.set(f.relpath, sniff);
  }
  return out;
}

/** A gzip file's importer, from its decompressed head through a no-follow handle; else undefined. */
export async function sniffDropFile(
  fullPath: string,
  relpath: string,
  resolveImportKind: DropSweepDeps["resolveImportKind"],
): Promise<DropSniff | undefined> {
  let handle: FileHandle | undefined;
  try {
    handle = await openNoFollow(fullPath);
    const magic = Buffer.alloc(2);
    const { bytesRead } = await handle.read(magic, 0, 2, 0);
    if (!isGzipMagic(magic.subarray(0, bytesRead))) return undefined;
    const { sample, gzip } = await sniffImportFileHeadDetail(handle);
    const name = relpath.split(/[\\/]/).pop() ?? relpath;
    const kind = resolveImportKind(name.replace(/\.gz$/i, ""), sample);
    return { kind, gzip, assetHost: assetHostFromDropRelpath(relpath) || "" };
  } catch {
    return undefined; // the solo path reads it and names whatever is wrong
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

async function runSolos(files: readonly DropFileStat[], d: DropSweepDeps, tally: SweepTally): Promise<void> {
  for (let i = 0; i < files.length; i += DROP_CONCURRENCY) {
    await Promise.all(
      files.slice(i, i + DROP_CONCURRENCY).map(async (file) => {
        try {
          await recordOutcome(file, await d.processFile(file), d, tally);
        } finally {
          d.progress(file.relpath);
        }
      }),
    );
  }
}

async function recordBatchResult(
  file: DropFileStat,
  res: BatchFileResult,
  d: DropSweepDeps,
  tally: SweepTally,
): Promise<void> {
  if (!res.ok && res.error !== undefined)
    d.recordImportFailure(file.relpath.split(/[\\/]/).pop() ?? file.relpath, res.error, res.debug);
  await recordOutcome(file, { ok: res.ok, reason: res.reason, warning: res.warning }, d, tally);
}

/** One file's move and its tally entry — the same for a single file and a batch member. */
async function recordOutcome(
  file: DropFileStat,
  res: DropOutcome,
  d: DropSweepDeps,
  tally: SweepTally,
): Promise<void> {
  if (res.pending) {
    // Raw input awaiting a tool: keep it in place (don't move, keep tracked) so the banner's
    // "Run <tool>" can act on it and a later config/auto-run picks it up next sweep.
    tally.pendingRawInputs.push(res.pending);
    return;
  }
  // A failed move is named to the analyst, merged into the file's one warning or failure
  // entry (buildSweepLogEntries reads only the first warning per file) (#2281).
  const moveNote = await d.moveDropFile(d.dropDir, file.relpath, res.ok, file).then(
    () => undefined,
    (e) => {
      logLine(`[drop] move failed for ${file.relpath}: ${(e as Error).message}`);
      return stuckMoveNote(res.ok, (e as Error).message);
    },
  );
  // A submitted file still counts as "imported" for the dashboard's drop banner (it was
  // accepted and moved), but the drop-log records it as SUBMITTED until the analysis lands.
  const warning = res.ok ? joinReasons(res.warning, moveNote) : "";
  if (warning) tally.warned.push({ relpath: file.relpath, reason: warning });
  if (res.ok && res.submitted) {
    tally.imported.push(file.relpath);
    tally.submitted.push({ relpath: file.relpath, reason: joinReasons(res.submitted, moveNote) });
  } else if (res.ok) tally.imported.push(file.relpath);
  else
    tally.failed.push({
      relpath: file.relpath,
      reason: joinReasons(res.reason ?? "import failed", moveNote),
    });
  d.forget(file.relpath); // moved out of the watched area
}
