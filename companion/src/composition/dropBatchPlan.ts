/**
 * The drop folder's batch plan (#2540): which ready files of a sweep import together as ONE
 * merge-and-settle step, and which import on their own.
 *
 * A drop of thousands of small CloudTrail `.json.gz` files paid a fixed per-file tail (settle, a
 * tagger run record, a coverage and weakness rewrite, a case-timeline note, the post-import sweep).
 * A batch keeps every per-file step that carries provenance — its own evidence copy and custody
 * record, its own sequence number and row ids, its own parse and merge, in order — and shares
 * the tail. The plan is pure: the sweep sniffs each file and hands the verdicts in.
 *
 * ORDER IS THE CONTRACT. The ready files are walked sorted by relpath, and only a CONTIGUOUS run of
 * eligible files with the same importer and the same declared host (`drop/asset=<HOST>/`) becomes a
 * batch; any other file breaks the run and keeps its place. So the files import in the same order
 * whether or not they batch, which is what keeps the forensic timeline equal to one-at-a-time.
 *
 * Only AWS CloudTrail batches: the S3 delivery format is the one that arrives as thousands of small
 * gzip files, and it is the kind whose batch equivalence is tested. Other cloud kinds keep the
 * per-file path until each has its own differential test (M365 reads sign-in history across
 * uploads in its spray and MFA-fatigue rows).
 */
import type { DropFileStat } from "../analysis/dropScan.js";

/** At most this many files share one merge-and-settle step. */
export const DROP_BATCH_MAX_FILES = 100;
/** At most this many bytes (on disk, compressed) share one step — sizes the import memory guard. */
export const DROP_BATCH_MAX_BYTES = 32 * 1024 * 1024;
/** A file larger than this imports on its own: it is not a "small file" and gains nothing. */
export const DROP_BATCH_FILE_MAX_BYTES = 4 * 1024 * 1024;
/** A run shorter than this imports one at a time. */
export const DROP_BATCH_MIN_FILES = 2;
/** The import kinds that batch (see the header). */
export const DROP_BATCH_KINDS: ReadonlySet<string> = new Set(["aws"]);

/** The sweep's sniff of one file: its importer and whether it is gzip, from the head alone. */
export interface DropSniff {
  kind: string;
  gzip: boolean;
  /** The `drop/asset=<HOST>/` host, or "" when none is declared. */
  assetHost: string;
}

/** One step of the ordered work list: a batch, or one file imported on its own. */
export type DropWorkItem =
  | { type: "batch"; kind: string; assetHost: string; files: DropFileStat[] }
  | { type: "solo"; file: DropFileStat };

/** Whether one file may join a batch, from its listing size and its sniff. */
export function batchableSniff(file: DropFileStat, sniff: DropSniff | undefined): sniff is DropSniff {
  return !!sniff && sniff.gzip && DROP_BATCH_KINDS.has(sniff.kind) && file.size <= DROP_BATCH_FILE_MAX_BYTES;
}

/** The ready files sorted by relpath — the one order a sweep imports in. */
export function sortByRelpath(files: readonly DropFileStat[]): DropFileStat[] {
  return [...files].sort((a, b) => (a.relpath < b.relpath ? -1 : a.relpath > b.relpath ? 1 : 0));
}

/**
 * The ordered work list for `files` (already in import order). `sniffs` holds a verdict for each
 * file the sweep could sniff; a file without one never batches.
 */
export function planDropWork(
  files: readonly DropFileStat[],
  sniffs: ReadonlyMap<string, DropSniff>,
): DropWorkItem[] {
  const out: DropWorkItem[] = [];
  let run: { kind: string; assetHost: string; files: DropFileStat[]; bytes: number } | null = null;
  const close = (): void => {
    if (!run) return;
    if (run.files.length >= DROP_BATCH_MIN_FILES)
      out.push({ type: "batch", kind: run.kind, assetHost: run.assetHost, files: run.files });
    else for (const file of run.files) out.push({ type: "solo", file });
    run = null;
  };
  for (const file of files) {
    const sniff = sniffs.get(file.relpath);
    if (!batchableSniff(file, sniff)) {
      close();
      out.push({ type: "solo", file });
      continue;
    }
    const fits =
      run !== null &&
      run.kind === sniff.kind &&
      run.assetHost === sniff.assetHost &&
      run.files.length < DROP_BATCH_MAX_FILES &&
      run.bytes + file.size <= DROP_BATCH_MAX_BYTES;
    if (!fits) close();
    run ??= { kind: sniff.kind, assetHost: sniff.assetHost, files: [], bytes: 0 };
    run.files.push(file);
    run.bytes += file.size;
  }
  close();
  return out;
}
