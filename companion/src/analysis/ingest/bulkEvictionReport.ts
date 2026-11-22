import { mergeEvictions, type SuperEviction } from "../superTimelineStore.js";
import type { BulkImportOpts, BulkImportResult, BulkImportSink, BulkRunHandle } from "./velociraptorBulk.js";

type RunResult = Pick<BulkImportResult, "superEvicted" | "run">;
/** What reads the put-back rows and logs: the bulk sink, or the part of it a caller has. */
type PutBackReader = Pick<BulkImportSink, "log" | "superMissingOfRun">;

// A failed read leaves the report whole: overstating a loss is the safer error, and the line says so.
function logUnreadPutBack(sink: PutBackReader, caseId: string, label: string, err: unknown): void {
  const detail = err instanceof Error ? err.message : String(err);
  sink.log(
    `[import] ${caseId} ${label}: could not tell which dropped super-timeline rows the import puts back: ${detail} — the import record may count a row twice`,
    caseId,
  );
}

/**
 * A run's eviction less `reoffered` rows the settle puts back. The count never goes below zero; the
 * set-aside share never exceeds it; the span is kept as it is — it is a span, not a window.
 */
export function evictionLessReoffered(evicted: SuperEviction, reoffered: number): SuperEviction {
  const back = Math.min(evicted.count, Math.max(0, Math.floor(reoffered) || 0));
  if (!back) return evicted;
  const count = evicted.count - back;
  return count
    ? { ...evicted, count, setAside: Math.min(evicted.setAside, count) }
    : { count: 0, setAside: 0, from: "", to: "" };
}

/**
 * What a committed forensic-mode batched run tells its import the super-timeline cap dropped (#2816).
 *
 * It is the run's own batches plus its commit pass, LESS the rows the import's settle will put back.
 * A graded row is in the forensic timeline as well, and the settle offers every forensic row the
 * import added to the super-timeline again (routes/importSettlePaged.ts). So a graded row the run's
 * cap dropped is re-inserted there, and the settle's own report then covers whichever row goes for
 * good. Adding the two reports as they stand counted such a row twice: an import of 15 graded rows
 * into a cap of 5 recorded 20 dropped rows.
 *
 * The rows are matched by identity — the run's forensic rows the store no longer holds — not by
 * arithmetic on the counts. When that read fails the run's report stands whole.
 */
export async function bulkEvictionForRecord(
  sink: BulkImportSink,
  caseId: string,
  label: string,
  result: RunResult,
  atCommit: SuperEviction | undefined,
): Promise<SuperEviction> {
  const evicted = mergeEvictions(result.superEvicted, atCommit);
  if (!evicted.count || !sink.superMissingOfRun) return evicted;
  try {
    return evictionLessReoffered(evicted, await sink.superMissingOfRun(caseId, result.run));
  } catch (err) {
    logUnreadPutBack(sink, caseId, label, err);
    return evicted;
  }
}

/**
 * The end of a committed forensic-mode run: tell the import what the cap dropped. An import that
 * settles after this ONE run gets the figure above, when it is not zero. A hunt collect settles once
 * after SEVERAL runs, so it asks for `onRunEvicted` instead and gets the run's eviction whole — a
 * zero one too — with the run to ask about later (`collectEvictionForRecord`).
 */
export async function reportBulkEviction(
  sink: BulkImportSink,
  caseId: string,
  opts: Pick<BulkImportOpts, "label" | "onSuperEvicted" | "onRunEvicted">,
  result: RunResult,
  atCommit: SuperEviction | undefined,
): Promise<void> {
  if (opts.onRunEvicted) return opts.onRunEvicted(mergeEvictions(result.superEvicted, atCommit), result.run);
  const evicted = await bulkEvictionForRecord(sink, caseId, opts.label, result, atCommit);
  if (evicted.count) opts.onSuperEvicted?.(evicted);
}

/** One committed batched run of a collect: what its own cap passes dropped, and the run. */
export interface BatchedRunEviction {
  raw: SuperEviction | undefined;
  run: BulkRunHandle;
}

/**
 * What a hunt collect's import record says the cap dropped BEFORE the collect's one settle (#2831).
 *
 * Each batched artifact is a run of its own, and a later run's cap pass can drop an earlier run's
 * graded rows. Per-run accounting then counted such a row twice: the later run reported it, the
 * earlier run had already measured its own put-back rows, and the one settle offered it again. So
 * the collect measures once, after its last import and before that settle: everything reported so
 * far (`runs`, plus `other` — an uploaded report's own figure) less the batched runs' forensic rows
 * the store does not hold now, which are the rows the settle puts back.
 *
 * Only the batched runs are asked. A small artifact's rows are also absent before the settle, but
 * no cap pass dropped them — they were never offered — so they must not be subtracted.
 */
export async function collectEvictionForRecord(
  sink: PutBackReader | undefined,
  caseId: string,
  label: string,
  runs: readonly BatchedRunEviction[],
  other?: SuperEviction,
): Promise<SuperEviction> {
  const evicted = runs.reduce((sum, r) => mergeEvictions(sum, r.raw), mergeEvictions(other, undefined));
  if (!evicted.count || !runs.length || !sink?.superMissingOfRun) return evicted;
  try {
    let putBack = 0;
    for (const r of runs) putBack += await sink.superMissingOfRun(caseId, r.run);
    return evictionLessReoffered(evicted, putBack);
  } catch (err) {
    logUnreadPutBack(sink, caseId, label, err);
    return evicted;
  }
}
