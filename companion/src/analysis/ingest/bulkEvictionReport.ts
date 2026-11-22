import { mergeEvictions, type SuperEviction } from "../superTimelineStore.js";
import type { BulkImportResult, BulkImportSink } from "./velociraptorBulk.js";

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
 * arithmetic on the counts. When that read fails the run's report stands whole: overstating a loss
 * is the safer error, and the line says so.
 */
export async function bulkEvictionForRecord(
  sink: BulkImportSink,
  caseId: string,
  label: string,
  result: Pick<BulkImportResult, "superEvicted" | "run">,
  atCommit: SuperEviction | undefined,
): Promise<SuperEviction> {
  const evicted = mergeEvictions(result.superEvicted, atCommit);
  if (!evicted.count || !sink.superMissingOfRun) return evicted;
  try {
    return evictionLessReoffered(evicted, await sink.superMissingOfRun(caseId, result.run));
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    sink.log(
      `[import] ${caseId} ${label}: could not tell which dropped super-timeline rows the import puts back: ${detail} — the import record may count a row twice`,
      caseId,
    );
    return evicted;
  }
}
