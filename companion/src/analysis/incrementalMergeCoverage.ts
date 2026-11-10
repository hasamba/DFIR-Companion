import type { MergeStoredRow } from "./caseSqliteWorkerMerge.js";
import type { StateStore } from "./stateStore.js";
import { COVERAGE_EVENT_ID, coverageEventAt, isCoverageCandidate } from "./cloudMetadataAccess.js";
import { NEW_ROW_BASE, eventOf, type HeldRow } from "./incrementalMergeRows.js";

/**
 * The cloud coverage row in the incremental importer merge (#2504).
 *
 * A case with cloud audit logs and no host process telemetry carries one "Cloud coverage gap" row
 * (cloudMetadataAccess.ts metadataCoverageEvent), which the full merge rebuilds on every merge at the
 * earliest cloud-audit record of the whole timeline and appends after every other row. The
 * incremental merge holds only some rows, so it used to hand every such merge to the full path — and
 * a live cloud collection then loaded and re-saved the whole case on every page.
 *
 * Here the row is rebuilt from what the incremental merge can see exactly: the held rows as they now
 * read, plus the earliest clean cloud-audit row it did not hold, from the merge index. The earliest
 * instant wins, and at equal instants the first row in timeline order (stored rows by ordinal, new
 * rows after them) — earliestEventTime's own rule over the full timeline. The rebuilt row takes the
 * stored row's place (readHeld always holds it) and a first appearance past every new row, so it
 * sorts after any row at the same time, as the full merge's append makes it.
 */
export async function placeCoverage(
  store: StateStore,
  caseId: string,
  held: ReadonlyMap<number, MergeStoredRow>,
  rows: readonly HeldRow[],
): Promise<HeldRow[] | string> {
  let best: { ms: number; pre: number; timestamp: string } | null = null;
  const consider = (timestamp: string | undefined, pre: number): void => {
    const ms = Date.parse(timestamp ?? "");
    if (!Number.isFinite(ms) || timestamp === undefined) return;
    if (!best || ms < best.ms || (ms === best.ms && pre < best.pre)) best = { ms, pre, timestamp };
  };
  for (const h of rows) if (isCoverageCandidate(h.event)) consider(h.event.timestamp, h.pre);
  const [unheld] = await store.mergeRows(caseId, {
    earliestCloudAudit: true,
    excludeRowIds: [...held.keys()],
  });
  if (unheld) consider(eventOf(unheld).timestamp, unheld.ordinal);
  // The full merge falls back to the current time here, which no second computation can reproduce.
  if (!best) return "the cloud coverage row is due and no cloud record has a readable time";
  const { timestamp } = best;
  const stored = rows.find((h) => h.event.id === COVERAGE_EVENT_ID)?.stored;
  return [
    ...rows.filter((h) => h.event.id !== COVERAGE_EVENT_ID),
    { ...(stored ? { stored } : {}), event: coverageEventAt(timestamp), pre: NEW_ROW_BASE + rows.length },
  ];
}
