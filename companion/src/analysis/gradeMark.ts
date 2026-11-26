/**
 * The per-row grade mark (#2891). A row an import added carries `gradePending: true` from the moment
 * the import stamp is written (routes/importSettlePaged.ts, in the same row write as `importedAt` /
 * `importBatchId`) until the content tagger has really finished on it; a row reads as GRADED exactly
 * when it does not carry the mark.
 *
 * WHY. The settle stamps a batch, then dual-writes and tags it, then demotes case-wide. A crash between
 * the stamp and the tag, or a tagger that failed internally, used to leave untagged rows that the next
 * import's case-wide demote moved out as Info — so a row the tagger would have graded up (NTDS.dit,
 * `\Windows\Temp\*.ps1`) never reached the forensic timeline or the AI. Now:
 *   - the case-wide demote (composition/importDemote.ts) never moves a marked row, unless the caller
 *     says the tagger just finished on it;
 *   - start-up recovery (composition/ungradedRecovery.ts) finds marked rows and grades them.
 *
 * WHY THE POLARITY. "Pending" rather than "graded" keeps every row persisted before this change — and
 * every row a writer that never crosses the settle stamp produced (bulk Velociraptor, hunt summaries,
 * Watson, AI saves, sigma regrade, manual rows, promotions) — graded, with no per-case watermark: old
 * cases are grandfathered, and a writer this change does not know keeps today's behaviour.
 */
import { caseSqliteWorker } from "./caseSqliteWorker.js";
import { upgradeForensicEvent } from "./canonicalEvent.js";
import { SCAN_PAGE_ROWS, type ForensicRow, type ForensicRowStore } from "./forensicRows.js";
import type { ForensicEvent } from "./stateTypes.js";

export interface GradeMarkFields {
  /** Set with the import stamp; removed once the content tagger finished on this row (#2891). */
  gradePending?: true;
}

export const isGradePending = (e: GradeMarkFields): boolean => e.gradePending === true;

/** `e` without the mark (the same object when it carries none). */
export function withoutGradePending<E extends GradeMarkFields>(e: E): E {
  if (!("gradePending" in e)) return e;
  const { gradePending: _mark, ...rest } = e;
  return rest as E;
}

/**
 * What the content tagger reports: the ids of the rows it did NOT finish on. Void means it finished on
 * every row (a test stand-in, or the held Watson tagger, which grades nothing by design).
 */
export type TagOutcome = { ungraded: readonly string[] } | void;

/** The ids of `events` the tagger finished on. */
export function gradedIdsOf(events: readonly ForensicEvent[], outcome: TagOutcome): string[] {
  const ungraded = new Set(outcome ? outcome.ungraded : []);
  return events.map((e) => e.id).filter((id) => !ungraded.has(id));
}

/** What a demote caller vouches for: the rows the tagger just finished on (they may leave). */
export interface DemoteOptions {
  graded?: ReadonlySet<string>;
}

type WorkerRow = { rowId: number; version: number; entity: ForensicEvent };

/**
 * Every forensic row that carries the mark. On the case database it is one SQL query (start-up runs it
 * for every case, so it must not page every row through JavaScript); any other row store is scanned.
 * Reads the forensic timeline only — never the super-timeline.
 */
export async function forensicGradePendingRows(
  store: ForensicRowStore & { databasePath?(caseId: string): string },
  caseId: string,
): Promise<ForensicRow[]> {
  if (typeof store.databasePath === "function") {
    const rows = await caseSqliteWorker.request<WorkerRow[]>({
      op: "forensicRowsGradePending",
      dbPath: store.databasePath(caseId),
    });
    return rows.map((r) => ({ rowId: r.rowId, version: r.version, event: upgradeForensicEvent(r.entity) }));
  }
  const ids: string[] = [];
  for await (const page of store.forensicTimelineBatches(caseId, { limit: SCAN_PAGE_ROWS }))
    for (const e of page) if (isGradePending(e)) ids.push(e.id);
  return ids.length ? store.forensicRowsById(caseId, ids) : [];
}
