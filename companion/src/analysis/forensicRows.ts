import type { EntityQuery } from "./stateStore.js";
import type { ForensicEvent, InvestigationState } from "./stateTypes.js";

/**
 * The narrow, row-level view of a case's forensic timeline that an import's settle phase works
 * through (#1874). StateStore implements it over the case database; tests may implement it in memory.
 *
 * Every write names rows by `rowId`, the storage row, not by event id: a duplicate event id elsewhere
 * in the timeline is never touched, and an update carries the `version` it read, so a row another
 * writer changed since is refused rather than overwritten (see caseSqliteWorkerRows.ts).
 */
export interface ForensicRow {
  rowId: number;
  version: number;
  event: ForensicEvent;
}

/** The fields diffTimeline reads, per row, in timeline order — no payloads. Key arrays are empty
 * when read without keys. */
export interface ForensicOutline {
  rowIds: number[];
  ids: (string | null)[];
  timestamps: unknown[];
  descriptions: unknown[];
  severities: unknown[];
}

/** One journaled pre-import image: the row as it was stored before the import first changed it. */
export interface JournalEntry {
  rowId: number;
  entityId: string | null;
  event: ForensicEvent;
}

export interface RowWriteResult {
  updated: number;
  /** Rows gone since they were read — deleted by another writer; never re-inserted. */
  missing: number[];
  /** Rows whose version, id or timestamp moved since they were read; left untouched. */
  conflicts: number[];
}

export interface ForensicRowStore {
  loadOverview(caseId: string): Promise<InvestigationState>;
  /** loadOverview with an empty IOC list; a store without it serves loadOverview. */
  loadOverviewWithoutIocs?(caseId: string): Promise<InvestigationState>;
  forensicOutline(caseId: string, withKeys?: boolean): Promise<ForensicOutline>;
  forensicRowsById(caseId: string, ids: readonly string[]): Promise<ForensicRow[]>;
  forensicRowsByRowId(caseId: string, rowIds: readonly number[]): Promise<ForensicRow[]>;
  forensicRowsOutsideSeverities(caseId: string, keep: readonly string[]): Promise<ForensicRow[]>;
  forensicHosts(caseId: string): Promise<string[]>;
  forensicTimelineBatches(
    caseId: string,
    query?: Omit<EntityQuery, "cursor">,
  ): AsyncGenerator<ForensicEvent[]>;
  updateForensicRows(caseId: string, rows: readonly ForensicRow[]): Promise<RowWriteResult>;
  deleteForensicRows(caseId: string, rowIds: readonly number[]): Promise<number>;
  patchStateMeta(caseId: string, patch: Record<string, unknown>): Promise<void>;
  /**
   * The armed import journal's pre-images; null when `token` no longer holds it. `fence` (the
   * baseline's highest row id) leaves out the rows the import itself inserted.
   */
  readImportJournal?(caseId: string, token: string, fence?: number): Promise<JournalEntry[] | null>;
}

/**
 * The page size for a pass that reads the whole timeline a page at a time (#1874). Larger than the
 * dashboard's page: each page is one worker round trip, and these passes hold one page at a time.
 */
export const SCAN_PAGE_ROWS = 5000;

export const EMPTY_OUTLINE: ForensicOutline = {
  rowIds: [],
  ids: [],
  timestamps: [],
  descriptions: [],
  severities: [],
};

/** A row-shaped view of an outline for diffTimeline, which reads only these three fields. */
export function outlineEvents(
  outline: ForensicOutline,
): Array<Pick<ForensicEvent, "timestamp" | "description" | "severity">> {
  // SQL NULL stands for a missing field, which a loaded row carries as undefined.
  const field = (v: unknown): unknown => (v === null ? undefined : v);
  return outline.rowIds.map((_, i) => ({
    timestamp: field(outline.timestamps[i]) as string,
    description: field(outline.descriptions[i]) as string,
    severity: field(outline.severities[i]) as ForensicEvent["severity"],
  }));
}
