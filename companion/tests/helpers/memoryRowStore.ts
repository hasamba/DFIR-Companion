import { emptyState, type ForensicEvent, type InvestigationState } from "../../src/analysis/stateTypes.js";
import type {
  ForensicOutline,
  ForensicRow,
  ForensicRowStore,
  RowWriteResult,
} from "../../src/analysis/forensicRows.js";
import { demoteBelowSeverity } from "../../src/analysis/forensicGate.js";

/**
 * An in-memory ForensicRowStore (#1874) over one case, for settle-seam unit tests: the row-level
 * interface StateStore implements over SQLite, with the same rules — row ids and versions, an update
 * keeps a row's position, a missing row is never re-inserted.
 */
export interface MemoryRowStore extends ForensicRowStore {
  /** The whole case as it is now. */
  load(caseId?: string): Promise<InvestigationState>;
  /** Every row write, in order (the ids written by each call). */
  writes: string[][];
  /** Replace the non-timeline fields (a test's "the importer merged this"). */
  setOverview(patch: Partial<InvestigationState>): void;
  /** Demote rows below Low, the way composition/importDemote.ts does; returns what it removed. */
  demoteInfo(caseId?: string): Promise<ForensicEvent[]>;
}

export function memoryRowStore(initial: InvestigationState): MemoryRowStore {
  let overview: InvestigationState = {
    ...emptyState(initial.caseId ?? "c1"),
    ...initial,
    forensicTimeline: [],
  };
  let nextRowId = 1;
  let rows: ForensicRow[] = (initial.forensicTimeline ?? []).map((event) => ({
    rowId: nextRowId++,
    version: 1,
    event,
  }));
  const writes: string[][] = [];
  const copy = (r: ForensicRow): ForensicRow => ({ ...r });
  const store: MemoryRowStore = {
    writes,
    setOverview(patch) {
      overview = { ...overview, ...patch, forensicTimeline: [] };
    },
    async load() {
      return { ...overview, forensicTimeline: rows.map((r) => r.event) };
    },
    async loadOverview() {
      return { ...overview, forensicTimeline: [] };
    },
    async forensicOutline(_caseId, withKeys = true): Promise<ForensicOutline> {
      return {
        rowIds: rows.map((r) => r.rowId),
        ids: rows.map((r) => r.event.id),
        timestamps: withKeys ? rows.map((r) => r.event.timestamp) : [],
        descriptions: withKeys ? rows.map((r) => r.event.description) : [],
        severities: withKeys ? rows.map((r) => r.event.severity) : [],
      };
    },
    async forensicRowsById(_caseId, ids) {
      const want = new Set(ids);
      return rows.filter((r) => want.has(r.event.id)).map(copy);
    },
    async forensicRowsByRowId(_caseId, rowIds) {
      const want = new Set(rowIds);
      return rows.filter((r) => want.has(r.rowId)).map(copy);
    },
    async forensicRowsOutsideSeverities(_caseId, keep) {
      return rows.filter((r) => !keep.includes(r.event.severity)).map(copy);
    },
    async forensicHosts() {
      return [...new Set(rows.map((r) => r.event.asset).filter((h): h is string => !!h))];
    },
    async *forensicTimelineBatches(_caseId, query = {}) {
      const page = rows.filter((r) => !query.host || r.event.asset === query.host).map((r) => r.event);
      for (let i = 0; i < page.length; i += 2) yield page.slice(i, i + 2);
    },
    async updateForensicRows(_caseId, updates): Promise<RowWriteResult> {
      const out: RowWriteResult = { updated: 0, missing: [], conflicts: [] };
      const ids: string[] = [];
      for (const u of updates) {
        const i = rows.findIndex((r) => r.rowId === u.rowId);
        if (i < 0) {
          out.missing.push(u.rowId);
          continue;
        }
        const cur = rows[i];
        if (cur.version !== u.version || cur.event.timestamp !== u.event.timestamp) {
          out.conflicts.push(u.rowId);
          continue;
        }
        rows = rows.map((r, k) => (k === i ? { ...r, version: r.version + 1, event: u.event } : r));
        ids.push(u.event.id);
        out.updated++;
      }
      writes.push(ids);
      return out;
    },
    async deleteForensicRows(_caseId, rowIds) {
      const gone = new Set(rowIds);
      const before = rows.length;
      rows = rows.filter((r) => !gone.has(r.rowId));
      return before - rows.length;
    },
    async patchStateMeta(_caseId, patch) {
      overview = { ...overview, ...patch, forensicTimeline: [] };
    },
    async demoteInfo() {
      const { demoted } = demoteBelowSeverity(
        rows.map((r) => r.event),
        "Low",
      );
      const gone = new Set(demoted);
      rows = rows.filter((r) => !gone.has(r.event));
      return demoted;
    },
  };
  return store;
}
