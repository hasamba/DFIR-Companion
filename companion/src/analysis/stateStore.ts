import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import type { CaseStore } from "../storage/caseStore.js";
import { caseSqliteWorker } from "./caseSqliteWorker.js";
import { type ForensicEvent, type InvestigationState, emptyState } from "./stateTypes.js";
import { upgradeForensicEvent } from "./canonicalEvent.js";
import { compactEventProvenance } from "./canonicalProvenanceCompact.js";
import type { OperationalMetricsStore, QueryIndex, QueryOperation } from "./operationalMetrics.js";
import {
  EMPTY_OUTLINE,
  type ForensicOutline,
  type ForensicRow,
  type ForensicRowStore,
  type JournalEntry,
  type RowWriteResult,
} from "./forensicRows.js";
import type {
  MergeApplyPlan,
  MergeIndexRecord,
  MergeSnapshot,
  MergeStoredRow,
} from "./caseSqliteWorkerMerge.js";

export const INVESTIGATION_DB_FILENAME = "investigation.sqlite";
const LEGACY_STATE_FILENAME = "investigation.json";
const DEFAULT_QUERY_LIMIT = 500;

export interface StateStoreDeps {
  readFile?: (path: string) => Promise<string>;
  operationalMetrics?: OperationalMetricsStore;
}

export interface EntityQuery {
  cursor?: number;
  limit?: number;
  from?: string;
  to?: string;
  host?: string;
  source?: string;
  severity?: string;
  ioc?: string;
  technique?: string;
  entityId?: string;
  /**
   * SQL LIKE pattern matched against the raw stored JSON payload — a cheap PREFILTER, not a search
   * (#928). It carries no opinion about which fields are searchable: that belongs to the analysis
   * layer, and analysis/forensicSearch.ts applies the real predicate to the rows this returns.
   * Deliberately not a bare term, so nothing can mistake a payload substring hit for a match.
   */
  searchLike?: string;
  /**
   * Turn the full-text prefilter on. Set independently of `searchLike` because a non-ASCII term has
   * no usable LIKE pattern — LIKE folds case for ASCII only — and the prefilter then narrows to
   * rows holding a non-ASCII character instead. See analysis/forensicSearch.ts.
   */
  searchPrefilter?: boolean;
  /** Internal/export optimization: skip the full matching-row count when only cursor batches matter. */
  includeTotal?: boolean;
}

export interface EntityPage<T> {
  entities: T[];
  /**
   * Row ordinals parallel to `entities`. A caller that post-filters a page (analysis/forensicSearch)
   * has to resume from the row it stopped on, and the ordinal is a column — it is not inside the
   * event, so it cannot be recovered afterwards.
   */
  ordinals?: number[];
  nextCursor: number | null;
  total: number;
  /**
   * `total` stopped at a ceiling rather than counting every match, so it is a floor, not a count
   * (analysis/forensicSearch.ts). Render it as "10,000+"; presenting it as a total would be a
   * number the case does not support.
   */
  totalIsLowerBound?: boolean;
}

/**
 * Persistence contract used by the analysis pipeline and routes. The full-state methods preserve
 * the existing API while indexed consumers can page the forensic timeline without materializing
 * the case. New mutations should prefer narrower methods as they are introduced.
 */
export interface InvestigationStateStorage {
  load(caseId: string): Promise<InvestigationState>;
  loadOverview(caseId: string): Promise<InvestigationState>;
  save(state: InvestigationState): Promise<void>;
  queryForensicTimeline(caseId: string, query?: EntityQuery): Promise<EntityPage<ForensicEvent>>;
  appendForensicEvents(caseId: string, events: readonly ForensicEvent[]): Promise<number>;
  /** The case database's rollback fence before a bulk run (#1480); 0 when the case has no database yet. */
  importRowIdMark(caseId: string): Promise<number>;
  /**
   * Remove the rows one bulk run appended above its fence, by the run's `importBatchId`, for the
   * kinds named — both timelines in one transaction (#1480).
   */
  rollbackImportBatch(
    caseId: string,
    afterRowId: number,
    importBatchId: string,
    kinds: readonly ImportRollbackKind[],
  ): Promise<Record<ImportRollbackKind, ImportRollback>>;
  hasForensicEventIds(caseId: string, ids: readonly string[]): Promise<Set<string>>;
  forensicTimelineBatches(
    caseId: string,
    query?: Omit<EntityQuery, "cursor">,
  ): AsyncGenerator<ForensicEvent[]>;
  iocProvenanceCandidates(
    caseId: string,
    keys: readonly string[],
    ids: readonly string[],
  ): Promise<IocProvenanceCandidates>;
  integrityCheck(caseId: string): Promise<{ ok: boolean; message: string }>;
}

/**
 * The rows the worker's FTS term index names for a set of IOC keys plus every authoritative
 * `extractedFrom` id (#1452): forensic rows in ordinal order, super rows in the streaming order,
 * so the provenance builders see them exactly as the streaming path fed them.
 */
/** What a bulk-run rollback removed for one kind (#1480): the row count and the ids, for the tags written to them. */
export interface ImportRollback {
  deleted: number;
  ids: string[];
}
export type ImportRollbackKind = "forensicTimeline" | "superTimeline";

export interface IocProvenanceCandidates {
  forensic: ForensicEvent[];
  super: ForensicEvent[];
  /** Distinct rows fetched — for logs and tests. */
  candidates: number;
}

const NO_IOC_CANDIDATES: IocProvenanceCandidates = { forensic: [], super: [], candidates: 0 };

interface WorkerEntityPage<T> {
  entities: T[];
  /** Row ordinals parallel to `entities`, so a post-filtered page can resume from the right row. */
  ordinals?: number[];
  nextCursor: number | null;
  total: number;
}

function queryIndex(query: EntityQuery): QueryIndex {
  if (query.ioc) return "ioc";
  if (query.technique) return "technique";
  if (query.entityId) return "entity";
  if (query.host) return "host";
  if (query.source) return "source";
  if (query.severity) return "severity";
  if (query.from || query.to) return "timestamp";
  return "ordinal";
}

// A legacy JSON case can be below SQLite's practical capacity but still above V8's maximum string
// size. The original file remains untouched, so this error names recovery rather than presenting a
// half-migrated database as authoritative.
function isTooLargeToDecode(err: unknown): boolean {
  const code = (err as NodeJS.ErrnoException).code;
  if (code === "ERR_STRING_TOO_LONG") return true;
  const message = (err as Error)?.message ?? "";
  return /Invalid string length/i.test(message) || /string longer than/i.test(message);
}

type WorkerRow = { rowId: number; version: number; entity: ForensicEvent };
const toForensicRow = (row: WorkerRow): ForensicRow => ({
  rowId: row.rowId,
  version: row.version,
  event: upgradeForensicEvent(row.entity),
});
// What save() writes for a forensic row, so a targeted write stores exactly what a full save would.
export const storedForm = (e: ForensicEvent): ForensicEvent =>
  compactEventProvenance(upgradeForensicEvent(e));

/** Which forensic rows mergeRows reads (analysis/caseSqliteWorkerMerge.ts). */
export type MergeRowSelect = (
  | { rowIds: readonly number[] }
  | { ids: readonly string[] }
  | { keys: readonly string[] }
  | { flagMask: number }
  | { clampYear: number }
) & { excludeRowIds?: readonly number[] };

/** What captureImportBaseline reads in one transaction (analysis/importBaseline.ts). */
export interface CapturedBaseline {
  overview: InvestigationState;
  outline: ForensicOutline;
}

export class StateStore implements InvestigationStateStorage, ForensicRowStore {
  private readonly readLegacyFile: (path: string) => Promise<string>;
  private readonly hasInjectedReader: boolean;
  private readonly operationalMetrics?: OperationalMetricsStore;

  // onRetry remains in the stable constructor signature for server/tests. SQLite transactions use
  // their own busy handling inside the worker, so atomic-rename retry reporting no longer applies.
  constructor(
    private readonly cases: CaseStore,
    private readonly onRetry?: (caseId: string, retries: number) => void,
    deps: StateStoreDeps = {},
  ) {
    this.hasInjectedReader = deps.readFile !== undefined;
    this.readLegacyFile = deps.readFile ?? ((path) => readFile(path, "utf8"));
    this.operationalMetrics = deps.operationalMetrics;
  }

  /** The cases root this store reads (per-case in-memory state keys on its generations, #1866). */
  get casesRoot(): string {
    return this.cases.casesRoot;
  }

  private recordQuery(operation: QueryOperation, index: QueryIndex, startedAt: number, rows: number): void {
    void this.operationalMetrics?.record({
      type: "query",
      operation,
      index,
      durationMs: Math.max(0, performance.now() - startedAt),
      rows: Math.max(0, Math.floor(rows)),
    });
  }

  databasePath(caseId: string): string {
    return join(this.cases.stateDir(caseId), INVESTIGATION_DB_FILENAME);
  }

  private legacyPath(caseId: string): string {
    return join(this.cases.stateDir(caseId), LEGACY_STATE_FILENAME);
  }

  private async ensureMigrated(caseId: string): Promise<boolean> {
    const dbPath = this.databasePath(caseId);
    if (await caseSqliteWorker.request<boolean>({ op: "stateExists", dbPath })) return true;

    // The injected reader is a long-standing failure-test seam. Production migration stays wholly
    // in the worker; only seam-driven tests parse on the caller thread.
    if (this.hasInjectedReader) {
      try {
        const parsed = JSON.parse(
          await this.readLegacyFile(this.legacyPath(caseId)),
        ) as Partial<InvestigationState>;
        await this.save({ ...emptyState(caseId), ...parsed, caseId });
        return true;
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code === "ENOENT") return false;
        if (isTooLargeToDecode(err)) throw this.legacyTooLargeError(caseId);
        throw err;
      }
    }

    try {
      return await caseSqliteWorker.request<boolean>({
        op: "migrateState",
        dbPath,
        jsonPath: this.legacyPath(caseId),
      });
    } catch (err) {
      if (isTooLargeToDecode(err)) throw this.legacyTooLargeError(caseId);
      throw err;
    }
  }

  private legacyTooLargeError(caseId: string): Error {
    return new Error(
      `case "${caseId}" cannot be opened: its legacy state is too large to load for migration. ` +
        `${this.legacyPath(caseId)} has passed V8's ` +
        `~512 MB max string length. The original JSON case is still untouched and no partial SQLite ` +
        `migration is authoritative. Restore the newest backup below that size, open it once to ` +
        `complete migration, and then continue in the indexed store.`,
    );
  }

  async load(caseId: string): Promise<InvestigationState> {
    return this.loadState(caseId, []);
  }

  async loadOverview(caseId: string): Promise<InvestigationState> {
    return this.loadState(caseId, ["forensicTimeline"]);
  }

  private async loadState(caseId: string, excludedKinds: string[]): Promise<InvestigationState> {
    const startedAt = performance.now();
    if (!(await this.ensureMigrated(caseId))) return emptyState(caseId);
    const parsed = await caseSqliteWorker.request<Partial<InvestigationState> | null>({
      op: "loadState",
      dbPath: this.databasePath(caseId),
      excludedKinds,
    });
    if (parsed?.caseId && parsed.caseId !== caseId) {
      await caseSqliteWorker.request<void>({
        op: "setStateCaseId",
        dbPath: this.databasePath(caseId),
        caseId,
      });
    }
    const state = { ...emptyState(caseId), ...(parsed ?? {}), caseId };
    const result = state.forensicTimeline.length
      ? { ...state, forensicTimeline: state.forensicTimeline.map(upgradeForensicEvent) }
      : state;
    this.recordQuery("state_load", "entity", startedAt, result.forensicTimeline.length);
    return result;
  }

  async save(state: InvestigationState): Promise<void> {
    const startedAt = performance.now();
    // #1874: a verbose (pre-1.1.0) envelope is written back compact — lossless, and only once.
    const canonicalState = state.forensicTimeline.length
      ? {
          ...state,
          forensicTimeline: state.forensicTimeline.map((e) =>
            compactEventProvenance(upgradeForensicEvent(e)),
          ),
        }
      : state;
    await caseSqliteWorker.request<void>({
      op: "saveState",
      dbPath: this.databasePath(canonicalState.caseId),
      state: canonicalState,
    });
    this.recordQuery("state_save", "entity", startedAt, canonicalState.forensicTimeline.length);
    void this.onRetry;
  }

  async queryForensicTimeline(caseId: string, query: EntityQuery = {}): Promise<EntityPage<ForensicEvent>> {
    const startedAt = performance.now();
    await this.ensureMigrated(caseId);
    const indexName = query.ioc ? "ioc" : query.technique ? "technique" : undefined;
    const indexValue = query.ioc ?? query.technique;
    const page = await caseSqliteWorker.request<WorkerEntityPage<ForensicEvent>>({
      op: "queryEntities",
      dbPath: this.databasePath(caseId),
      kind: "forensicTimeline",
      query: {
        afterOrdinal: query.cursor,
        limit: query.limit ?? DEFAULT_QUERY_LIMIT,
        from: query.from,
        to: query.to,
        host: query.host,
        source: query.source,
        severity: query.severity,
        entityId: query.entityId,
        indexName,
        indexValue,
        searchLike: query.searchLike,
        searchPrefilter: query.searchPrefilter,
        includeTotal: query.includeTotal,
      },
    });
    const result = { ...page, entities: page.entities.map(upgradeForensicEvent) };
    this.recordQuery("forensic_timeline", queryIndex(query), startedAt, result.entities.length);
    return result;
  }

  async appendForensicEvents(caseId: string, events: readonly ForensicEvent[]): Promise<number> {
    if (!events.length) return 0;
    const startedAt = performance.now();
    if (!(await this.ensureMigrated(caseId))) {
      await this.save(emptyState(caseId));
    }
    const appended = await caseSqliteWorker.request<number>({
      op: "appendEntities",
      dbPath: this.databasePath(caseId),
      kind: "forensicTimeline",
      entities: events.map(upgradeForensicEvent),
    });
    this.recordQuery("event_append", "entity", startedAt, appended);
    return appended;
  }

  async importRowIdMark(caseId: string): Promise<number> {
    if (!(await this.ensureMigrated(caseId))) return 0;
    return caseSqliteWorker.request<number>({ op: "entityRowIdMark", dbPath: this.databasePath(caseId) });
  }

  // The super-timeline lives in the same database (superTimelineStore.ts), which is what lets one
  // transaction cover both kinds; its migration, if it ran after the fence, inserted rows without
  // this run's batch id, so they are never touched.
  async rollbackImportBatch(
    caseId: string,
    afterRowId: number,
    importBatchId: string,
    kinds: readonly ImportRollbackKind[],
  ): Promise<Record<ImportRollbackKind, ImportRollback>> {
    const empty = { forensicTimeline: { deleted: 0, ids: [] }, superTimeline: { deleted: 0, ids: [] } };
    if (!kinds.length || !(await this.ensureMigrated(caseId))) return empty;
    const startedAt = performance.now();
    const out = await caseSqliteWorker.request<Partial<Record<ImportRollbackKind, ImportRollback>>>({
      op: "rollbackImportBatch",
      dbPath: this.databasePath(caseId),
      kinds: [...kinds],
      afterRowId,
      importBatchId,
    });
    const result = { ...empty, ...out };
    this.recordQuery(
      "event_rollback",
      "entity",
      startedAt,
      result.forensicTimeline.deleted + result.superTimeline.deleted,
    );
    return result;
  }

  async hasForensicEventIds(caseId: string, ids: readonly string[]): Promise<Set<string>> {
    if (!ids.length || !(await this.ensureMigrated(caseId))) return new Set();
    const found = await caseSqliteWorker.request<string[]>({
      op: "hasEntityIds",
      dbPath: this.databasePath(caseId),
      kind: "forensicTimeline",
      ids: [...ids],
    });
    return new Set(found);
  }

  async *forensicTimelineBatches(
    caseId: string,
    query: Omit<EntityQuery, "cursor"> = {},
  ): AsyncGenerator<ForensicEvent[]> {
    let cursor: number | null = null;
    do {
      const page = await this.queryForensicTimeline(caseId, {
        ...query,
        cursor: cursor ?? undefined,
        includeTotal: false,
      });
      if (page.entities.length) yield page.entities;
      cursor = page.nextCursor;
    } while (cursor !== null);
  }

  // ── #1874: targeted row access for an import's settle phase (analysis/caseSqliteWorkerRows.ts) ──

  /** Save every field but the forensic timeline, which is left exactly as stored. */
  async saveOverview(state: InvestigationState): Promise<void> {
    await caseSqliteWorker.request<void>({
      op: "saveState",
      dbPath: this.databasePath(state.caseId),
      state: { ...state, forensicTimeline: [] },
      excludedKinds: ["forensicTimeline"],
    });
  }

  /** The forensic timeline's ids and row ids in order, plus (unless `withKeys` is false) its diff keys. */
  async forensicOutline(caseId: string, withKeys = true): Promise<ForensicOutline> {
    if (!(await this.ensureMigrated(caseId))) return { ...EMPTY_OUTLINE };
    const outline = await caseSqliteWorker.request<ForensicOutline | null>({
      op: "forensicOutline",
      dbPath: this.databasePath(caseId),
      withKeys,
    });
    return outline ?? { ...EMPTY_OUTLINE };
  }

  /**
   * The import section's snapshot: overview + outline, read in the same transaction that arms the
   * import journal under `token`. Null when the case has no state yet.
   */
  async captureImportBaseline(caseId: string, token: string): Promise<CapturedBaseline | null> {
    if (!(await this.ensureMigrated(caseId))) return null;
    const got = await caseSqliteWorker.request<{
      overview: Partial<InvestigationState> | null;
      outline: ForensicOutline;
    } | null>({ op: "captureImportBaseline", dbPath: this.databasePath(caseId), token });
    if (!got) return null;
    return { overview: { ...emptyState(caseId), ...(got.overview ?? {}), caseId }, outline: got.outline };
  }

  /** The journaled pre-images, or null when `token` no longer holds the journal. */
  async readImportJournal(caseId: string, token: string): Promise<JournalEntry[] | null> {
    const rows = await caseSqliteWorker.request<
      { rowId: number; entityId: string | null; payload: ForensicEvent }[] | null
    >({ op: "readImportJournal", dbPath: this.databasePath(caseId), token });
    return rows
      ? rows.map((r) => ({ rowId: r.rowId, entityId: r.entityId, event: upgradeForensicEvent(r.payload) }))
      : null;
  }

  async disarmImportJournal(caseId: string, token: string): Promise<void> {
    await caseSqliteWorker.request<boolean>({
      op: "disarmImportJournal",
      dbPath: this.databasePath(caseId),
      token,
    });
  }

  async forensicRowsById(caseId: string, ids: readonly string[]): Promise<ForensicRow[]> {
    if (!ids.length || !(await this.ensureMigrated(caseId))) return [];
    const rows = await caseSqliteWorker.request<WorkerRow[]>({
      op: "entityRows",
      dbPath: this.databasePath(caseId),
      kind: "forensicTimeline",
      ids: [...ids],
    });
    return rows.map(toForensicRow);
  }

  async forensicRowsByRowId(caseId: string, rowIds: readonly number[]): Promise<ForensicRow[]> {
    if (!rowIds.length || !(await this.ensureMigrated(caseId))) return [];
    const rows = await caseSqliteWorker.request<WorkerRow[]>({
      op: "entityRows",
      dbPath: this.databasePath(caseId),
      kind: "forensicTimeline",
      rowIds: [...rowIds],
    });
    return rows.map(toForensicRow);
  }

  async forensicRowsOutsideSeverities(caseId: string, keep: readonly string[]): Promise<ForensicRow[]> {
    if (!(await this.ensureMigrated(caseId))) return [];
    const rows = await caseSqliteWorker.request<WorkerRow[]>({
      op: "forensicRowsOutsideSeverities",
      dbPath: this.databasePath(caseId),
      keep: [...keep],
    });
    return rows.map(toForensicRow);
  }

  async forensicHosts(caseId: string): Promise<string[]> {
    if (!(await this.ensureMigrated(caseId))) return [];
    return caseSqliteWorker.request<string[]>({
      op: "distinctHosts",
      dbPath: this.databasePath(caseId),
      kind: "forensicTimeline",
    });
  }

  async updateForensicRows(caseId: string, rows: readonly ForensicRow[]): Promise<RowWriteResult> {
    if (!rows.length) return { updated: 0, missing: [], conflicts: [] };
    const startedAt = performance.now();
    const result = await caseSqliteWorker.request<RowWriteResult>({
      op: "updateEntityRows",
      dbPath: this.databasePath(caseId),
      kind: "forensicTimeline",
      rows: rows.map((r) => ({ rowId: r.rowId, version: r.version, entity: storedForm(r.event) })),
    });
    this.recordQuery("event_update", "entity", startedAt, result.updated);
    return result;
  }

  async deleteForensicRows(caseId: string, rowIds: readonly number[]): Promise<number> {
    if (!rowIds.length) return 0;
    const startedAt = performance.now();
    const deleted = await caseSqliteWorker.request<number>({
      op: "deleteEntityRows",
      dbPath: this.databasePath(caseId),
      kind: "forensicTimeline",
      rowIds: [...rowIds],
    });
    this.recordQuery("event_delete", "entity", startedAt, deleted);
    return deleted;
  }

  async patchStateMeta(caseId: string, patch: Record<string, unknown>): Promise<void> {
    await caseSqliteWorker.request<boolean>({
      op: "patchStateMeta",
      dbPath: this.databasePath(caseId),
      patch,
    });
  }

  // `keys` are already trimmed + lowercased and at least 3 characters long — the caller filters.
  async iocProvenanceCandidates(
    caseId: string,
    keys: readonly string[],
    ids: readonly string[],
  ): Promise<IocProvenanceCandidates> {
    if (!(await this.ensureMigrated(caseId))) return { ...NO_IOC_CANDIDATES };
    const found = await caseSqliteWorker.request<IocProvenanceCandidates>({
      op: "iocCandidates",
      dbPath: this.databasePath(caseId),
      keys: [...keys],
      ids: [...ids],
    });
    return {
      forensic: found.forensic.map(upgradeForensicEvent),
      super: found.super.map(upgradeForensicEvent),
      candidates: found.candidates,
    };
  }

  // ── #1874: the incremental importer merge (analysis/incrementalMerge.ts) ──

  /** The case metadata and every array but the forensic timeline and the IOCs. */
  async loadMergeOverview(caseId: string): Promise<InvestigationState> {
    return this.loadState(caseId, ["forensicTimeline", "iocs"]);
  }

  async mergeSnapshot(caseId: string): Promise<MergeSnapshot | null> {
    if (!(await this.ensureMigrated(caseId))) return null;
    return caseSqliteWorker.request<MergeSnapshot | null>({
      op: "mergeSnapshot",
      dbPath: this.databasePath(caseId),
    });
  }

  async mergeRows(caseId: string, select: MergeRowSelect): Promise<MergeStoredRow[]> {
    return caseSqliteWorker.request<MergeStoredRow[]>({
      op: "mergeRows",
      dbPath: this.databasePath(caseId),
      select,
    });
  }

  async mergeIdCounts(caseId: string, ids: readonly string[]): Promise<Record<string, number>> {
    if (!ids.length) return {};
    return caseSqliteWorker.request({
      op: "mergeIdCounts",
      dbPath: this.databasePath(caseId),
      ids: [...ids],
    });
  }

  async mergeIocCandidates(
    caseId: string,
    lowered: readonly string[],
    aliasIds: readonly string[],
  ): Promise<{ rows: MergeStoredRow[]; nextSeq: number }> {
    return caseSqliteWorker.request({
      op: "mergeIocCandidates",
      dbPath: this.databasePath(caseId),
      lowered: [...lowered],
      aliasIds: [...aliasIds],
    });
  }

  async mergeIocsCiting(caseId: string, eventIds: readonly string[]): Promise<MergeStoredRow[]> {
    if (!eventIds.length) return [];
    return caseSqliteWorker.request({
      op: "mergeIocsCiting",
      dbPath: this.databasePath(caseId),
      eventIds: [...eventIds],
    });
  }

  async mergeApply(
    caseId: string,
    plan: MergeApplyPlan,
  ): Promise<{ inserted: number; deleted: number; moved: number }> {
    const startedAt = performance.now();
    const out = await caseSqliteWorker.request<{ inserted: number; deleted: number; moved: number }>({
      op: "mergeApply",
      dbPath: this.databasePath(caseId),
      plan,
    });
    this.recordQuery("state_save", "entity", startedAt, plan.forensic.placed.length);
    return out;
  }

  async mergeStalePositions(
    caseId: string,
    stamp: string,
  ): Promise<{ generation: number; rowCount: number; positions: number[] } | null> {
    return caseSqliteWorker.request({ op: "mergeStalePositions", dbPath: this.databasePath(caseId), stamp });
  }

  async mergeIndexWrite(
    caseId: string,
    generation: number,
    entries: { position: number; index: MergeIndexRecord & { clean: boolean } }[],
    meta: { stamp: string; stable: boolean },
  ): Promise<number> {
    return caseSqliteWorker.request({
      op: "mergeIndexWrite",
      dbPath: this.databasePath(caseId),
      generation,
      entries,
      meta,
    });
  }

  async integrityCheck(caseId: string): Promise<{ ok: boolean; message: string }> {
    return caseSqliteWorker.request({
      op: "integrity",
      dbPath: this.databasePath(caseId),
    });
  }
}
