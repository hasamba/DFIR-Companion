import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import { caseSqliteWorker } from "./caseSqliteWorker.js";
import { type ForensicEvent, type InvestigationState, emptyState } from "./stateTypes.js";
import { upgradeForensicEvent } from "./canonicalEvent.js";

export const INVESTIGATION_DB_FILENAME = "investigation.sqlite";
const LEGACY_STATE_FILENAME = "investigation.json";
const DEFAULT_QUERY_LIMIT = 500;

export interface StateStoreDeps {
  readFile?: (path: string) => Promise<string>;
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
  /** Internal/export optimization: skip the full matching-row count when only cursor batches matter. */
  includeTotal?: boolean;
}

export interface EntityPage<T> {
  entities: T[];
  nextCursor: number | null;
  total: number;
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
  hasForensicEventIds(caseId: string, ids: readonly string[]): Promise<Set<string>>;
  forensicTimelineBatches(caseId: string, query?: Omit<EntityQuery, "cursor">): AsyncGenerator<ForensicEvent[]>;
  integrityCheck(caseId: string): Promise<{ ok: boolean; message: string }>;
}

interface WorkerEntityPage<T> {
  entities: T[];
  nextCursor: number | null;
  total: number;
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

export class StateStore implements InvestigationStateStorage {
  private readonly readLegacyFile: (path: string) => Promise<string>;
  private readonly hasInjectedReader: boolean;

  // onRetry remains in the stable constructor signature for server/tests. SQLite transactions use
  // their own busy handling inside the worker, so atomic-rename retry reporting no longer applies.
  constructor(
    private readonly cases: CaseStore,
    private readonly onRetry?: (caseId: string, retries: number) => void,
    deps: StateStoreDeps = {},
  ) {
    this.hasInjectedReader = deps.readFile !== undefined;
    this.readLegacyFile = deps.readFile ?? ((path) => readFile(path, "utf8"));
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
        const parsed = JSON.parse(await this.readLegacyFile(this.legacyPath(caseId))) as Partial<InvestigationState>;
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
    return state.forensicTimeline.length
      ? { ...state, forensicTimeline: state.forensicTimeline.map(upgradeForensicEvent) }
      : state;
  }

  async save(state: InvestigationState): Promise<void> {
    const canonicalState = state.forensicTimeline.length
      ? { ...state, forensicTimeline: state.forensicTimeline.map(upgradeForensicEvent) }
      : state;
    await caseSqliteWorker.request<void>({
      op: "saveState",
      dbPath: this.databasePath(canonicalState.caseId),
      state: canonicalState,
    });
    void this.onRetry;
  }

  async queryForensicTimeline(
    caseId: string,
    query: EntityQuery = {},
  ): Promise<EntityPage<ForensicEvent>> {
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
        includeTotal: query.includeTotal,
      },
    });
    return { ...page, entities: page.entities.map(upgradeForensicEvent) };
  }

  async appendForensicEvents(caseId: string, events: readonly ForensicEvent[]): Promise<number> {
    if (!events.length) return 0;
    if (!(await this.ensureMigrated(caseId))) {
      await this.save(emptyState(caseId));
    }
    return caseSqliteWorker.request<number>({
      op: "appendEntities",
      dbPath: this.databasePath(caseId),
      kind: "forensicTimeline",
      entities: events.map(upgradeForensicEvent),
    });
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

  async integrityCheck(caseId: string): Promise<{ ok: boolean; message: string }> {
    return caseSqliteWorker.request({
      op: "integrity",
      dbPath: this.databasePath(caseId),
    });
  }
}
