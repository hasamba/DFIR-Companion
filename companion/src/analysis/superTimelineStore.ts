import { join } from "node:path";
import type { CaseStore } from "../storage/caseStore.js";
import type { EntityPage, EntityQuery } from "./stateStore.js";
import type { ForensicEvent } from "./stateTypes.js";
import { caseSqliteWorker } from "./caseSqliteWorker.js";
import { INVESTIGATION_DB_FILENAME } from "./stateStore.js";
import {
  NO_HOST_FACET,
  STARRED_LABEL,
  superHostOf,
  superOriginOf,
  type SuperLabelMap,
  type SuperQuery,
  type SuperQueryResult,
} from "./superTimeline.js";
import { eventMatchesExclude, eventMatchesSearch } from "./searchFilter.js";
import { upgradeForensicEvent } from "./canonicalEvent.js";

// The super-timeline remains logically separate from the forensic timeline: it has a distinct
// entity kind, query API, labels, cap, and no path into synthesis. Sharing the case database is a
// storage detail that makes backup/restore/integrity atomic across both records.
export const DEFAULT_SUPER_MAX = 100_000;
export const DEFAULT_SUPER_QUERY_LIMIT = 500;
const SCAN_BATCH_SIZE = 1_000;
const MAX_QUERY_PAGE = 10_000;

interface SuperScanRow {
  event: ForensicEvent;
  labels: string[];
  rowId: number;
  sortMs: number;
}

interface SuperScanCursor {
  afterMs: number;
  afterRowId: number;
}

interface SuperScanResult {
  rows: SuperScanRow[];
  nextCursor: SuperScanCursor | null;
}

export class SuperTimelineStore {
  constructor(
    private readonly cases: CaseStore,
    private readonly max: number = DEFAULT_SUPER_MAX,
  ) {}

  private databasePath(caseId: string): string {
    return join(this.cases.stateDir(caseId), INVESTIGATION_DB_FILENAME);
  }

  private eventsPath(caseId: string): string {
    return join(this.cases.stateDir(caseId), "super-timeline.json");
  }

  private labelsPath(caseId: string): string {
    return join(this.cases.stateDir(caseId), "super-timeline-labels.json");
  }

  private async ensureMigrated(caseId: string): Promise<void> {
    await caseSqliteWorker.request<void>({
      op: "migrateSuper",
      dbPath: this.databasePath(caseId),
      eventsPath: this.eventsPath(caseId),
      labelsPath: this.labelsPath(caseId),
      max: this.max,
    });
  }

  async append(caseId: string, events: ForensicEvent[]): Promise<number> {
    if (!events.length) return 0;
    await this.ensureMigrated(caseId);
    return caseSqliteWorker.request<number>({
      op: "appendSuper",
      dbPath: this.databasePath(caseId),
      events: events.map(upgradeForensicEvent),
      max: this.max,
    });
  }

  /**
   * Filter, facet, and paginate while scanning SQLite in fixed-size pages. Facets retain their
   * existing semantics (time-window only, independent of origin/label selection), but no complete
   * event array is created just to return one dashboard page.
   */
  async query(caseId: string, q: SuperQuery = {}, labelMap?: SuperLabelMap): Promise<SuperQueryResult> {
    await this.ensureMigrated(caseId);
    const originSet = q.origins?.length ? new Set(q.origins) : null;
    const excludeSet = q.exclude?.length ? new Set(q.exclude) : null;
    const excludeHostSet = q.excludeHosts?.length ? new Set(q.excludeHosts) : null;
    const labelSet = q.labels?.length ? new Set(q.labels) : null;
    const origins = new Set<string>();
    const hosts = new Set<string>();
    const labelsAvailable = new Set<string>();
    const offset = Math.max(0, Math.floor(q.offset ?? 0));
    const requestedLimit = q.limit == null ? DEFAULT_SUPER_QUERY_LIMIT : Math.max(0, Math.floor(q.limit));
    const limit = Math.min(requestedLimit, MAX_QUERY_PAGE);
    const events: ForensicEvent[] = [];
    let total = 0;

    for await (const row of this.scan(caseId, { from: q.from, to: q.to })) {
      const event = row.event;
      const labels = labelMap?.[event.id] ?? row.labels;
      const origin = superOriginOf(event);
      const host = superHostOf(event);
      origins.add(origin);
      hosts.add(host || NO_HOST_FACET);
      for (const label of labels) if (label !== STARRED_LABEL) labelsAvailable.add(label);

      if (originSet && !originSet.has(origin)) continue;
      if (excludeSet && excludeSet.has(origin)) continue;
      if (excludeHostSet && excludeHostSet.has(host)) continue;
      if (labelSet && !labels.some((label) => labelSet.has(label))) continue;
      if (q.taggedOnly && !labels.some((label) => label !== STARRED_LABEL)) continue;
      if (q.starred && !labels.includes(STARRED_LABEL)) continue;
      if (q.search && !eventMatchesSearch(event, q.search)) continue;
      if (q.excludeText?.length && eventMatchesExclude(event, q.excludeText)) continue;

      if (total >= offset && events.length < limit) events.push(event);
      total++;
    }

    return {
      events,
      total,
      origins: [...origins].sort(),
      hosts: [...hosts].sort(),
      labelsAvailable: [...labelsAvailable].sort(),
    };
  }

  async get(caseId: string, id: string): Promise<ForensicEvent | null> {
    await this.ensureMigrated(caseId);
    const event = await caseSqliteWorker.request<ForensicEvent | null>({
      op: "getSuper",
      dbPath: this.databasePath(caseId),
      id,
    });
    return event ? upgradeForensicEvent(event) : null;
  }

  /**
   * Typed-workbench read path. It shares the normalized entity indexes with the forensic timeline,
   * but keeps the dataset kind explicit so a caller can never accidentally cross the synthesis seam.
   */
  async queryIndexed(caseId: string, query: EntityQuery = {}): Promise<EntityPage<ForensicEvent>> {
    await this.ensureMigrated(caseId);
    const indexName = query.ioc ? "ioc" : query.technique ? "technique" : undefined;
    const page = await caseSqliteWorker.request<{
      entities: ForensicEvent[];
      nextCursor: number | null;
      total: number;
    }>({
      op: "queryEntities",
      dbPath: this.databasePath(caseId),
      kind: "superTimeline",
      query: {
        afterOrdinal: query.cursor,
        limit: query.limit ?? DEFAULT_SUPER_QUERY_LIMIT,
        from: query.from,
        to: query.to,
        host: query.host,
        source: query.source,
        severity: query.severity,
        entityId: query.entityId,
        indexName,
        indexValue: query.ioc ?? query.technique,
        includeTotal: query.includeTotal,
      },
    });
    return {
      ...page,
      entities: page.entities.map(upgradeForensicEvent),
    };
  }

  // Compatibility method for the tagger and targeted AI lookup. New large-case consumers should
  // iterate eventBatches() so their working set stays bounded.
  async all(caseId: string): Promise<ForensicEvent[]> {
    const events: ForensicEvent[] = [];
    for await (const batch of this.eventBatches(caseId)) events.push(...batch);
    return events;
  }

  async *eventBatches(caseId: string, batchSize = SCAN_BATCH_SIZE): AsyncGenerator<ForensicEvent[]> {
    await this.ensureMigrated(caseId);
    let batch: ForensicEvent[] = [];
    for await (const row of this.scan(caseId, {}, batchSize)) {
      batch.push(row.event);
      if (batch.length >= batchSize) {
        yield batch;
        batch = [];
      }
    }
    if (batch.length) yield batch;
  }

  async setLabels(caseId: string, eventId: string, labels: string[]): Promise<void> {
    await this.ensureMigrated(caseId);
    await caseSqliteWorker.request<void>({
      op: "setSuperLabels",
      dbPath: this.databasePath(caseId),
      eventId,
      labels,
    });
  }

  private async *scan(
    caseId: string,
    time: { from?: string; to?: string },
    batchSize = SCAN_BATCH_SIZE,
  ): AsyncGenerator<SuperScanRow> {
    let cursor: SuperScanCursor | null = null;
    do {
      const result: SuperScanResult = await caseSqliteWorker.request<SuperScanResult>({
        op: "scanSuper",
        dbPath: this.databasePath(caseId),
        query: {
          from: time.from,
          to: time.to,
          afterMs: cursor?.afterMs,
          afterRowId: cursor?.afterRowId,
          limit: Math.max(1, Math.min(MAX_QUERY_PAGE, Math.floor(batchSize))),
        },
      });
      for (const row of result.rows) yield { ...row, event: upgradeForensicEvent(row.event) };
      cursor = result.nextCursor;
    } while (cursor);
  }
}
