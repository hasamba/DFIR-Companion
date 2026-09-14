import { join } from "node:path";
import { performance } from "node:perf_hooks";
import type { CaseStore } from "../storage/caseStore.js";
import type { EntityPage, EntityQuery } from "./stateStore.js";
import type { ForensicEvent } from "./stateTypes.js";
import { caseSqliteWorker } from "./caseSqliteWorker.js";
import { INVESTIGATION_DB_FILENAME } from "./stateStore.js";
import {
  NO_HOST_FACET,
  STARRED_LABEL,
  TAGGER_AUTHOR_PREFIX,
  superHostOf,
  superOriginOf,
  type SuperLabelMap,
  type SuperQuery,
  type SuperQueryResult,
} from "./superTimeline.js";
import { eventMatchesExclude, eventMatchesSearch } from "./searchFilter.js";
import { upgradeForensicEvent } from "./canonicalEvent.js";
import type { OperationalMetricsStore, QueryIndex } from "./operationalMetrics.js";

// The super-timeline remains logically separate from the forensic timeline: it has a distinct
// entity kind, query API, labels, cap, and no path into synthesis. Sharing the case database is a
// storage detail that makes backup/restore/integrity atomic across both records.
//
// ORDERING (#932 item 12). Every read is event time ascending, and a row with NO time sorts after
// every dated row (the worker's sort sentinel is +MAX; the keyset cursor uses the same one). It used
// to be the reverse: an installed-apps table, which has no clock, was page one of every query and
// the first thing a time window returned. Undated rows stay inside a time window — they cannot be
// proven out of range — but after the dated ones.
//
// RETENTION. The cap bounds UNPROTECTED rows: at `max` unprotected rows it evicts in INSERTION
// order, so the super-timeline keeps the most recently imported `max` unprotected rows, whatever
// their event time, plus every protected row. It used to evict by event time with an undated row
// counting as the oldest, so an undated import was the first thing a case forgot; the opposite
// rank — undated as newest — would let undated rows fill the cap and evict every later dated row
// on arrival while still reporting it added. Insertion order privileges no class of row, and the
// analyst can re-import what it dropped. `append` returns the rows RETAINED after eviction.
//
// PROTECTION (#958). A row the analyst starred or tagged is protected and is never evicted. The
// relation (`super_protected`) lives in the case database beside the rows, is written only for a
// row that exists (a tag on an evicted or unknown id protects nothing and stores nothing), and is
// fed by TagsStore from analyst-authored event tags — never from the automatic tagger, whose tags
// can cover most rows. The legacy `super_labels` sidecar takes no part in it. Migration protects
// tagged legacy rows before the cap runs, and a tagged id that content-dedup drops hands its
// protection to the retained row with the same content. The tags file stays the authority: it is
// written and snapshotted apart from the database, so whenever it changed since the last sync
// (a restore, a crash between the two writes, a case indexed before #958) the worker re-derives
// the exact set from it. Releasing a row — by unstar or by that sync — enforces the cap at once.
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

export interface SuperTimelineMeta {
  rows: number;
  generation: number;
  hosts: string[];
}

export class SuperTimelineStore {
  constructor(
    private readonly cases: CaseStore,
    private readonly max: number = DEFAULT_SUPER_MAX,
    private readonly operationalMetrics?: OperationalMetricsStore,
  ) {}

  private recordQuery(index: QueryIndex, startedAt: number, rows: number): void {
    void this.operationalMetrics?.record({
      type: "query",
      operation: "super_timeline",
      index,
      durationMs: Math.max(0, performance.now() - startedAt),
      rows: Math.max(0, Math.floor(rows)),
    });
  }

  private databasePath(caseId: string): string {
    return join(this.cases.stateDir(caseId), INVESTIGATION_DB_FILENAME);
  }

  private eventsPath(caseId: string): string {
    return join(this.cases.stateDir(caseId), "super-timeline.json");
  }

  private labelsPath(caseId: string): string {
    return join(this.cases.stateDir(caseId), "super-timeline-labels.json");
  }

  // TagsStore's side file; read by the worker only to seed protection at migration time.
  private tagsPath(caseId: string): string {
    return join(this.cases.stateDir(caseId), "tags.json");
  }

  private async ensureMigrated(caseId: string): Promise<void> {
    await caseSqliteWorker.request<void>({
      op: "migrateSuper",
      dbPath: this.databasePath(caseId),
      eventsPath: this.eventsPath(caseId),
      labelsPath: this.labelsPath(caseId),
      tagsPath: this.tagsPath(caseId),
      excludeAuthorPrefix: TAGGER_AUTHOR_PREFIX,
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
    const startedAt = performance.now();
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

    const result = {
      events,
      total,
      origins: [...origins].sort(),
      hosts: [...hosts].sort(),
      labelsAvailable: [...labelsAvailable].sort(),
    };
    this.recordQuery(q.from || q.to ? "timestamp" : "ordinal", startedAt, events.length);
    return result;
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
    const startedAt = performance.now();
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
    const result = {
      ...page,
      entities: page.entities.map(upgradeForensicEvent),
    };
    const index: QueryIndex = query.ioc
      ? "ioc"
      : query.technique
        ? "technique"
        : query.entityId
          ? "entity"
          : query.host
            ? "host"
            : query.source
              ? "source"
              : query.severity
                ? "severity"
                : query.from || query.to
                  ? "timestamp"
                  : "ordinal";
    this.recordQuery(index, startedAt, result.entities.length);
    return result;
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

  // Legacy label sidecar. False when the row is not in the store — nothing is written for it.
  async setLabels(caseId: string, eventId: string, labels: string[]): Promise<boolean> {
    await this.ensureMigrated(caseId);
    return caseSqliteWorker.request<boolean>({
      op: "setSuperLabels",
      dbPath: this.databasePath(caseId),
      eventId,
      labels,
    });
  }

  // Exempt one row from the cap. False when the row is not in the store (unknown, or already
  // evicted): the relation never names a row that is not there, so the caller learns the tag it is
  // syncing points at nothing.
  async protect(caseId: string, eventId: string): Promise<boolean> {
    await this.ensureMigrated(caseId);
    return caseSqliteWorker.request<boolean>({
      op: "protectSuper",
      dbPath: this.databasePath(caseId),
      eventId,
    });
  }

  async unprotect(caseId: string, eventId: string): Promise<void> {
    await this.ensureMigrated(caseId);
    await caseSqliteWorker.request<void>({
      op: "unprotectSuper",
      dbPath: this.databasePath(caseId),
      eventId,
      max: this.max,
    });
  }

  /**
   * The store's row count, mutation generation and distinct host spellings as stored — for a
   * reader that must say whether the store changed under it and which spellings to query (#969).
   * Index-only in the worker; never decodes a payload.
   */
  /** The retention cap this store enforces. */
  get cap(): number {
    return this.max;
  }

  async meta(caseId: string): Promise<SuperTimelineMeta> {
    await this.ensureMigrated(caseId);
    return caseSqliteWorker.request<SuperTimelineMeta>({
      op: "superMeta",
      dbPath: this.databasePath(caseId),
    });
  }

  /**
   * Time-bounded raw rows for an analyst-initiated, ephemeral read (ARCHITECTURE.md, the
   * remediation-check exception, #969): every row in [from, to] in store order, undated rows
   * included (the caller counts and skips them), stopping after `budget` rows read.
   */
  async *scanWindow(
    caseId: string,
    time: { from: string; to: string },
    budget: number,
  ): AsyncGenerator<ForensicEvent> {
    await this.ensureMigrated(caseId);
    let read = 0;
    for await (const row of this.scan(caseId, time)) {
      if (read >= budget) return;
      read += 1;
      yield row.event;
    }
  }

  async protectedIds(caseId: string): Promise<string[]> {
    await this.ensureMigrated(caseId);
    return caseSqliteWorker.request<string[]>({
      op: "listSuperProtected",
      dbPath: this.databasePath(caseId),
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
