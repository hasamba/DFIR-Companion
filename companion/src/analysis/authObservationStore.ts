// Cross-upload password-spray detection (#1104, second half of 930.5 / 931.3): a durable per-case
// record of every authentication attempt an import produced a SprayCandidate for, so a spray whose
// attempts are split across two separate uploads — or a low-and-slow spray an analyst uploads in
// daily batches — can still cross the existing threshold when the two uploads are summed.
//
// A sibling to superTimelineStore.ts over the SAME case SQLite database (INVESTIGATION_DB_FILENAME),
// reusing caseSqliteWorker's generic kind-based entities table (kind: "authObservation") — no new
// table, no schema migration, and unlike superTimelineStore.ts, no legacy-JSON migration story: this
// store has no predecessor, so it never needs one.
//
// Internal bookkeeping only — never surfaced to AI, the dashboard, or any report (same status as
// jobLedgerStore.ts). It is a THIRD, purely internal store; it only ever feeds the existing
// deterministic passwordSprayPatterns(), whose OUTPUT goes through the same import -> merge ->
// tagger -> forensic-timeline path the within-upload rows already use. No forensic/super-timeline
// boundary change (CLAUDE.md §7).
//
// Domain (scripts/module-map.json): analysis/ingest, not analysis/timeline like its model
// superTimelineStore.ts — this file imports sprayObservationKey() from passwordSprayFanout.ts
// (analysis/ingest, tier 3), and a lower-tier analysis/timeline (tier 0) importing UP from
// analysis/ingest is exactly the boundary check:boundaries exists to catch. Filed at the tier its
// real dependency lives at, per ARCHITECTURE.md's own guidance for a module in the wrong domain.

import { createHash } from "node:crypto";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import type { CaseStore } from "../storage/caseStore.js";
import { caseSqliteWorker } from "./caseSqliteWorker.js";
import { INVESTIGATION_DB_FILENAME } from "./stateStore.js";
import { sprayObservationKey, type SprayOutcome } from "./passwordSprayFanout.js";
import type { OperationalMetricsStore } from "./operationalMetrics.js";

// What one stored sign-in established (#2301): the spray pair (failed / success), an MFA
// interruption (required, denied or timed out — kept for MFA-fatigue detection, #2306), or any
// other outcome. Only failed/success rows ever feed the password-spray detector.
export type AuthObservationOutcome = SprayOutcome | "interrupted" | "other";
// "unconfirmed" (#2306): a 500121 strong-auth failure whose detail does not say denied or timed out —
// an interruption, but never counted as a rejected prompt by MFA-fatigue detection.
export type MfaDetail = "required" | "denied" | "timed out" | "approved" | "unconfirmed";

export interface StoredAuthObservation {
  timestamp: string; // ISO
  account: string;
  sourceIp: string; // "" when the record named none (never counted as a spray attempt)
  hostOrTenant: string;
  outcome: AuthObservationOutcome;
  locator: string; // this observation's own raw-record locator, from its own upload
  importer: string; // "ecar" | "m365"
  importBatch: string; // the importing call's own opts.idPrefix
  // Sign-in detail (#2301), set by importers that read it (m365Import.ts via signInObservation.ts).
  resultCode?: string;
  mfaDetail?: MfaDetail;
  authMethod?: string;
  sessionId?: string;
  correlationId?: string;
  app?: string;
  recordId?: string; // the record's cloud identity key (cloudRecordIdentity.ts)
}

export interface AuthObservationWindow {
  observations: StoredAuthObservation[];
  truncated: boolean; // true iff more rows existed in the window than AUTH_OBSERVATION_QUERY_MAX
}

/** One page of a tenant / account / time-window query, oldest first. */
export interface AuthObservationPage {
  observations: StoredAuthObservation[];
  next: AuthObservationCursor | null; // null on the last page
}
export interface AuthObservationCursor {
  ms: number;
  rowId: number;
}
export interface AuthObservationQuery {
  since?: string; // ISO, inclusive
  until?: string; // ISO, inclusive
  tenant?: string;
  account?: string; // compared trimmed + lowercased
  after?: AuthObservationCursor;
  limit?: number; // per page; the worker bounds it
}

// Measured in EVIDENCE time (#2301): rows older than the newest stored observation minus this span
// are pruned. Never the wall clock — an export of last year's activity is evidence, not stale.
export const DEFAULT_AUTH_OBSERVATION_RETENTION_HOURS = 168; // 7 days
// Bounds one query's memory. Matches SuperTimelineStore's own retention-cap order of magnitude
// (DEFAULT_SUPER_MAX = 100_000) rather than a narrower figure, since a real tenant can produce
// tens of thousands of sign-in records inside a 7-day window on its own.
export const AUTH_OBSERVATION_QUERY_MAX = 100_000;
const KIND = "authObservation";
// hasEntityIds builds one JSON array for its whole `ids` list — chunked so one M365 export with
// hundreds of thousands of candidates never builds a single multi-hundred-thousand-entry array.
const APPEND_CHUNK_SIZE = 5_000;
// A prune DELETE runs at most this often per case, not on every append, so a long-running case's
// steady trickle of imports never pays a prune-transaction cost on each one.
const PRUNE_THROTTLE_MS = 60 * 60 * 1000;

// The stable on-disk identity of one observation. Reuses sprayObservationKey() — the SAME identity
// rule dedupExact() applies in-memory — hashed to a short opaque id so the SQLite entity_id column
// never carries a raw account name. Deliberately excludes importBatch: two uploads describing the
// same real auth attempt (overlapping export windows, a re-uploaded file) must collapse to one
// stored observation, or an overlapping re-export would inflate the distinct-account count.
// A row that carries its cloud record id (#2301) is identified by that id instead: two MFA prompts
// in the same second are two records, and the spray key alone would fold them into one.
function observationId(o: StoredAuthObservation): string {
  const key = o.recordId ? `record|${o.recordId}` : sprayObservationKey(o);
  return createHash("sha256").update(key).digest("hex").slice(0, 16);
}

export class AuthObservationStore {
  private readonly lastPrunedAtMs = new Map<string, number>();

  constructor(
    private readonly cases: CaseStore,
    private readonly retentionHoursValue: number = DEFAULT_AUTH_OBSERVATION_RETENTION_HOURS,
    private readonly operationalMetrics?: OperationalMetricsStore,
  ) {}

  /** The retention window this store enforces, in hours. */
  retentionHours(): number {
    return this.retentionHoursValue;
  }

  private databasePath(caseId: string): string {
    return join(this.cases.stateDir(caseId), INVESTIGATION_DB_FILENAME);
  }

  private async pruneIfDue(caseId: string, dbPath: string): Promise<void> {
    const now = Date.now();
    const last = this.lastPrunedAtMs.get(caseId) ?? 0;
    if (now - last < PRUNE_THROTTLE_MS) return;
    // Set BEFORE the await, not after (#1239): this.lastPrunedAtMs also throttles a second
    // concurrent append() for the same case (an import burst) from racing a duplicate prune while
    // the first is still in flight. On failure, roll the timestamp back to its previous value —
    // a transient worker error must not cost this case a full extra hour of accumulating expired
    // rows before the next attempt. The throttle is wall-clock (it paces work); the retention cut
    // is evidence time (#2301): older than the newest stored observation minus the span.
    this.lastPrunedAtMs.set(caseId, now);
    try {
      await caseSqliteWorker.request<number>({
        op: "pruneEntitiesBeforeNewest",
        dbPath,
        kind: KIND,
        spanMs: this.retentionHoursValue * 3_600_000,
      });
    } catch (err) {
      if (this.lastPrunedAtMs.get(caseId) === now) this.lastPrunedAtMs.set(caseId, last);
      throw err;
    }
  }

  /**
   * Appends observations not already stored (by observationId), after a throttled retention
   * prune. Returns the number of NEW rows actually written — a re-append of an already-stored
   * observation, or a re-import of the identical file, writes zero new rows.
   */
  async append(caseId: string, observations: StoredAuthObservation[]): Promise<number> {
    if (!observations.length) return 0;
    const dbPath = this.databasePath(caseId);
    await this.pruneIfDue(caseId, dbPath);

    let added = 0;
    for (let i = 0; i < observations.length; i += APPEND_CHUNK_SIZE) {
      const chunk = observations.slice(i, i + APPEND_CHUNK_SIZE);
      const withIds = chunk.map((o) => ({ ...o, id: observationId(o) }));
      const ids = withIds.map((o) => o.id);
      const existing = await caseSqliteWorker.request<string[]>({
        op: "hasEntityIds",
        dbPath,
        kind: KIND,
        ids,
      });
      const existingSet = new Set(existing);
      const fresh = withIds.filter((o) => !existingSet.has(o.id));
      if (fresh.length) {
        added += await caseSqliteWorker.request<number>({
          op: "appendEntities",
          dbPath,
          kind: KIND,
          entities: fresh,
        });
      }
    }
    return added;
  }

  /**
   * Every stored observation with timestamp >= sinceIso, newest first, capped at
   * AUTH_OBSERVATION_QUERY_MAX — `truncated: true` when more rows existed in the window than the
   * cap, so a caller can disclose the bound rather than silently searching a partial history.
   */
  async queryWindow(
    caseId: string,
    sinceIso: string,
    // Only failed/success rows with a source IP (#2301), filtered before the cap.
    opts: { sprayOnly?: boolean } = {},
  ): Promise<AuthObservationWindow> {
    const startedAt = performance.now();
    const dbPath = this.databasePath(caseId);
    const sinceMs = Date.parse(sinceIso);
    const result = await caseSqliteWorker.request<{
      entities: StoredAuthObservation[];
      truncated: boolean;
    }>({
      op: "queryAuthObservationsWindow",
      dbPath,
      sinceMs: Number.isFinite(sinceMs) ? sinceMs : 0,
      limit: AUTH_OBSERVATION_QUERY_MAX,
      sprayOnly: opts.sprayOnly === true,
    });
    void this.operationalMetrics?.record({
      type: "query",
      operation: "auth_observation",
      index: "timestamp",
      durationMs: Math.max(0, performance.now() - startedAt),
      rows: result.entities.length,
    });
    return { observations: result.entities, truncated: result.truncated };
  }

  /**
   * One page of stored observations, oldest first, filtered by evidence-time window and optionally
   * by tenant and account (#2301). Keyset-paged on (timestamp, row): walking `next` until it is null
   * returns every matching row, however many — no fixed cap can hide part of a sequence.
   */
  async queryPage(caseId: string, query: AuthObservationQuery = {}): Promise<AuthObservationPage> {
    const ms = (iso: string | undefined, fallback: number): number => {
      const t = iso ? Date.parse(iso) : NaN;
      return Number.isFinite(t) ? t : fallback;
    };
    return caseSqliteWorker.request<AuthObservationPage>({
      op: "authObservationsPage",
      dbPath: this.databasePath(caseId),
      query: {
        sinceMs: ms(query.since, 0),
        untilMs: ms(query.until, 8.64e15),
        tenant: query.tenant,
        account: query.account,
        after: query.after,
        limit: query.limit,
      },
    });
  }
}
