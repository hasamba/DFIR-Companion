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

export interface StoredAuthObservation {
  timestamp: string; // ISO
  account: string;
  sourceIp: string;
  hostOrTenant: string;
  outcome: SprayOutcome;
  locator: string; // this observation's own raw-record locator, from its own upload
  importer: string; // "ecar" | "m365"
  importBatch: string; // the importing call's own opts.idPrefix
}

export interface AuthObservationWindow {
  observations: StoredAuthObservation[];
  truncated: boolean; // true iff more rows existed in the window than AUTH_OBSERVATION_QUERY_MAX
}

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
function observationId(o: StoredAuthObservation): string {
  return createHash("sha256").update(sprayObservationKey(o)).digest("hex").slice(0, 16);
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
    this.lastPrunedAtMs.set(caseId, now);
    const beforeMs = now - this.retentionHoursValue * 3_600_000;
    await caseSqliteWorker.request<number>({
      op: "pruneEntitiesBefore",
      dbPath,
      kind: KIND,
      beforeMs,
    });
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
  async queryWindow(caseId: string, sinceIso: string): Promise<AuthObservationWindow> {
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
}
