import type { AuditExportStore } from "../../analysis/auditExportStore.js";
import type { AuditCursorStore } from "../../analysis/auditExportCursor.js";
import { StateLock } from "../../analysis/stateLock.js";
import { toAuditEvent, testAuditEvent, type AuditDestination } from "../../analysis/auditExport.js";
import type { ActivityLogEntry } from "../../analysis/activityLog.js";
import { sendAuditBatch, type AuditSendResult, type AuditTransport } from "./auditSend.js";

// The audit-export runner (#929): forward each case's new activity entries to every enabled
// destination, exactly once, and survive a restart.
//
// Mirrors createNotifier (notifyDispatch.ts) — a factory in the delivery layer, wired from
// composition, with injectable transports so it is testable with no network.
//
// THE TWO RULES THAT MAKE THE FEED TRUSTWORTHY:
//   1. The durable position advances ONLY after a send succeeds. A failed or unknown send leaves
//      the position alone, so the next run re-sends rather than skipping. That is why the
//      Elasticsearch format uses `create` with the entry id (elasticBulkFormat.ts) — a re-send is
//      expected there and must not duplicate a row.
//   2. Work for one (destination, case) pair is serialized. Every activity append can trigger a
//      run, so two runs overlap routinely; without the lock both would read the same position and
//      send the same entries.

/** The slice of ActivityLogStore this runner needs. Narrow on purpose, so tests need no files. */
export interface ActivityReader {
  readBatches(
    caseId: string,
    afterLines: number,
    limit?: number,
  ): AsyncIterable<{ entries: ActivityLogEntry[]; lines: number }>;
  /** Raw line count, for seeding a newly enabled destination at the current end. */
  countLines(caseId: string): Promise<number>;
}

export interface AuditRunResult {
  destinationId: string;
  name: string;
  caseId: string;
  ok: boolean;
  sent: number;
  error?: string;
}

export interface AuditDestinationStatus {
  destinationId: string;
  lastAttemptAt?: string;
  lastSuccessAt?: string;
  lastError?: string;
  sentTotal: number;
}

export interface AuditTestResult extends AuditSendResult {
  destinationId: string;
  name: string;
}

export interface AuditExporterDeps {
  store: AuditExportStore;
  cursors: AuditCursorStore;
  activity: ActivityReader;
  /** Every case id, for a backfill. */
  listCaseIds: () => Promise<string[]>;
  transport: AuditTransport;
  /** Records per request. */
  batchSize?: number;
  log?: (msg: string) => void;
  now?: () => string;
}

export interface AuditExporter {
  /** Forward everything new in one case to every enabled destination. */
  exportCase(caseId: string): Promise<AuditRunResult[]>;
  /**
   * Move one destination's position to the current end of every case, forwarding nothing.
   *
   * This is what makes "switching a destination on forwards only what happens next" true. An
   * unseeded position is zero, so without this the first action after enabling drags the case's
   * entire history to the collector — the opposite of what the Settings pane promises, and the
   * reason Send history is a separate, confirmed button.
   */
  seed(destinationId: string): Promise<void>;
  /**
   * Drain every case for every enabled destination. Called once at startup: a position left behind
   * by a collector outage or a crash is otherwise only noticed the next time that case sees
   * activity, and a closed case never sees any again.
   */
  resume(): Promise<AuditRunResult[]>;
  /** Re-send one destination's whole history, every case, from the beginning. */
  backfill(destinationId: string): Promise<AuditRunResult[]>;
  /** Send one clearly-marked test record to one destination, or to all of them. */
  test(destinationId: string | undefined, at: string): Promise<AuditTestResult[]>;
  /** Last attempt / success / error per destination, for the Settings pane. */
  status(): AuditDestinationStatus[];
}

const DEFAULT_BATCH = 500;

interface MutableStatus {
  lastAttemptAt?: string;
  lastSuccessAt?: string;
  lastError?: string;
  sentTotal: number;
}

export function createAuditExporter(deps: AuditExporterDeps): AuditExporter {
  const now = deps.now ?? (() => new Date().toISOString());
  const batchSize = deps.batchSize ?? DEFAULT_BATCH;
  // Serializes per (destination, case). StateLock keys on a string, so the pair is the key; NUL
  // cannot occur in either id, so the composed key cannot collide.
  const lock = new StateLock();
  // In-memory only. A restart loses it, which is correct: it describes THIS process's attempts,
  // while the durable record of what was delivered is the cursor file.
  const statuses = new Map<string, MutableStatus>();

  const statusFor = (id: string): MutableStatus => {
    const existing = statuses.get(id);
    if (existing) return existing;
    const fresh: MutableStatus = { sentTotal: 0 };
    statuses.set(id, fresh);
    return fresh;
  };

  /**
   * Drain one case into one destination, a batch at a time, stopping at the first failure.
   *
   * Stopping matters: batch N+1 holds later actions than batch N, and shipping it after N failed
   * would put the destination's records out of order AND leave the position ambiguous. The
   * successful prefix is durably recorded; the rest is retried on the next run.
   *
   * The caller holds this (destination, case) pair's lock, so the position is read ONCE and the
   * walk is a single pass over the log rather than a re-read per batch.
   */
  async function drain(destination: AuditDestination, caseId: string): Promise<AuditRunResult> {
    const base = { destinationId: destination.id, name: destination.name, caseId };
    const status = statusFor(destination.id);
    status.lastAttemptAt = now();
    let sent = 0;

    const from = await deps.cursors.get(destination.id, caseId);
    for await (const { entries, lines } of deps.activity.readBatches(caseId, from, batchSize)) {
      if (entries.length === 0) {
        // Every line in this window failed to parse. The position must still move, or the reader
        // returns the same corrupt window forever.
        await deps.cursors.set(destination.id, caseId, lines);
        continue;
      }
      const events = entries.map((entry) => toAuditEvent(entry, caseId));
      const result = await sendAuditBatch(destination, events, deps.transport);
      if (!result.ok) {
        status.lastError = result.error;
        deps.log?.(
          `[audit-export] ${destination.name} (${caseId}): ${result.error ?? "send failed"} — ${sent} record(s) delivered, position held`,
        );
        return { ...base, ok: false, sent, ...(result.error ? { error: result.error } : {}) };
      }
      // Only now is the delivery durable.
      await deps.cursors.set(destination.id, caseId, lines);
      sent += result.sent;
      status.sentTotal += result.sent;
    }

    if (sent > 0) {
      status.lastSuccessAt = now();
      delete status.lastError;
      deps.log?.(`[audit-export] ${destination.name} (${caseId}): ${sent} record(s) forwarded`);
    }
    return { ...base, ok: true, sent };
  }

  const lockKey = (destinationId: string, caseId: string) => `${destinationId}\u0000${caseId}`;

  async function runForCase(destination: AuditDestination, caseId: string): Promise<AuditRunResult> {
    return lock.runExclusive(lockKey(destination.id, caseId), () => drain(destination, caseId));
  }

  async function enabledDestinations(): Promise<AuditDestination[]> {
    try {
      return (await deps.store.load()).filter((d) => d.enabled);
    } catch (err) {
      deps.log?.(`[audit-export] failed to load destinations: ${(err as Error).message}`);
      return [];
    }
  }

  async function exportCase(caseId: string): Promise<AuditRunResult[]> {
    const destinations = await enabledDestinations();
    if (!destinations.length) return [];
    // Per destination in parallel — one unreachable collector must not hold up a healthy one.
    return Promise.all(destinations.map((d) => runForCase(d, caseId)));
  }

  async function seed(destinationId: string): Promise<void> {
    const destination = await deps.store.get(destinationId);
    if (!destination) throw new Error(`audit destination ${destinationId} not found`);
    const caseIds = await deps.listCaseIds();
    for (const caseId of caseIds) {
      // Under the pair's lock, so a concurrent drain cannot read the old position and start
      // sending history between the count and the write.
      await lock.runExclusive(lockKey(destinationId, caseId), async () => {
        await deps.cursors.set(destinationId, caseId, await deps.activity.countLines(caseId));
      });
    }
    deps.log?.(
      `[audit-export] ${destination.name}: positioned at the current end of ${caseIds.length} case(s) — only later activity is forwarded`,
    );
  }

  async function resume(): Promise<AuditRunResult[]> {
    const destinations = await enabledDestinations();
    if (!destinations.length) return [];
    const caseIds = await deps.listCaseIds();
    const results: AuditRunResult[] = [];
    // Sequential: startup recovery is bulk work competing with a server that has just come up.
    for (const destination of destinations) {
      for (const caseId of caseIds) {
        results.push(await runForCase(destination, caseId));
      }
    }
    const sent = results.reduce((n, r) => n + r.sent, 0);
    if (sent > 0) {
      deps.log?.(`[audit-export] resumed: ${sent} record(s) that had not been delivered`);
    }
    return results;
  }

  async function backfill(destinationId: string): Promise<AuditRunResult[]> {
    const destination = await deps.store.get(destinationId);
    if (!destination) throw new Error(`audit destination ${destinationId} not found`);
    // Deliberately explicit, never automatic on enable: a destination switched on mid-investigation
    // would otherwise flood the SIEM with a year of history nobody asked for. #929 left this
    // question unanswered, and "send everything on enable" is the wrong default to pick silently.
    const caseIds = await deps.listCaseIds();
    const results: AuditRunResult[] = [];
    // Sequential across cases: a backfill is bulk work and must not starve live forwarding.
    for (const caseId of caseIds) {
      // RESET AND DRAIN UNDER ONE LOCK. Resetting outside it let a live export finish in between,
      // advance the position to the end, and leave the backfill with nothing to send — so the one
      // operation that exists to re-send everything quietly sent nothing.
      results.push(
        await lock.runExclusive(lockKey(destinationId, caseId), async () => {
          await deps.cursors.reset(destinationId, caseId);
          return drain(destination, caseId);
        }),
      );
    }
    deps.log?.(
      `[audit-export] backfill ${destination.name}: ${results.reduce((n, r) => n + r.sent, 0)} record(s) across ${caseIds.length} case(s)`,
    );
    return results;
  }

  async function test(destinationId: string | undefined, at: string): Promise<AuditTestResult[]> {
    const all = await deps.store.load();
    // A test bypasses the enabled flag so a destination can be verified before it is switched on.
    const targets = destinationId ? all.filter((d) => d.id === destinationId) : all;
    return Promise.all(
      targets.map(async (destination) => {
        const result = await sendAuditBatch(destination, [testAuditEvent(at)], deps.transport);
        const status = statusFor(destination.id);
        status.lastAttemptAt = at;
        if (result.ok) {
          status.lastSuccessAt = at;
          delete status.lastError;
        } else {
          status.lastError = result.error;
        }
        return { ...result, destinationId: destination.id, name: destination.name };
      }),
    );
  }

  function status(): AuditDestinationStatus[] {
    // Synchronous by contract — the route already holds the destination list and joins on id, so
    // reading the store here would make this async for no added truth. It reports only what this
    // process observed.
    return [...statuses.entries()].map(([destinationId, s]) => ({
      destinationId,
      ...(s.lastAttemptAt ? { lastAttemptAt: s.lastAttemptAt } : {}),
      ...(s.lastSuccessAt ? { lastSuccessAt: s.lastSuccessAt } : {}),
      ...(s.lastError ? { lastError: s.lastError } : {}),
      sentTotal: s.sentTotal,
    }));
  }

  return { exportCase, seed, resume, backfill, test, status };
}
