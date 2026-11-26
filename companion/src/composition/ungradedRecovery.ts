/**
 * Start-up re-grade of the rows still waiting for the content tagger (#2891, analysis/gradeMark.ts).
 *
 * WHY. A row an import added carries the mark from its insert (#2909, an armed section) or its stamp,
 * and only the tagger's finished run removes it. A crash (an out-of-memory kill) before the tag, an
 * importer that threw after a partial merge, or a tagger that failed internally leaves marked rows. The
 * case-wide demote never moves them, so nothing is lost — but they are not graded either, and Info rows
 * among them still sit in the forensic timeline. The next import's settle grades them (#2909,
 * routes/importRegrade.ts sweepLeftovers, bounded); this is the backstop that grades every case at
 * start-up, on the same core: stamp if needed → dual-write → tagger → caps → demote → remove the mark.
 *
 * WHAT IT SELECTS (its own contract, unlike the in-process recovery that selects by file):
 *   - exactly the marked rows. A marked row the gate never touches (promoted, manual, a coverage note)
 *     only loses its mark: it is never re-tagged or demoted, and keeps its stored severity. A marked row
 *     with no stamp is stamped (an importer that threw before its settle);
 *   - plus the UNSTAMPED rows of the same stored file as a marked batch — rows the paged stamp never
 *     reached before the crash ("stamp if needed"). They get that batch's id, its import time and the
 *     mark. Stamped rows are not stamped again; graded rows of the batch are not re-tagged.
 *   - a grade arm a crash left set is dropped first (no section can be open while this holds the case).
 *
 * WHEN. After the server listens (maintenanceTasks.ts), never from createApp, so tests that only build
 * the app never run it. One case at a time, in its own incarnation, inside the case's import section
 * (runExclusive: it waits behind the hunt start-up holds, takes no hold of its own, and calls nothing
 * that takes the section again). No hold is needed: the demote holds marked rows, so there is no race.
 * Reads the forensic timeline only. A tagger that keeps failing leaves rows marked; they are retried at
 * the next start, with one WARN per case.
 */
import { gateExempt } from "../analysis/forensicGate.js";
import { disarmGrade, forensicGradePendingIds, gradeProbe } from "../analysis/gradeMark.js";
import { SCAN_PAGE_ROWS, type ForensicRowStore } from "../analysis/forensicRows.js";
import type { InvestigationState } from "../analysis/stateTypes.js";
import { generationOf, runInCaseScope } from "../storage/caseIncarnation.js";
import { getServerLogger } from "../logging/serverLogger.js";
import type { RouteContext } from "../routes/context.js";
import { routeSettleDeps } from "../routes/routeSettleDeps.js";
import { recoveryDepsFromSettle, type RowRecoveryDeps } from "../routes/importRowRecovery.js";
import { finishRegrade, regradeMarked } from "../routes/importRegrade.js";
import { carryAndStampPaged } from "../routes/importSettlePaged.js";
import { rowPages, runUnlocked } from "../routes/importSettleRows.js";

export interface Regrade {
  /** Rows the tagger was offered again (marked rows plus the unstamped rows of their files). */
  regraded: number;
  /** Rows still marked afterwards: the tagger did not finish on them. */
  held: number;
  /** Marked rows out of the gate's reach whose mark was only removed. */
  cleared: number;
}

const NOTHING: Regrade = { regraded: 0, held: 0, cleared: 0 };

const ledgerOf =
  (store: ForensicRowStore): ((caseId: string) => Promise<InvestigationState>) =>
  (caseId) =>
    store.loadOverviewWithoutIocs ? store.loadOverviewWithoutIocs(caseId) : store.loadOverview(caseId);

/**
 * Re-grade one case's marked rows. Takes no import lock: the caller holds the case's section, so no
 * import is in flight — a grade arm still set is a crash's leftover and is dropped first (#2909).
 */
export async function regradePendingRows(deps: RowRecoveryDeps, caseId: string): Promise<Regrade> {
  const store = deps.stateStore;
  await disarmGrade(store, caseId);
  const ids = await forensicGradePendingIds(store, caseId);
  if (!ids.length) return NOTHING;
  const ledger = await ledgerOf(store)(caseId);
  const siblings = await stampUnreachedRows(deps, caseId, ids, ledger);
  const all = [...new Set([...ids, ...siblings])];
  const done = await regradeMarked(deps, caseId, all, { ledger });
  await finishRegrade(deps, caseId, { ...done, ledger });
  const still = new Set(await forensicGradePendingIds(store, caseId));
  const held = all.filter((id) => still.has(id)).length;
  return { regraded: done.offered, held, cleared: done.cleared };
}

/**
 * The unstamped, gate-reachable rows that carry a stored name of a marked, stamped batch: stamped with
 * that batch's id and import time, and the mark. Marked rows are read a page at a time; one scan of the
 * forensic timeline finds the siblings for every batch.
 */
async function stampUnreachedRows(
  deps: RowRecoveryDeps,
  caseId: string,
  markedIds: readonly string[],
  ledger: InvestigationState,
): Promise<string[]> {
  const store = deps.stateStore;
  const batchOf = new Map<string, { id: string; importedAt?: string }>();
  for await (const rows of rowPages(store, caseId, markedIds))
    for (const { event: e } of rows) {
      if (!e.importBatchId) continue;
      for (const name of e.sourceScreenshots)
        if (typeof name === "string" && !batchOf.has(name))
          batchOf.set(name, { id: e.importBatchId, importedAt: e.importedAt });
    }
  if (!batchOf.size) return [];
  const byBatch = new Map<string, { importedAt?: string; ids: string[] }>();
  for await (const page of store.forensicTimelineBatches(caseId, { limit: SCAN_PAGE_ROWS }))
    for (const e of page) {
      if (e.importBatchId || gateExempt(e)) continue;
      const batch = e.sourceScreenshots.map((s) => batchOf.get(s)).find((b) => !!b);
      if (!batch) continue;
      const entry = byBatch.get(batch.id) ?? { importedAt: batch.importedAt, ids: [] };
      entry.ids.push(e.id);
      byBatch.set(batch.id, entry);
    }
  const lock = deps.runStateExclusive ?? runUnlocked;
  const stampedIds: string[] = [];
  for (const [importBatchId, { importedAt, ids }] of byBatch) {
    const scope = { addedIds: ids, touchedRowIds: [], touchedKnown: true, mergedCount: 0 };
    const stamped = await lock(caseId, () =>
      carryAndStampPaged(store, caseId, ledger, scope, false, {
        capturedAt: undefined,
        downgrade: !!deps.superTimelineStore,
        importBatchId,
        importedAt,
        gradePending: !deps.superTimelineStore || deps.markGradePending === false ? false : true,
      }),
    );
    stampedIds.push(...stamped.addedIds);
  }
  return stampedIds;
}

const errorText = (err: unknown): string => (err as Error)?.message ?? String(err);

/**
 * One case: ask first (one query, no lock); take the case's import section only when the case carries
 * a grade arm (a section a crash never finished, #2909) or marked rows.
 */
async function regradeCase(ctx: RouteContext, deps: RowRecoveryDeps, caseId: string): Promise<void> {
  const probe = await gradeProbe(deps.stateStore, caseId);
  if (!probe.armed && !probe.marked) return;
  const done = await ctx.importLock.runExclusive(caseId, () => regradePendingRows(deps, caseId));
  if (done === NOTHING) return;
  getServerLogger().warn(
    `[import] ${caseId}: start-up re-grade — ${done.regraded} row(s) offered to the content tagger again, ` +
      `${done.held} still waiting for it, ${done.cleared} promoted/manual row(s) unmarked`,
    { caseId },
  );
}

/** The start-up sweep over every case (startServer hands it to startPostListenTasks). Never rejects. */
export function ungradedRowRecovery(ctx: RouteContext): () => Promise<void> {
  return async () => {
    const settle = routeSettleDeps(ctx);
    if (!settle) return;
    const deps = recoveryDepsFromSettle(settle);
    let cases: Awaited<ReturnType<RouteContext["store"]["listCases"]>> = [];
    try {
      cases = await ctx.store.listCases();
    } catch (err) {
      getServerLogger().warn(`[import] start-up re-grade could not list the cases: ${errorText(err)}`);
      return;
    }
    for (const listed of cases) {
      const caseId = listed.caseId;
      const run = () => regradeCase(ctx, deps, caseId);
      await runInCaseScope(ctx.store.casesRoot, caseId, run, generationOf(listed)).catch((err: unknown) =>
        getServerLogger().warn(`[import] ${caseId}: start-up re-grade failed: ${errorText(err)}`, { caseId }),
      );
    }
  };
}
