/**
 * Settle the rows an import left unsettled when its own settle did not run or did not finish
 * (#2890; the hunt-collect precedent is #2851/#2852, composition/veloHuntRecovery.ts).
 *
 * WHY. An import merges its rows into the forensic timeline, and only its settle
 * (routes/importSettle.ts) stamps them, dual-writes them, runs the tagger and demotes. When the
 * pre-import snapshot could not be read, or the settle threw partway, those rows stay in the forensic
 * timeline unsettled. The next import settles only its own new rows, but its demote is case-wide: it
 * moves them out UNTAGGED, so a row the tagger would have graded up (NTDS.dit, `\Windows\Temp\*.ps1`)
 * never reaches the forensic timeline or the AI, and nothing says so.
 *
 * WHAT. Select this import's rows by their source — importers stamp the stored name on each row as
 * `sourceScreenshots` — that carry no import stamp, or carry the batch id the failed settle preset
 * (#2888: a settle that failed during or after the stamp leaves stamped rows). Then run the settle's
 * own steps on them: stamp with the SAME id (a second failure leaves them findable), dual-write,
 * tagger, demote — merge-all → tagger → demote, as every import. Rows the failed settle stamped keep
 * its import time, and the rows it did not reach get that same time: one instant, one batch. Rows an
 * analyst or Watson promoted and manual rows are never the import's. Nothing selected → no demote.
 *
 * Not recovered: the import record, the Undo checkpoint, and the settle's look-alike / cap passes.
 *
 * In routes/ (not composition/) because both route layers and composition call it, and routes may
 * not import composition. It takes no lock: every caller already holds the case's import section,
 * which is not re-entrant. The restart window (a crash between stamp and tag) is covered by the grade
 * mark and start-up recovery instead (#2891, analysis/gradeMark.ts, composition/ungradedRecovery.ts).
 */
import { randomUUID } from "node:crypto";
import { disarmGrade, type DemoteOptions, type TagOutcome } from "../analysis/gradeMark.js";
import { finishRegrade } from "./importRegrade.js";
import type { CapCandidates } from "./importSettleCap.js";
import { SCAN_PAGE_ROWS, type ForensicRowStore } from "../analysis/forensicRows.js";
import { isManualId } from "../analysis/manualId.js";
import { getServerLogger } from "../logging/serverLogger.js";
import {
  carryAndStampPaged,
  clearGradePending,
  dualWriteAndTagPaged,
  type DualWriteDeps,
} from "./importSettlePaged.js";
import { runUnlocked, type RunExclusive } from "./importSettleRows.js";
import {
  failedAfterGrading,
  settleForensicImport,
  type SettleDeps,
  type SettledImport,
} from "./importSettle.js";
import type { ImportBaseline } from "../analysis/importBaseline.js";
import type { ForensicEvent, InvestigationState } from "../analysis/stateTypes.js";

export interface RowRecoveryDeps {
  stateStore: ForensicRowStore;
  runStateExclusive?: RunExclusive;
  superTimelineStore?: DualWriteDeps["superTimelineStore"];
  onSuperTimeline?: (caseId: string) => void;
  autoTagImported: (caseId: string, added: ForensicEvent[]) => Promise<TagOutcome>;
  /** The case-wide forensic demote (either flavour; its result is not read). `graded`: see SettleDeps. */
  demote: (caseId: string, opts?: DemoteOptions) => Promise<unknown>;
  /** The held tagger for rows marked "held" (#2909, SettleDeps.tagHeld). */
  tagHeld?: (caseId: string, added: ForensicEvent[]) => Promise<TagOutcome>;
  /** False: write no grade mark; "held": a Watson paste's mark (SettleDeps.markGradePending). */
  markGradePending?: boolean | "held";
}

/** True for a row source (a stored name) that belongs to the import being recovered. */
export type RowSource = (source: string) => boolean;

/** Unstamped, or stamped by the failed settle's own batch — never another import's batch. */
function unsettled(e: ForensicEvent, ofImport: RowSource, batchId: string | undefined): boolean {
  return (
    (!e.importBatchId || (batchId !== undefined && e.importBatchId === batchId)) &&
    !e.promotedAt &&
    !isManualId(e.id) &&
    e.sourceScreenshots.some((s) => typeof s === "string" && ofImport(s))
  );
}

/**
 * The core: settle the selected rows. Takes no lock (the caller holds the import section) and
 * THROWS on a store failure. Returns null when nothing was selected, else how many rows it settled.
 */
export async function settleUnsettledRows(
  deps: RowRecoveryDeps,
  caseId: string,
  ofImport: RowSource,
  batchId?: string,
): Promise<number | null> {
  const store = deps.stateStore;
  const lock = deps.runStateExclusive ?? runUnlocked;
  await disarmGrade(store, caseId); // #2909: the importer's merge window is over (importSettle.ts)
  const ids: string[] = [];
  let importedAt: string | undefined; // the failed settle's own instant, when it stamped any row
  for await (const page of store.forensicTimelineBatches(caseId, { limit: SCAN_PAGE_ROWS }))
    for (const e of page) {
      if (!unsettled(e, ofImport, batchId)) continue;
      ids.push(e.id);
      if (!importedAt && batchId && e.importBatchId === batchId) importedAt = e.importedAt;
    }
  if (!ids.length) return null; // nothing of this import is unsettled: no case-wide demote either
  const ledger = store.loadOverviewWithoutIocs
    ? await store.loadOverviewWithoutIocs(caseId)
    : await store.loadOverview(caseId);
  const scope = { addedIds: ids, touchedRowIds: [], touchedKnown: true, mergedCount: 0 };
  const superStore = deps.superTimelineStore;
  const stamped = await lock(caseId, () =>
    carryAndStampPaged(store, caseId, ledger, scope, false, {
      capturedAt: undefined,
      downgrade: !!superStore,
      importBatchId: batchId, // the same id: a second failure leaves the rows findable (#2888)
      importedAt, // and the same instant: the recovery does not rewrite when the case received them
      gradePending: !superStore || deps.markGradePending === false ? false : (deps.markGradePending ?? true),
    }),
  );
  await gradeStampedRows(deps, caseId, stamped.addedIds, { ledger, candidates: stamped.candidates });
  return stamped.addedIds.length;
}

/**
 * The seam's back half for rows already stamped: dual-write → tagger → the settle's three corrections
 * (#2909: build-time and lab-setup caps, Defender engine start-up, on these rows' candidates) → demote
 * → remove the grade mark from the survivors the tagger finished on (#2891). Takes no import lock (the
 * caller holds the section). Without `caps` the corrections are skipped (no ledger to read them from).
 */
export async function gradeStampedRows(
  deps: RowRecoveryDeps,
  caseId: string,
  ids: readonly string[],
  caps?: { ledger: InvestigationState; candidates: CapCandidates },
): Promise<void> {
  const store = deps.stateStore;
  const lock = deps.runStateExclusive ?? runUnlocked;
  let gradedIds: string[] = [];
  if (deps.superTimelineStore && ids.length) {
    const dualDeps = { ...deps, stateStore: store, runStateExclusive: lock };
    gradedIds = (await dualWriteAndTagPaged(dualDeps, caseId, ids)).gradedIds;
  }
  if (caps) return finishRegrade(deps, caseId, { gradedIds, ...caps });
  await deps.demote(caseId, { graded: new Set(gradedIds) });
  await clearGradePending(store, lock, caseId, gradedIds);
}

/** The recovery deps from the deps an import already hands settleForensicImport. */
export function recoveryDepsFromSettle(d: SettleDeps): RowRecoveryDeps {
  const demote = d.demoteForensic ?? d.demoteForensicForCase ?? (async () => undefined);
  return {
    stateStore: d.stateStore,
    runStateExclusive: d.runStateExclusive,
    superTimelineStore: d.superTimelineStore,
    onSuperTimeline: d.onSuperTimeline,
    autoTagImported: d.autoTagImported,
    ...(d.tagHeld ? { tagHeld: d.tagHeld } : {}),
    demote,
    ...(d.markGradePending !== undefined && d.markGradePending !== true
      ? { markGradePending: d.markGradePending }
      : {}),
  };
}

export interface ImportRecoveryTarget {
  caseId: string;
  /** Every stored name the import's rows can carry. */
  storedNames: readonly string[];
  /** The log prefix of the calling path, e.g. "import" or "velociraptor". */
  tag: string;
}

const errorText = (err: unknown): string => (err as Error)?.message ?? String(err);

/** What the recovery did: rows settled, and its own failure when it failed too. */
export interface ImportRecovery {
  settled: number;
  error?: string;
}

/** Settle the import's rows now, from INSIDE its held section. Never throws; logs a WARN. */
export async function recoverImportRows(
  deps: RowRecoveryDeps,
  t: ImportRecoveryTarget & { batchId?: string; cause: string },
): Promise<ImportRecovery> {
  const names = new Set(t.storedNames.filter((n) => !!n));
  const files = [...names].join(", ");
  try {
    const settled = (await settleUnsettledRows(deps, t.caseId, (s) => names.has(s), t.batchId)) ?? 0;
    getServerLogger().warn(
      `[${t.tag}] ${t.caseId}: settled ${settled} row(s) of ${files} ${t.cause} (no import record or Undo entry)`,
      { caseId: t.caseId },
    );
    return { settled };
  } catch (err) {
    const error = errorText(err);
    getServerLogger().warn(
      `[${t.tag}] ${t.caseId}: settling the rows of ${files} after its settle failed did not work either: ${error}`,
      { caseId: t.caseId },
    );
    return { settled: 0, error };
  }
}

/**
 * Run the settle with a preset batch id; on a throw, log it and settle the import's rows the settle
 * did not reach, then return null. Wrap ONLY the settle call: when a later step (the import record)
 * fails, every row was already settled, and recovering would re-stamp them and demote again. The same
 * holds for a settle that threw AFTER its demote (a post-demote diff read, `failedAfterGrading`): it
 * logs a WARN and recovers nothing.
 */
export async function settleOrRecover<T>(
  deps: RowRecoveryDeps,
  t: ImportRecoveryTarget,
  settle: (importBatchId: string) => Promise<T>,
): Promise<T | null> {
  const batchId = randomUUID();
  try {
    return await settle(batchId);
  } catch (err) {
    if (failedAfterGrading(err)) {
      getServerLogger().warn(
        `[${t.tag}] ${t.caseId}: the settle's diff/report step failed after grading completed: ${errorText(err)}`,
        { caseId: t.caseId },
      );
      return null;
    }
    getServerLogger().warn(`[${t.tag}] ${t.caseId}: settle failed: ${errorText(err)}`, { caseId: t.caseId });
    await recoverImportRows(deps, { ...t, batchId, cause: "whose settle failed" });
    return null;
  }
}

/**
 * The settle for a path whose settle failure must still FAIL the import (#2891: the dedicated import
 * routes, the NG-SIEM search, a Watson paste, a cloud collection page, the import replay). Same
 * preset batch id and same rule as `settleOrRecover` — recovery only for a failure before grading
 * completed — but the original error is RETHROWN once the rows are settled, so the caller's failure
 * report is unchanged. Wrap ONLY the settle call; the caller holds the case's import section.
 */
export async function settleImportOrRecoverThenThrow(
  settleDeps: SettleDeps,
  t: ImportRecoveryTarget,
  before: InvestigationState | ImportBaseline,
  label?: string,
  /** `preGraded`: rows the caller already tagged (settleForensicImport's option). */
  extra: { preGraded?: readonly string[] } = {},
): Promise<SettledImport> {
  const batchId = randomUUID();
  try {
    return await settleForensicImport(settleDeps, t.caseId, before, label, {
      ...extra,
      importBatchId: batchId,
    });
  } catch (err) {
    if (!failedAfterGrading(err)) {
      const deps = recoveryDepsFromSettle(settleDeps);
      await recoverImportRows(deps, { ...t, batchId, cause: "whose settle failed" });
    }
    throw err;
  }
}

/** The pre-import snapshot could not be read, so the settle cannot run: settle the rows without it. */
export async function recoverWithoutSnapshot(
  deps: RowRecoveryDeps,
  t: ImportRecoveryTarget,
): Promise<ImportRecovery> {
  getServerLogger().warn(`[${t.tag}] ${t.caseId}: no pre-import snapshot — the settle cannot run`, {
    caseId: t.caseId,
  });
  return recoverImportRows(deps, { ...t, cause: "whose pre-import read failed" });
}

/**
 * The guarded settle every swallowing import path runs (#2890): nothing without settle deps; no
 * snapshot → WARN + recovery; else the settle under `settleOrRecover`. Null when the caller has no
 * settle result to report (the rows were recovered, or there was nothing to settle).
 */
export async function settleImportOrRecover(
  settleDeps: SettleDeps | null | undefined,
  t: ImportRecoveryTarget,
  before: InvestigationState | ImportBaseline | null,
  label?: string,
): Promise<SettledImport | null> {
  if (!settleDeps) return null;
  const deps = recoveryDepsFromSettle(settleDeps);
  if (!before) {
    await recoverWithoutSnapshot(deps, t);
    return null;
  }
  return settleOrRecover(deps, t, (importBatchId) =>
    settleForensicImport(settleDeps, t.caseId, before, label, { importBatchId }),
  );
}
