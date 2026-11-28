import type { ForensicEvent, InvestigationState } from "../analysis/stateTypes.js";
import { disarmGrade, type DemoteOptions, type GradeMode, type TagOutcome } from "../analysis/gradeMark.js";
import { NO_REGRADE, sweepLeftovers, withCapCandidates } from "./importRegrade.js";
import type { SuperEviction, SuperRelink } from "../analysis/superTimelineStore.js";
import type { TimelineDiff } from "../analysis/timelineDiff.js";
import type { IocsDiff } from "../analysis/iocsDiff.js";
import { getServerLogger } from "../logging/serverLogger.js";
import { formatImportSettled } from "../logging/importLog.js";
import type { ForensicRowStore } from "../analysis/forensicRows.js";
import { settleIocsDiff, settleTimelineDiff } from "./importSettleDiff.js";
import { toImportBaseline, type ImportBaseline } from "../analysis/importBaseline.js";
import { gradeCapsScoped } from "./importSettleCap.js";
import { flagLookalikeCandidates } from "./importSettleLookalike.js";
import { nameCallersScoped } from "./importSettleNames.js";
import { principalLedgerChanged } from "../analysis/principalNames.js";
import { runUnlocked, settleScope, type RunExclusive } from "./importSettleRows.js";
import {
  carryAndStampPaged,
  clearGradePending,
  dualWriteAndTagPaged,
  huntSettlePaged,
} from "./importSettlePaged.js";
import { relinkSuperAfterSettle } from "./importSettleRelinkSuper.js";
import {
  rehomeSuperTimeline,
  renameLedgerChanged,
  type SuperRehomeStore,
} from "./importSettleRehomeSuper.js";

/**
 * The forensic / super-timeline seam that every import must cross after the importer has merged
 * its delta (ARCHITECTURE.md → "The forensic / super-timeline boundary"): merge-all has already
 * happened, so (1) the rows this import ADDED are dual-written into the super-timeline, the
 * superset that keeps Info telemetry, (2) the deterministic tagger gets its one chance to raise
 * high-value telemetry out of Info — its promotion window is the import that collected the row,
 * never a later run — and (3) demote removes whatever is still Info from the forensic timeline,
 * which is the only record the model reads. The diffs come from the POST-demote state, so "+N
 * events" counts graded signal, not telemetry.
 *
 * This used to be six inline copies (the generic import route twice, the streamed ingest, the hunt
 * collector, the two Velociraptor external-ingest paths) and ZERO copies on the dedicated
 * `import-*` routes, which called their
 * importer and resynthesized: an Info row from a dedicated route stayed in the forensic timeline
 * and reached the model, and never entered the super-timeline at all (#932 item 12 found it on
 * `/import-leapp`; #956 tracks the rest). One function, so a route cannot half-run the seam.
 *
 * The baseline is what the section captured under the import lock BEFORE the importer ran
 * (routes/importSection.ts) — the diff is only honest against that snapshot. Since #1874 it is not
 * a full copy of the case, and no step here loads or saves the whole case: each reads and writes
 * only the rows it changes (see the functions below).
 *
 * A hostname rename the import taught the case re-homes the rows the case already held (#1495),
 * and the super-timeline's own copies of them — dual-written earlier, or Info rows that live only
 * there — are re-homed from the store's rows in the same settle (#1508), so both records show one
 * host. That pass is non-fatal like the dual-write: it changes which host a row is filed under,
 * never whether the row is in a record.
 *
 * The post-demote diffs are also the one place that knows what an import left behind, so this is
 * where the `[import] … done — forensic +N, super +M, IOCs +K` log line is written (#1438), with
 * `{ caseId }` so it lands in the case's own log too; `label` names the file when the caller has
 * it. An all-zero settle logs at DEBUG: the Velociraptor monitors settle on every poll, and an empty
 * poll must not fill the session log.
 */
export interface SettleDeps {
  /** Row-level access to the case (StateStore); `load` only for a legacy `onState`-only caller. */
  stateStore: ForensicRowStore & { load?(caseId: string): Promise<InvestigationState> };
  /**
   * The case's state lock (createApp's runStateExclusive). Each settle step reads, changes and
   * writes its rows inside it, so an analyst edit, an enrichment or a synthesis — all of which save
   * through the same lock — can never interleave with a step and have its change overwritten.
   */
  runStateExclusive?: RunExclusive;
  superTimelineStore?: {
    append(caseId: string, events: ForensicEvent[]): Promise<number>;
    /** #1535 — the retained count AND what the cap dropped, from one atomic write. Optional so a
     * test fake that only implements `append` keeps working; the eviction then reports nothing. */
    appendReporting?(
      caseId: string,
      events: ForensicEvent[],
    ): Promise<{ retained: number; evicted: SuperEviction }>;
    /** #2619 — move a stored row onto the forensic id it now has (Undo + re-import). */
    relink?(caseId: string, links: readonly SuperRelink[]): Promise<number>;
  } & Partial<SuperRehomeStore>;
  onSuperTimeline?: (caseId: string) => void;
  /**
   * Fired once when the settle changed the forensic timeline (#1174: the dashboard learns the new
   * importedAt/importBatchId stamps from this settle, not from whatever broadcast happens next). It
   * takes the case id, not a state: the app loads and pushes the state only when a dashboard is
   * watching the case (#1874).
   */
  onStateChanged?: (caseId: string) => void;
  /** Legacy callers that only wire a state broadcaster: the settle loads the case once for it. */
  onState?: (state: InvestigationState) => void;
  autoTagImported: (caseId: string, added: ForensicEvent[]) => Promise<TagOutcome>;
  /** The held tagger for rows marked "held" (#2909, importSettlePaged.ts DualWriteDeps.tagHeld). */
  tagHeld?: (caseId: string, added: ForensicEvent[]) => Promise<TagOutcome>;
  /**
   * The held tagger for the LEFTOVER sweep's "held" rows (default `tagHeld`). #2930: a Watson paste's
   * own `tagHeld` collects raises for its own turn; rows an earlier paste left held belong to that
   * paste, so the paste hands the re-grade tagger here and they go through the held-proposal outbox.
   */
  sweepTagHeld?: (caseId: string, added: ForensicEvent[]) => Promise<TagOutcome>;
  /**
   * The forensic gate's demote; returns the rows it removed (composition/importDemote.ts). `graded`:
   * the rows the tagger just finished on — the only rows carrying the grade mark it may move (#2891).
   */
  demoteForensic?: (caseId: string, opts?: DemoteOptions) => Promise<ForensicEvent[]>;
  /** The same demote returning the whole case afterwards — legacy callers only. */
  demoteForensicForCase?: (caseId: string, opts?: DemoteOptions) => Promise<InvestigationState>;
  /**
   * False: write no grade mark (#2891). "held" (#2909): a Watson paste — its rows are marked "held",
   * so only the held tagger ever grades them (its raises are proposals the analyst approves); a plain
   * re-grade would apply a raise the analyst never approved.
   */
  markGradePending?: boolean | "held";
}

/**
 * The grade-arm mode an import section takes (#2909, analysis/gradeMark.ts): the mark goes on inserts
 * only when the section ends in this settle with its tagger wired (a super-timeline store), as the
 * stamp-time mark does. Undefined: no arm.
 */
export function gradeArmOf(deps: SettleDeps | null | undefined): GradeMode | undefined {
  if (!deps?.superTimelineStore || deps.markGradePending === false) return undefined;
  return deps.markGradePending === "held" ? "held" : true;
}

export interface SettledImport {
  /** Rows the super-timeline RETAINED from this import (0 when no store is wired). */
  superTimelineAddedCount: number;
  /**
   * False when no super-timeline store is wired, so the count above is not a real zero (#3042): the
   * import message then leaves the super-timeline line out. Optional for legacy fakes (= wired).
   */
  superTimelineAvailable?: boolean;
  /**
   * What the super-timeline's cap dropped to make room for this import (#1535). Undefined when no
   * store is wired or the store cannot report it; `count: 0` when the cap took nothing. This is
   * per-import; a case's complete eviction record is `SuperTimelineStore.meta().evictedTotal`,
   * which also covers evictions no import caused (unstarring a row releases protection).
   */
  superTimelineEvicted?: SuperEviction;
  /** Forensic-timeline diff against the baseline, computed post-demote. */
  timelineDiff: TimelineDiff;
  iocsDiff: IocsDiff;
  /**
   * The rows this import added that are still in the forensic timeline, read as they are now. A
   * function, so a caller that does not need them (no false-positive markers to match) reads
   * nothing; call it while the import section is still held.
   */
  addedEvents(): Promise<ForensicEvent[]>;
  /** How many rows the forensic timeline holds after the settle. */
  forensicCount: number;
  /** The case after demote — only when a legacy `demoteForensicForCase` produced it. */
  state?: InvestigationState;
  /**
   * The import taught the case a principal name, or a conflict (#2490). The checkpoint gates read
   * it: an upload of Info-only sign-ins adds no forensic row or IOC, and Undo must still be able to
   * take back the names it taught.
   */
  principalNamesChanged?: boolean;
}

/**
 * `before` is what the import is diffed against: the ImportBaseline its section captured
 * (analysis/importBaseline.ts), or — from a legacy caller — the full state it loaded then.
 * `opts.importBatchId` presets the stamp's batch id, so a caller whose settle fails after stamping can
 * find those rows again (a hunt collect, #2888); every other caller lets the settle pick one.
 * `opts.onGraded` runs once demote has returned (a hunt collect records it on its job, so a restart
 * does not re-grade the batch). Any failure from there on is a `SettleAfterGradingError`.
 */
export async function settleForensicImport(
  deps: SettleDeps,
  caseId: string,
  before: InvestigationState | ImportBaseline,
  label?: string,
  opts: { importBatchId?: string; onGraded?: () => Promise<void>; preGraded?: readonly string[] } = {},
): Promise<SettledImport> {
  const baseline = toImportBaseline(before);
  const store = deps.stateStore;
  const lock = deps.runStateExclusive ?? runUnlocked;
  // #2909: the importer's merge window is over — nothing the settle inserts (hunt summaries) is the
  // importer's row, so the grade arm goes first (analysis/gradeMark.ts).
  await disarmGrade(store, caseId);
  const scope = await settleScope(store, caseId, baseline);
  // Its rename ledger and collector identities only (#1874): not the IOC list, as long as the timeline.
  const ledger = store.loadOverviewWithoutIocs
    ? await store.loadOverviewWithoutIocs(caseId)
    : await store.loadOverview(caseId);
  // A rename the import taught the case (or a changed collector identity) can re-home ANY old row;
  // otherwise only the rows the import added or touched can need it.
  const ledgerChanged = renameLedgerChanged(baseline.overview, ledger);
  const scanAll = ledgerChanged || !scope.touchedKnown;
  // #1735: the always-on debug log keeps these at any live level. Counts only, never row content.
  // Silent when the import added nothing and carried no rename: a Velociraptor monitor settles on
  // every poll, and empty polls must not push real history out of the capped debug log.
  let traced = scope.addedIds.length > 0 || ledgerChanged;
  const debug = (step: string): void => {
    if (traced) getServerLogger().debug(`[import-debug] ${caseId}: settle ${step}`, { caseId });
  };

  // Rows the case already held under a name this (or any earlier) import taught it was a former one
  // are re-homed (#1495), then the rows new to this case are stamped with WHEN the case received
  // them and WHICH import action did it (#1157) — one instant, one batch id — and the first-party
  // egress downgrade (#1530) rides in the same pass. Its position is the whole argument: BEFORE the
  // dual-write, so the super-timeline keeps the Info copy the forensic record is about to lose;
  // BEFORE the tagger, so a tagger rule that matches the row raises it straight back out of Info.
  // Gated on the super-timeline store like the dual-write: demote removes a sub-threshold row from
  // the forensic timeline whether or not a capture store exists, so lowering a grade with no store
  // wired would delete evidence. Only the rows that change are written, under the state lock.
  // In pages (#2713, importSettlePaged.ts): only the added ids and each later step's rows are kept.
  const stamped = await lock(caseId, () =>
    carryAndStampPaged(store, caseId, ledger, scope, scanAll, {
      capturedAt: baseline.capturedAt,
      downgrade: !!deps.superTimelineStore,
      importBatchId: opts.importBatchId,
      // #2891: the mark goes on with the stamp only when the tagger runs below (a super store is wired).
      gradePending: gradeArmOf(deps) ?? false,
    }),
  );
  const addedIds = stamped.addedIds;
  const candidates = stamped.candidates;
  traced ||= stamped.carried > 0;
  debug(
    `start forensicBefore=${baseline.outline.ids.length} merged=${scope.mergedCount} ` +
      `added=${addedIds.length} renameCarry=${stamped.carried}`,
  );
  let changed = addedIds.length > 0 || stamped.carried > 0;

  // The super-timeline's own copies follow the ledger (#1508). Either signal triggers it: a rename
  // whose old-name rows were all Info changes the ledger but moves no forensic row, and a forensic
  // row the carry moved has a copy in the store that must move with it.
  if (deps.superTimelineStore && (stamped.carried > 0 || ledgerChanged)) {
    await rehomeSuperCopies(deps, caseId, ledger);
  }

  // Dual-write FIRST, from the pre-demote (now stamped) rows; then the tagger (importSettlePaged.ts).
  let superTimelineAddedCount = 0;
  let superTimelineEvicted: SuperEviction | undefined;
  let relinkCandidates: Awaited<ReturnType<typeof dualWriteAndTagPaged>>["relinkCandidates"] = [];
  let gradedIds: string[] = []; // #2891: the rows the tagger finished on
  if (deps.superTimelineStore && addedIds.length) {
    const dual = await dualWriteAndTagPaged({ ...deps, runStateExclusive: lock }, caseId, addedIds);
    gradedIds = dual.gradedIds;
    superTimelineAddedCount = dual.retained;
    superTimelineEvicted = dual.evicted;
    relinkCandidates = dual.relinkCandidates;
    debug(
      `dual-write superRetained=${superTimelineAddedCount} superEvicted=${superTimelineEvicted?.count ?? 0} ` +
        `taggerOffered=${addedIds.length}`,
    );
  } else {
    debug(`dual-write skipped store=${deps.superTimelineStore ? "yes" : "no"} added=${addedIds.length}`);
  }
  // #2909: rows earlier imports left waiting for the tagger are graded now too, before the caps and the
  // demote (importRegrade.ts) — inside this import's section, state locks only.
  const sweep =
    (deps.superTimelineStore &&
      (await sweepLeftovers(deps.sweepTagHeld ? { ...deps, tagHeld: deps.sweepTagHeld } : deps, caseId, {
        ledger,
        ownIds: addedIds,
        ownGraded: gradedIds.length,
        preGraded: opts.preGraded,
        // A legacy baseline cannot say which old rows this import touched: stamp no leftover then.
        keepStamp: scope.touchedKnown ? touchedRow(scope.touchedRowIds) : () => true,
      }))) ||
    NO_REGRADE;
  changed ||= sweep.offered + sweep.cleared > 0;
  // Case-account look-alikes (#1971): after the tagger, before the caps. Scans only when this import
  // added a new account or group member.
  const lookalikes = await lock(caseId, () => flagLookalikeCandidates(store, caseId, candidates.lookalike));
  changed ||= lookalikes > 0;
  // Merge-all → tagger → CAP → demote (#1529). The tagger has had its one promotion window above;
  // now the rows inside a corroborated provisioning window are capped at Low with a stated reason,
  // before demote decides what leaves the forensic timeline.
  // Off every rename chain, the cap can only change a row that already carries a cap mark (the
  // tagger never writes one), so only such rows of this import's own are handed on.
  // Lab setup (#1946): a file copied in through a hypervisor drag-and-drop folder is capped at Medium.
  // Defender engine start-up (#2084): the Info start-up rows are still here; demote is next.
  // #2909: the rows the sweep re-graded are handed on too (their candidates join this import's).
  const caps = await gradeCapsScoped(store, lock, caseId, ledger, {
    scanAll,
    candidates: withCapCandidates(candidates, sweep.candidates),
  });
  const capped = caps.capped;
  changed ||= caps.capped + caps.labCapped + caps.engineBoot > 0;
  // Hunt grading (#2670): a hunt case records this import's rows (Info still here) as host counts and
  // writes one summary entry per graded program. Reads no raw record; changes no imported row.
  // In pages of the added ids (#2713, importSettlePaged.ts), each page read under the state lock.
  const hunt = await huntSettlePaged(store, lock, caseId, addedIds, (e) =>
    getServerLogger().warn(`[hunt] ${caseId}: grading skipped: ${e.message}`, { caseId }),
  );
  changed ||= hunt > 0;
  const graded = [...gradedIds, ...sweep.gradedIds, ...(opts.preGraded ?? [])];
  const demoted = await demote(deps, caseId, { graded: new Set(graded) });
  changed ||= demoted.removed > 0;
  // #2891: the survivors the tagger finished on lose their mark — still unfinished grading, so a failure
  // here is recovered like any other before it (the rows keep the mark, and a re-grade finds them).
  await clearGradePending(store, lock, caseId, graded);
  // Every row is stamped, tagged and demoted from here on: a failure below is not unfinished grading,
  // and a recovery that re-ran it would re-stamp the rows and demote again (review of #2890).
  try {
    await opts.onGraded?.();
    // #2619: after demote, so only rows that stay in the forensic record relink their raw-record copy.
    await relinkSuperAfterSettle({ ...deps, runStateExclusive: lock }, caseId, relinkCandidates);
    // Caller names (#2490): after demote, so only rows that stay in the forensic record are rewritten.
    const namesChanged = principalLedgerChanged(baseline.overview, ledger);
    const named = await lock(caseId, () =>
      nameCallersScoped(store, caseId, ledger, {
        scanAll: namesChanged || !scope.touchedKnown,
        candidateIds: candidates.nameIds,
      }),
    );
    changed ||= named > 0;
    // #1874: from the rows that can change it, not a keyed read of the whole timeline (importSettleDiff.ts).
    const { timelineDiff, forensicCount } = await settleTimelineDiff(store, caseId, baseline);
    debug(
      `demote buildTimeCapped=${capped} forensicBeforeDemote=${forensicCount + demoted.removed} ` +
        `forensicAfterDemote=${forensicCount}`,
    );
    const iocsDiff = await settleIocsDiff(store, caseId, baseline);
    const addedEvents = async (): Promise<ForensicEvent[]> =>
      addedIds.length ? (await store.forensicRowsById(caseId, addedIds)).map((r) => r.event) : [];
    if (changed) await announceState(deps, caseId, demoted.state);
    logImportSettled(caseId, label, {
      forensicAdded: timelineDiff.added.length,
      forensicRemoved: timelineDiff.removed.length,
      superAdded: superTimelineAddedCount,
      superEvicted: superTimelineEvicted?.count ?? 0,
      iocsAdded: iocsDiff.added.length,
      iocsRemoved: iocsDiff.removed.length,
    });
    return {
      superTimelineAddedCount,
      superTimelineAvailable: Boolean(deps.superTimelineStore),
      superTimelineEvicted,
      timelineDiff,
      iocsDiff,
      addedEvents,
      forensicCount,
      ...(demoted.state ? { state: demoted.state } : {}),
      ...(namesChanged ? { principalNamesChanged: true } : {}),
    };
  } catch (err) {
    throw new SettleAfterGradingError(err);
  }
}

/** The old rows this import touched, by row id (the sweep never re-stamps them). */
function touchedRow(rowIds: readonly number[]): (rowId: number) => boolean {
  const touched = new Set(rowIds);
  return (rowId) => touched.has(rowId);
}

/**
 * A settle failure raised AFTER demote returned: every row of the import was stamped, dual-written,
 * tagged and demoted; only the relink, caller-naming, diff or report steps did not finish. Keeps the
 * cause's message. A recovery must not re-run grading for it (routes/importRowRecovery.ts).
 */
export class SettleAfterGradingError extends Error {
  readonly gradingComplete = true;
  constructor(cause: unknown) {
    super(cause instanceof Error ? cause.message : String(cause), { cause });
    this.name = "SettleAfterGradingError";
  }
}

/** True for a settle failure that happened after grading completed (see SettleAfterGradingError). */
export const failedAfterGrading = (err: unknown): boolean => err instanceof SettleAfterGradingError;

async function demote(
  deps: SettleDeps,
  caseId: string,
  opts: DemoteOptions,
): Promise<{ removed: number; state?: InvestigationState }> {
  if (deps.demoteForensic) return { removed: (await deps.demoteForensic(caseId, opts)).length };
  if (!deps.demoteForensicForCase) return { removed: 0 };
  // A legacy demote reports the state, not what it removed; the diff above still counts removals.
  return { removed: 0, state: await deps.demoteForensicForCase(caseId, opts) };
}

// One broadcast per settle. A legacy caller with only a state broadcaster gets one load for it.
async function announceState(deps: SettleDeps, caseId: string, state?: InvestigationState): Promise<void> {
  if (deps.onStateChanged) return deps.onStateChanged(caseId);
  if (!deps.onState) return;
  const current = state ?? (await deps.stateStore.load?.(caseId));
  if (current) deps.onState(current);
}

// Non-fatal by design, like the dual-write above: the forensic re-home is already saved, and a
// row the pass could not rewrite is still in the record under its former name — the next settle
// that changes the ledger tries again. A store without the method (a test fake) is skipped.
async function rehomeSuperCopies(deps: SettleDeps, caseId: string, state: InvestigationState): Promise<void> {
  const superStore = deps.superTimelineStore;
  if (!superStore?.rehome || !superStore.eventBatches) return;
  try {
    const rewritten = await rehomeSuperTimeline(superStore as SuperRehomeStore, caseId, state);
    if (rewritten) deps.onSuperTimeline?.(caseId);
  } catch (error) {
    getServerLogger().warn(
      `[import] ${caseId}: super-timeline rename re-home failed — ${error instanceof Error ? error.message : String(error)}`,
      { caseId },
    );
  }
}

export interface SettledCounts {
  forensicAdded: number;
  forensicRemoved: number;
  superAdded: number;
  /** Rows the super-timeline's cap had to drop to make room for this import (#1535). */
  superEvicted?: number;
  iocsAdded: number;
  iocsRemoved: number;
}

/**
 * The outcome line, shared with the two seams that settle inline instead of calling
 * settleForensicImport (the job resume handler, the analysis-run replay). INFO when anything
 * changed; DEBUG when every count is zero (an empty monitor poll).
 */
export function logImportSettled(caseId: string, label: string | undefined, counts: SettledCounts): void {
  const line = formatImportSettled({ caseId, label, ...counts });
  const empty = Object.values(counts).every((n) => !n);
  if (empty) getServerLogger().debug(line, { caseId });
  else getServerLogger().info(line, { caseId });
}
