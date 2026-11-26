/**
 * The re-grade of rows still carrying the grade mark (#2909, analysis/gradeMark.ts) — one core for the
 * three places that finish a grading another import left undone:
 *   - the next import's settle (`sweepLeftovers`, from routes/importSettle.ts) — so rows held after a
 *     tagger failure, or merged by an import that threw before its stamp, reach the forensic timeline
 *     at the next import instead of waiting for a restart;
 *   - start-up (composition/ungradedRecovery.ts), for every case;
 *   - the in-process recovery's caps (routes/importRowRecovery.ts, `finishRegrade`).
 *
 * WHAT IT DOES to the marked rows it is handed, in the settle's own order (CLAUDE.md §7): a row the
 * gate never touches (promoted, manual, a coverage note) only loses its mark — never re-tagged, never
 * demoted, its stored severity kept; an unstamped row is stamped (fresh batch id, now, the settle's
 * first-party downgrade) unless the caller says it must keep its stamp; then dual-write (the
 * super-timeline copy never carries the mark) → tagger by mark (true → content tagger, "held" → the held
 * tagger only) → the three post-tagger corrections → demote (only the rows the tagger finished on may
 * leave) → the survivors lose their mark.
 *
 * LOCKS. Every function here takes only the per-step state lock. The caller holds the case's import
 * section, which is not re-entrant: the settle and the in-process recovery run inside their import's
 * section, start-up takes it once per case. Nothing here calls anything that takes the section.
 * Reads the forensic timeline only — never the super-timeline.
 */
import type { DemoteOptions, TagOutcome } from "../analysis/gradeMark.js";
import { forensicGradePendingIds, isGradePending } from "../analysis/gradeMark.js";
import { gateExempt } from "../analysis/forensicGate.js";
import { SCAN_PAGE_ROWS, type ForensicRowStore } from "../analysis/forensicRows.js";
import type { ForensicEvent, InvestigationState } from "../analysis/stateTypes.js";
import { getServerLogger } from "../logging/serverLogger.js";
import { gradeCapsScoped, type CapCandidates } from "./importSettleCap.js";
import {
  carryAndStampPaged,
  clearGradePending,
  collector,
  dualWriteAndTagPaged,
  emptyCandidates,
  type DualWriteDeps,
  type SettleCandidates,
} from "./importSettlePaged.js";
import { rowPages, runUnlocked, type RunExclusive } from "./importSettleRows.js";

export interface RegradeDeps {
  stateStore: ForensicRowStore;
  runStateExclusive?: RunExclusive;
  superTimelineStore?: DualWriteDeps["superTimelineStore"];
  onSuperTimeline?: (caseId: string) => void;
  autoTagImported: (caseId: string, added: ForensicEvent[]) => Promise<TagOutcome>;
  tagHeld?: DualWriteDeps["tagHeld"];
}

export interface Regraded {
  /** The rows the tagger finished on: the demote may move them; their mark goes after it. */
  gradedIds: string[];
  /** The cap candidates of the rows offered to the tagger (gradeCapsScoped reads them). */
  candidates: CapCandidates;
  /** Rows offered to the tagger. */
  offered: number;
  /** Exempt rows (promoted / manual / coverage note) whose mark was only removed. */
  cleared: number;
}

export const NO_REGRADE: Regraded = {
  gradedIds: [],
  candidates: { buildTimeIds: [], labSetupIds: [], engineBoot: [] },
  offered: 0,
  cleared: 0,
};

/** Two candidate sets as one (the settle's own rows and the rows its sweep re-graded). */
export function withCapCandidates(a: CapCandidates, b: CapCandidates): CapCandidates {
  if (!b.buildTimeIds.length && !b.labSetupIds.length && !b.engineBoot.length) return a;
  return {
    buildTimeIds: [...a.buildTimeIds, ...b.buildTimeIds],
    labSetupIds: [...a.labSetupIds, ...b.labSetupIds],
    engineBoot: [...a.engineBoot, ...b.engineBoot],
  };
}

const capsOf = (c: SettleCandidates): CapCandidates => ({
  buildTimeIds: c.buildTimeIds,
  labSetupIds: c.labSetupIds,
  engineBoot: c.engineBoot,
});

export interface RegradeOptions {
  /** The case's rename ledger (the stamp's host carry and the cap candidates read it). */
  ledger: InvestigationState;
  /**
   * Rows that must keep their stamp (none: none). The settle names the old rows its own import
   * touched: a fold can carry a new row's mark onto an old row, which then did absorb ungraded
   * evidence and is tagged — but an Undo of this import must never roll that old row back.
   */
  keepStamp?: (rowId: number) => boolean;
}

/**
 * Grade the marked rows `ids` (dual-write → tagger), after clearing the exempt ones and stamping the
 * unstamped ones. No caps, no demote: the caller runs them once for everything it graded.
 */
export async function regradeMarked(
  deps: RegradeDeps,
  caseId: string,
  ids: readonly string[],
  opts: RegradeOptions,
): Promise<Regraded> {
  const store = deps.stateStore;
  const lock = deps.runStateExclusive ?? runUnlocked;
  const exempt: string[] = [];
  const unstamped: string[] = [];
  const offered: string[] = [];
  const candidates = emptyCandidates();
  const collect = collector(opts.ledger);
  for await (const rows of rowPages(store, caseId, ids)) {
    for (const { rowId, event: e } of rows) {
      if (!isGradePending(e)) continue; // graded meanwhile
      if (gateExempt(e)) exempt.push(e.id);
      else if (!e.importBatchId && !opts.keepStamp?.(rowId)) unstamped.push(e.id);
      else {
        offered.push(e.id);
        collect(candidates, e, false);
      }
    }
  }
  const cleared = exempt.length ? await clearGradePending(store, lock, caseId, exempt) : 0;
  if (unstamped.length) {
    const scope = { addedIds: unstamped, touchedRowIds: [], touchedKnown: true, mergedCount: 0 };
    const stamped = await lock(caseId, () =>
      carryAndStampPaged(store, caseId, opts.ledger, scope, false, {
        capturedAt: undefined,
        downgrade: !!deps.superTimelineStore,
        gradePending: true, // a row marked "held" keeps "held" (stampedMode)
      }),
    );
    offered.push(...stamped.addedIds);
    candidates.buildTimeIds.push(...stamped.candidates.buildTimeIds);
    candidates.labSetupIds.push(...stamped.candidates.labSetupIds);
    candidates.engineBoot.push(...stamped.candidates.engineBoot);
  }
  let gradedIds: string[] = [];
  if (deps.superTimelineStore && offered.length) {
    const dualDeps = { ...deps, stateStore: store, runStateExclusive: lock };
    gradedIds = (await dualWriteAndTagPaged(dualDeps, caseId, offered)).gradedIds;
  }
  return { gradedIds, candidates: capsOf(candidates), offered: offered.length, cleared };
}

/**
 * The back half for rows a re-grade (or the in-process recovery) just tagged: the three corrections
 * → demote (only `graded` may leave among marked rows) → the survivors lose their mark.
 */
export async function finishRegrade(
  deps: RegradeDeps & { demote: (caseId: string, opts?: DemoteOptions) => Promise<unknown> },
  caseId: string,
  done: { gradedIds: readonly string[]; candidates: CapCandidates; ledger: InvestigationState },
): Promise<void> {
  const store = deps.stateStore;
  const lock = deps.runStateExclusive ?? runUnlocked;
  await gradeCapsScoped(store, lock, caseId, done.ledger, { scanAll: false, candidates: done.candidates });
  await deps.demote(caseId, { graded: new Set(done.gradedIds) });
  await clearGradePending(store, lock, caseId, done.gradedIds);
}

/** At most this many leftover rows are re-graded per settle; the rest stay held for the next one. */
export const LEFTOVER_BUDGET = 10 * SCAN_PAGE_ROWS;
/** After a sweep the tagger finished on nothing, the case's sweeps pause this long (start-up still runs). */
export const SWEEP_BACKOFF_MS = 10 * 60 * 1000;
const sweepFailedAt = new Map<string, number>();

/** Test seam: forget every case's sweep back-off. */
export function resetSweepBackoff(): void {
  sweepFailedAt.clear();
}

export interface SweepArgs extends RegradeOptions {
  /** This import's own rows (graded by the settle itself). */
  ownIds: readonly string[];
  /** How many of them the settle's own tagger pass finished on. */
  ownGraded: number;
  /** Rows the caller already tagged (a cloud summary's rebuilt rows): neither re-graded nor swept. */
  preGraded?: readonly string[];
}

/**
 * The next import's sweep (#2909): grade the marked rows earlier imports left — a tagger failure, an
 * importer that threw after a partial merge, a crash. Bounded: skipped when this import's own tagger
 * pass finished on none of its rows (a broken tags file would only re-tag the same rows on every
 * Velociraptor monitor poll), or while the case is in back-off after a sweep that graded nothing; at
 * most LEFTOVER_BUDGET rows per settle. Null when it did not run or found nothing.
 */
export async function sweepLeftovers(
  deps: RegradeDeps,
  caseId: string,
  args: SweepArgs,
): Promise<Regraded | null> {
  if (args.ownIds.length && !args.ownGraded) return null;
  const failed = sweepFailedAt.get(caseId);
  if (failed !== undefined && Date.now() - failed < SWEEP_BACKOFF_MS) return null;
  const skip = new Set([...args.ownIds, ...(args.preGraded ?? [])]);
  const marked = await forensicGradePendingIds(deps.stateStore, caseId);
  const leftovers = marked.filter((id) => !skip.has(id));
  if (!leftovers.length) return null;
  const done = await regradeMarked(deps, caseId, leftovers.slice(0, LEFTOVER_BUDGET), args);
  if (done.offered && !done.gradedIds.length) sweepFailedAt.set(caseId, Date.now());
  else sweepFailedAt.delete(caseId);
  getServerLogger().warn(
    `[import] ${caseId}: re-graded ${done.gradedIds.length} of ${done.offered} row(s) an earlier import left ` +
      `waiting for the content tagger (${leftovers.length} waiting, ${done.cleared} promoted/manual unmarked)`,
    { caseId },
  );
  return done;
}
