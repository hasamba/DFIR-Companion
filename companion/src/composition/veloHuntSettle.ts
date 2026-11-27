/**
 * The end of a hunt collect's import section: the one combined settle, the import record and the
 * single undo checkpoint — and what the collect says when an artifact failed partway (#2817).
 *
 * A collect imports its artifacts one at a time inside one import section, so each artifact is in the
 * case as soon as its import returns. When a LATER artifact fails (the memory guard can refuse a
 * batched artifact partway, a parse or storage error, a cancel), the earlier ones are kept — whole-
 * collect rollback is not offered — and they must still cross the seam like any other import: tagged,
 * demoted, recorded, undoable. The collect stops at the failed artifact, settles what imported here,
 * then fails with a message naming both groups; it must not claim "nothing was changed".
 *
 * `settleHuntCollect` never throws. On a guard refusal it runs right after the server said it was
 * short of memory, so a failure here is logged and reported to the caller, and the artifact's own
 * error stays the one on the hunt card.
 */
import type { AppOptions } from "./appOptions.js";
import type { DemoteOptions, TagOutcome } from "../analysis/gradeMark.js";
import type { RouteContext } from "../routes/context.js";
import type { ForensicEvent, InvestigationState } from "../analysis/stateTypes.js";
import type { SkippedArtifact } from "../integrations/velociraptor/velociraptorApi.js";
import { describeImportSource } from "../analysis/importMeta.js";
import {
  createSuperEvictionTally,
  mergeEvictions,
  type SuperEvictionTally,
} from "../analysis/superTimelineStore.js";
import { collectEvictionForRecord, type BatchedRunEviction } from "../analysis/ingest/bulkEvictionReport.js";
import type { BulkImportOpts } from "../analysis/ingest/velociraptorBulk.js";
import { failedAfterGrading, settleForensicImport } from "../routes/importSettle.js";
import { logLine } from "../logging/serverLogger.js";
import { countsFromSettled, type ImportCounts } from "../analysis/importNotification.js";

export interface HuntSettleDeps {
  options: AppOptions;
  autoTagImported: (caseId: string, added: ForensicEvent[]) => Promise<TagOutcome>;
  /** #2930: the held tagger for a Watson paste's "held" rows the settle's leftover sweep meets. */
  tagHeld?: (caseId: string, added: ForensicEvent[]) => Promise<TagOutcome>;
  demoteForensicForCase: (caseId: string, opts?: DemoteOptions) => Promise<InvestigationState>;
  runStateExclusive?: <T>(caseId: string, fn: () => Promise<T>) => Promise<T>;
  pushImportCheckpoint: RouteContext["pushImportCheckpoint"];
}

/**
 * What the super-timeline's cap dropped across a collect, before its settle (#1535, #2831) — a hunt
 * writes one evidence file per artifact and reports one import card for the collection. The tally
 * side takes a report that is already final: a super-only artifact's own append, and an uploaded
 * report's batched import (as the `superEvictions` of its import base). `addRun` takes a batched
 * ARTIFACT's run instead, whole, so the rows the settle puts back are measured once for the collect.
 */
export interface HuntEvictions extends SuperEvictionTally {
  addRun: NonNullable<BulkImportOpts["onRunEvicted"]>;
  readonly runs: readonly BatchedRunEviction[];
}

export function createHuntEvictions(): HuntEvictions {
  const runs: BatchedRunEviction[] = [];
  return { ...createSuperEvictionTally(), runs, addRun: (raw, run) => void runs.push({ raw, run }) };
}

export interface HuntSettleInput {
  caseId: string;
  huntId: string;
  /** The state read when the import slot was granted; null when there is no state store. */
  stateBefore: InvestigationState | null;
  importedAny: boolean;
  /** The evidence file of the last artifact or upload that DID import. */
  lastFile: string | undefined;
  bundleName: string | undefined;
  artifactCount: number;
  /** What the collect's own direct super-timeline appends (a super-only bundle) added. */
  superTimelineAddedCount: number;
  /** What the cap dropped in the collect's imports, before the settle below. */
  capDropped: HuntEvictions;
  /** The batch id the job recorded for this collect (#2888): the settle stamps its rows with it. */
  importBatchId?: string;
}

export interface HuntSettleResult {
  addedEvents: number;
  addedIocs: number;
  /** True when an undo checkpoint was pushed (the settle found a change to take back). */
  checkpointed: boolean;
  /** The settle, record or checkpoint failed: logged here, the rows stay as they were imported. */
  error?: string;
  /**
   * The settle itself did not complete (#2888): it threw, or never ran because the pre-import state
   * read failed. Only then can rows of this collect carry its batch id without having been tagged; a
   * record or Undo failure after a complete settle leaves `error` set and this unset.
   */
  seamFailed?: boolean;
  /** What the collect added, for the "import finished" message (#2978); absent when nothing settled. */
  counts?: ImportCounts;
}

/** #2888: the pre-import state read failed, so the settle has nothing to diff against. */
export const NO_STATE_BEFORE = "the case state could not be read before the import";

/** One combined import-meta diff (so the dashboard's "last import / +N" banner lights up). */
export async function settleHuntCollect(
  deps: HuntSettleDeps,
  input: HuntSettleInput,
): Promise<HuntSettleResult> {
  const { options } = deps;
  const { caseId, huntId, stateBefore, lastFile } = input;
  const result: HuntSettleResult = { addedEvents: 0, addedIocs: 0, checkpointed: false };
  if (!input.importedAny || !options.stateStore) return result;
  if (!stateBefore) {
    // #2888: never silent — the rows are in the case, unsettled; the caller settles them at once.
    logLine(`[velociraptor] hunt ${huntId}: settling what was imported failed: ${NO_STATE_BEFORE}`);
    return { ...result, error: NO_STATE_BEFORE, seamFailed: true };
  }
  let counted = result; // the counts stand once the settle itself returned, whatever fails after it
  let seamDone = false;
  try {
    // Measured here, once: after the last import, before the settle puts the graded rows back (#2831).
    const beforeSettle = await collectEvictionForRecord(
      options.bulkImportSink,
      caseId,
      `hunt ${huntId}`,
      input.capDropped.runs,
      input.capDropped.plus(undefined),
    );
    // The one seam (routes/importSettle.ts): dual-write, tag, demote, diff post-demote.
    const settled = await settleForensicImport(
      {
        stateStore: options.stateStore,
        superTimelineStore: options.superTimelineStore,
        onSuperTimeline: options.onSuperTimeline,
        onState: options.onState,
        autoTagImported: deps.autoTagImported,
        tagHeld: deps.tagHeld,
        demoteForensicForCase: deps.demoteForensicForCase,
        runStateExclusive: deps.runStateExclusive,
      },
      caseId,
      stateBefore,
      `hunt ${huntId}`,
      { importBatchId: input.importBatchId, onGraded: () => recordGraded(options, input) },
    );
    seamDone = true;
    const { timelineDiff: diff, iocsDiff } = settled;
    const superTotal = input.superTimelineAddedCount + settled.superTimelineAddedCount;
    const counts = countsFromSettled({ timelineDiff: diff, superTimelineAddedCount: superTotal }); // #2978
    counted = { ...result, addedEvents: diff.added.length, addedIocs: iocsDiff.added.length, counts };
    if (options.importMetaStore) {
      await options.importMetaStore.record(caseId, {
        kind: "velociraptor",
        file: lastFile ?? `velo-hunt_${huntId}.json`,
        // Name the COLLECTION, not the last file it wrote. Both halves come from the JOB, which
        // snapshotted them at launch — describeImportSource records why any other source is wrong.
        source: describeImportSource({
          bundleName: input.bundleName,
          huntId,
          artifactCount: input.artifactCount,
        }),
        diff,
        superTimelineAddedCount: input.superTimelineAddedCount + settled.superTimelineAddedCount,
        superTimelineEvicted: mergeEvictions(beforeSettle, settled.superTimelineEvicted),
        iocsDiff,
      });
      options.onImportMeta?.(caseId);
    }
    // #76: snapshot the pre-collect state for undo when the hunt actually added data.
    if (!(diff.added.length || diff.removed.length || iocsDiff.added.length || iocsDiff.removed.length))
      return counted;
    await deps.pushImportCheckpoint(
      caseId,
      stateBefore,
      `velociraptor (${lastFile ?? `hunt ${huntId}`})`,
      settled.state,
    );
    return { ...counted, checkpointed: true };
  } catch (e) {
    // Non-fatal to the collect, but never silent (#2817): the rows are in the case and the settle,
    // the import record or the undo entry is missing. Rows the settle did not reach would be moved out
    // untagged by the next import's case-wide demote (#2851), so the collect settles them at once, still
    // inside its section, when this reports an error (#2852, veloHuntRecovery.ts `recoverFailedHuntSettle`).
    const error = (e as Error).message;
    logLine(`[velociraptor] hunt ${huntId}: settling what was imported failed: ${error}`);
    // A throw after the demote (a post-demote diff read) is not a seam failure: every row was graded.
    return seamDone || failedAfterGrading(e)
      ? { ...counted, error }
      : { ...counted, error, seamFailed: true };
  }
}

/**
 * The settle's demote has returned (review of #2890): drop the batch id from the stored job, so a
 * restart that finds the job still importing re-selects only unstamped rows, never re-stamping and
 * demoting this graded batch again. Only while the job still names this batch. Never throws.
 */
async function recordGraded(options: AppOptions, input: HuntSettleInput): Promise<void> {
  const batchId = input.importBatchId;
  if (!batchId || !options.veloHuntStore) return;
  try {
    await options.veloHuntStore.update(input.caseId, input.huntId, (cur) =>
      cur.importingBatchId === batchId ? { ...cur, importingBatchId: undefined } : null,
    );
  } catch (err) {
    logLine(
      `[velociraptor] hunt ${input.huntId}: recording that grading finished failed: ${(err as Error).message}`,
    );
  }
}

// The guard's refusal says this (analysis/importMemoryGuard.ts); it is false once an earlier artifact is kept.
const NOTHING_CHANGED = " and nothing was changed.";

/**
 * The artifacts a stopped collect did not import, as the job's skipped list records them: the one
 * that failed, with its error, and the ones after it that were never tried. All of them were
 * downloaded, so each carries the mark that keeps it out of the card's failed-fetch list (#2835).
 */
export function notImportedRecords(failed: string, error: string, notReached: string[]): SkippedArtifact[] {
  const stopped = (name: string, why: string): SkippedArtifact => ({
    name,
    error: why,
    notImported: "stopped",
  });
  return [
    stopped(failed, error.replace(NOTHING_CHANGED, ".")),
    ...notReached.map((name) => stopped(name, `not imported: the collect stopped when ${failed} failed`)),
  ];
}

/**
 * The hunt card's message for a collect that failed after it imported something. The artifact's own
 * error comes first and whole — retry advice included — less the claim that nothing was changed.
 * Stored raw, as every job error is: the card escapes it when it renders.
 */
export function midFailureMessage(
  error: string,
  imported: string[],
  notImported: string[],
  settled: HuntSettleResult,
): string {
  const base = error.replace(NOTHING_CHANGED, ".").trim();
  const sentence = /[.!?]$/.test(base) ? base : `${base}.`;
  const tail = settled.checkpointed
    ? " Undo is available for what was imported."
    : settled.error
      ? " Settling or recording what was imported failed (see the server log): it may have no import record and no Undo entry."
      : "";
  return `${sentence} Imported: ${imported.join(", ")}. Not imported: ${notImported.join(", ")}.${tail}`;
}

/** #2889: the re-grade failed too — the rows may never have been graded. */
export const SETTLE_WARNING_UNGRADED =
  "Imported, but grading did not finish: rows may be missing from the forensic timeline. " +
  "Collect again, or check the server log.";
/** #2889: the re-grade ran. It never claims grading finished: it can settle 0 and still miss rows. */
export const SETTLE_WARNING_UNRECORDED =
  "Imported, but settling or recording what was imported failed (see the server log): " +
  "it may have no import record and no Undo entry.";

/**
 * The hunt card's warning for a collect that imported with no failed artifact but whose settle,
 * record or Undo step failed (#2889); undefined for a clean settle, so a clean collect clears it.
 * `recovery` is what the in-process re-grade (`recoverFailedHuntSettle`) returned.
 */
export function settleWarning(
  settled: Pick<HuntSettleResult, "error">,
  recovery: { error?: string } | undefined,
): string | undefined {
  if (!settled.error) return undefined;
  return recovery?.error ? SETTLE_WARNING_UNGRADED : SETTLE_WARNING_UNRECORDED;
}
