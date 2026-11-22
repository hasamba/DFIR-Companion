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
import type { RouteContext } from "../routes/context.js";
import type { ForensicEvent, InvestigationState } from "../analysis/stateTypes.js";
import type { SkippedArtifact } from "../integrations/velociraptor/velociraptorApi.js";
import { describeImportSource } from "../analysis/importMeta.js";
import { mergeEvictions, type SuperEviction } from "../analysis/superTimelineStore.js";
import { settleForensicImport } from "../routes/importSettle.js";
import { logLine } from "../logging/serverLogger.js";

export interface HuntSettleDeps {
  options: AppOptions;
  autoTagImported: (caseId: string, added: ForensicEvent[]) => Promise<void>;
  demoteForensicForCase: (caseId: string) => Promise<InvestigationState>;
  runStateExclusive?: <T>(caseId: string, fn: () => Promise<T>) => Promise<T>;
  pushImportCheckpoint: RouteContext["pushImportCheckpoint"];
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
  /** What the collect's own direct super-timeline appends (a super-only bundle) added and evicted. */
  superTimelineAddedCount: number;
  superTimelineEvicted: SuperEviction | undefined;
}

export interface HuntSettleResult {
  addedEvents: number;
  addedIocs: number;
  /** True when an undo checkpoint was pushed (the settle found a change to take back). */
  checkpointed: boolean;
  /** The settle, record or checkpoint failed: logged here, the rows stay as they were imported. */
  error?: string;
}

/** One combined import-meta diff (so the dashboard's "last import / +N" banner lights up). */
export async function settleHuntCollect(
  deps: HuntSettleDeps,
  input: HuntSettleInput,
): Promise<HuntSettleResult> {
  const { options } = deps;
  const { caseId, huntId, stateBefore, lastFile } = input;
  const result: HuntSettleResult = { addedEvents: 0, addedIocs: 0, checkpointed: false };
  if (!input.importedAny || !options.stateStore || !stateBefore) return result;
  let counted = result; // the counts stand once the settle itself returned, whatever fails after it
  try {
    // The one seam (routes/importSettle.ts): dual-write, tag, demote, diff post-demote.
    const settled = await settleForensicImport(
      {
        stateStore: options.stateStore,
        superTimelineStore: options.superTimelineStore,
        onSuperTimeline: options.onSuperTimeline,
        onState: options.onState,
        autoTagImported: deps.autoTagImported,
        demoteForensicForCase: deps.demoteForensicForCase,
        runStateExclusive: deps.runStateExclusive,
      },
      caseId,
      stateBefore,
      `hunt ${huntId}`,
    );
    const { timelineDiff: diff, iocsDiff } = settled;
    counted = { ...result, addedEvents: diff.added.length, addedIocs: iocsDiff.added.length };
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
        superTimelineEvicted: mergeEvictions(input.superTimelineEvicted, settled.superTimelineEvicted),
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
    // the import record or the undo entry is missing; the next import's settle grades what is left.
    const error = (e as Error).message;
    logLine(`[velociraptor] hunt ${huntId}: settling what was imported failed: ${error}`);
    return { ...counted, error };
  }
}

// The guard's refusal says this (analysis/importMemoryGuard.ts); it is false once an earlier artifact is kept.
const NOTHING_CHANGED = " and nothing was changed.";

/**
 * The artifacts a stopped collect did not import, as the job's skipped list records them: the one
 * that failed, with its error, and the ones after it that were never tried.
 */
export function notImportedRecords(failed: string, error: string, notReached: string[]): SkippedArtifact[] {
  return [
    { name: failed, error: error.replace(NOTHING_CHANGED, ".") },
    ...notReached.map((name) => ({ name, error: `not imported: the collect stopped when ${failed} failed` })),
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
