/**
 * Re-grade an imported case with the current Sigma rules (#2206): the merge step.
 *
 * The re-graded rows go into the case through the same same-id merge a re-import uses
 * (mergeAndSaveDelta → stateMerge.upsertForensicEvents): the description and severity are
 * restated, the content tagger's grade is held (#2182), the change history records the move
 * (#2141), and the correlation passes re-apply their notes. An existing row's `promotedAt` is never
 * touched, and a row lifted out of the super-timeline joins as a normal graded row — never with
 * `promotedAt` (that is promoteSuperTimeline's mark, and this path never calls it).
 *
 * No `changeSource` is passed: a change source would skip the tagger hold.
 */
import { deltaSchema } from "../responseSchema.js";
import type { ForensicEvent, InvestigationState } from "../stateTypes.js";
import type { ImportContext } from "./importContext.js";
import { mergeAndSaveDelta } from "./importState.js";

export interface SigmaRegradeMergeOptions {
  /** The label the merge records as the change's source, e.g. "Sigma re-grade (r2026-07-01)". */
  label: string;
  at: string;
  /** The case-timeline note for this re-grade. */
  note: string;
}

export async function mergeSigmaRegrade(
  ctx: ImportContext,
  caseId: string,
  rows: readonly ForensicEvent[],
  opts: SigmaRegradeMergeOptions,
): Promise<InvestigationState | undefined> {
  if (!rows.length) return undefined;
  const delta = deltaSchema.parse({
    findings: [],
    iocs: [],
    mitreTechniques: [],
    threadsOpened: [],
    threadsClosed: [],
    timelineNote: opts.note,
    summary: "",
    // The schema keeps only the fields a merge may restate; promotedAt and provenance never ride.
    forensicEvents: rows.map((e) => ({ ...e })),
  });
  return ctx.withStateLock(caseId, () =>
    mergeAndSaveDelta(ctx, caseId, delta, {
      windowSequence: -1,
      timestamp: opts.at,
      sourceScreenshots: [opts.label],
    }),
  );
}
