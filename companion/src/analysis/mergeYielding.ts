import type { AnalysisDelta } from "./responseSchema.js";
import type { ForensicEvent, InvestigationState, IOC } from "./stateTypes.js";
import {
  assembleMerge,
  copyTimeline,
  correlateAndSort,
  mergeIocs,
  prepareIncoming,
  upsertForensicEvents,
  type WindowContext,
} from "./stateMerge.js";
import { timelinePasses } from "./timelineChain.js";
import { clampOutlierYears } from "./timeYearClamp.js";
import { FIXED_POINT_CLAMP, byIdLastWins, isFixedPoint } from "./incrementalMergeRows.js";
import { mapYielding, yieldToEventLoop } from "./yieldToEventLoop.js";

/**
 * The whole-case merge, giving the event loop a turn between its stages (#2716).
 *
 * On a large case the full-state merge and the index pass after it ran for minutes as one
 * synchronous block: no dashboard request, timer or poller could run until they finished. These are
 * the same steps, in the same order, over the same values — mergeDelta, runTimelineChain and
 * fixedPoints stay the reference and the tests hold these equal to them — with a yield between the
 * chain's passes and between the stages. Each pass still runs whole: the longest single block is now
 * the longest pass, not the sum of them.
 *
 * Yielding never releases the case's state lock (the caller holds it across the await), and every
 * value here is private to the merge until the caller saves it, so a reader that gets in during a
 * yield sees the case as it was stored before the merge, as it could during the store's own awaits.
 */

/** runTimelineChain, with a yield after every pass. */
export async function runTimelineChainYielding(
  forensicTimeline: readonly ForensicEvent[],
  iocs: readonly IOC[],
  at: string,
  clamp: (events: readonly ForensicEvent[]) => ForensicEvent[] = clampOutlierYears,
  metadataCoverage = true,
): Promise<ForensicEvent[]> {
  let events = forensicTimeline as ForensicEvent[];
  for (const pass of timelinePasses(iocs, at, clamp, metadataCoverage)) {
    events = pass(events);
    await yieldToEventLoop();
  }
  return events;
}

/** mergeDelta, step for step, with yields between its stages and the chain's passes. */
export async function mergeDeltaYielding(
  state: InvestigationState,
  incoming: AnalysisDelta,
  ctx: WindowContext,
): Promise<InvestigationState> {
  const delta = prepareIncoming(state, incoming, ctx);
  const { iocs, remapIocRefs, excludedRefsFor } = mergeIocs(state.iocs, delta, ctx, state.iocExcludeRules);
  const forensicTimeline = copyTimeline(state.forensicTimeline);
  upsertForensicEvents(forensicTimeline, delta, ctx);
  await yieldToEventLoop();
  const chained = await runTimelineChainYielding(forensicTimeline, iocs, ctx.timestamp);
  const { events, absorbedInto } = correlateAndSort(chained);
  await yieldToEventLoop();
  return assembleMerge(state, delta, ctx, {
    iocs,
    remapIocRefs,
    excludedRefsFor,
    forensicTimeline: events,
    absorbedInto,
  });
}

/** fixedPoints, with the chain yielding between passes and the per-row check run in slices. */
export async function fixedPointsYielding(values: readonly ForensicEvent[], at: string): Promise<boolean[]> {
  const chained = byIdLastWins(await runTimelineChainYielding(values, [], at, FIXED_POINT_CLAMP, false));
  return mapYielding(values, (v) => isFixedPoint(chained, v));
}
