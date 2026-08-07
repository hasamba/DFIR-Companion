import type { FindingsDiff } from "../findingsDiff.js";
import { sortByEventTime } from "../forensicSort.js";
import type { StateLock } from "../stateLock.js";
import type { StateStore } from "../stateStore.js";
import type { InvestigationState, TimelineEntry } from "../stateTypes.js";

/**
 * The synthesis write, and the lost-update guard that makes it safe (#453, split from `synthesize`).
 *
 * Synthesis derives its whole result from a snapshot taken BEFORE a seconds-long model call. Saving
 * that result naively would clobber anything an import or an analyst added while the model was
 * thinking. So the write re-reads the LATEST state under the lock and carries forward only what is
 * NEW since the snapshot — by id for events and threads, by lowercased value for IOCs, by
 * timestamp+sequence+text for Investigation-Log lines.
 *
 * The comparison is against the RAW snapshot (`loaded`), never the in-memory correlated state:
 * correlateEvents deduplicates events, and diffing against the correlated timeline would re-add
 * every event it just merged away.
 */

export interface SynthesisPersistContext {
  readonly opts: {
    stateStore: StateStore;
    stateLock?: StateLock;
  };
}

export interface SynthesisPersistInput {
  /** The RAW pre-call snapshot. Concurrency is judged against this, not the correlated state. */
  loaded: InvestigationState;
  /** This run's conclusions, derived from the snapshot. */
  next: InvestigationState;
  /** What this run changed, for the Investigation-Log line. */
  findingsDiff: FindingsDiff;
}

/**
 * Merge concurrent additions into this run's conclusions, append the run's log line, and save —
 * under the state lock when one is configured.
 *
 * Returns the state actually persisted. The caller must use THAT, not its own `next`: the run
 * record, the hypothesis sanitizer and the notify hook all describe what was written.
 */
export async function persistSynthesis(
  ctx: SynthesisPersistContext,
  caseId: string,
  input: SynthesisPersistInput,
): Promise<InvestigationState> {
  let persisted = input.next;
  const write = async (): Promise<void> => {
    const latest = await ctx.opts.stateStore.load(caseId);
    const merged = mergeConcurrentAdditions(input.loaded, input.next, latest);
    // Record THIS synthesis run as a durable, cross-session Investigation-Log line (#165) — imports
    // already log via timelineNote; synthesis didn't. Final merged counts; one entry per real run.
    persisted = {
      ...merged,
      timeline: [...merged.timeline, buildSynthesisLogEntry(merged, input.findingsDiff)],
    };
    await ctx.opts.stateStore.save(persisted);
  };
  if (ctx.opts.stateLock) await ctx.opts.stateLock.runExclusive(caseId, write);
  else await write();
  return persisted;
}

/** Investigation-Log lines are identified by content, not id — imports append them without one. */
const timelineKey = (t: TimelineEntry): string => `${t.timestamp}|${t.windowSequence}|${t.description}`;

/**
 * Carry forward every event, IOC, thread and log line that appeared BETWEEN the snapshot and now.
 *
 * Pure. `next` keeps its own conclusions and its correlation/legitimate work on the snapshot
 * timeline; `latest` contributes only what neither the snapshot nor this run already has. An IOC
 * present in both takes the LATEST copy, so enrichment that landed during the call is not reverted.
 */
export function mergeConcurrentAdditions(
  loaded: InvestigationState,
  next: InvestigationState,
  latest: InvestigationState,
): InvestigationState {
  const snapEventIds = new Set(loaded.forensicTimeline.map((e) => e.id));
  const nextEventIds = new Set(next.forensicTimeline.map((e) => e.id));
  const addedEvents = latest.forensicTimeline.filter(
    (e) => !snapEventIds.has(e.id) && !nextEventIds.has(e.id),
  );

  const snapIocVals = new Set(loaded.iocs.map((i) => i.value.toLowerCase()));
  const nextIocVals = new Set(next.iocs.map((i) => i.value.toLowerCase()));
  const latestIocByVal = new Map(latest.iocs.map((i) => [i.value.toLowerCase(), i]));
  const mergedIocs = [
    ...next.iocs.map((i) => latestIocByVal.get(i.value.toLowerCase()) ?? i),
    ...latest.iocs.filter(
      (i) => !snapIocVals.has(i.value.toLowerCase()) && !nextIocVals.has(i.value.toLowerCase()),
    ),
  ];

  const snapThreadIds = new Set(loaded.openThreads.map((t) => t.id));
  const nextThreadIds = new Set(next.openThreads.map((t) => t.id));
  const addedThreads = latest.openThreads.filter(
    (t) => !snapThreadIds.has(t.id) && !nextThreadIds.has(t.id),
  );

  const snapTimeline = new Set(loaded.timeline.map(timelineKey));
  const nextTimeline = new Set(next.timeline.map(timelineKey));
  const addedTimeline = latest.timeline.filter(
    (t) => !snapTimeline.has(timelineKey(t)) && !nextTimeline.has(timelineKey(t)),
  );

  return {
    ...next,
    forensicTimeline: addedEvents.length
      ? sortByEventTime([...next.forensicTimeline, ...addedEvents])
      : next.forensicTimeline,
    iocs: mergedIocs,
    openThreads: addedThreads.length ? [...next.openThreads, ...addedThreads] : next.openThreads,
    timeline: addedTimeline.length ? [...next.timeline, ...addedTimeline] : next.timeline,
  };
}

function buildSynthesisLogEntry(state: InvestigationState, diff: FindingsDiff): TimelineEntry {
  return {
    timestamp: new Date().toISOString(),
    windowSequence: 0,
    description:
      `Synthesis: ${state.findings.length} finding(s) (${diff.added.length} new, ` +
      `${diff.severityChanged.length} reclassified), ${state.forensicTimeline.length} event(s), ` +
      `${state.iocs.length} IOC(s)`,
    sourceScreenshots: [],
  };
}
