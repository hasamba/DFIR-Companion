import type { FindingsDiff } from "../findingsDiff.js";
import { sortByEventTime } from "../forensicSort.js";
import type { StateLock } from "../stateLock.js";
import type { StateStore } from "../stateStore.js";
import type { IntelRetirementDecision, InvestigationState, TimelineEntry } from "../stateTypes.js";
import { mergeIntelState } from "../intelHistory.js";
import { annotateSightingsWithLabIntel, upsertLabIntel } from "../labIntel.js";
import { mergeHostRenameRecords } from "../hostRenameRecord.js";
import { carryHostRenames } from "../hostRenameCarry.js";

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
  /**
   * A last deterministic pass over the merged state, run INSIDE the locked write (#1595): the
   * simulation verdict reads the analyst's override there, so an override saved while the model was
   * thinking is not overwritten by this run's stale answer.
   */
  reconcile?: (merged: InvestigationState) => Promise<InvestigationState>;
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
    const concurrent = mergeConcurrentAdditions(input.loaded, input.next, latest);
    const merged = input.reconcile ? await input.reconcile(concurrent) : concurrent;
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
  // An IOC both sides carry keeps the newest intel state per assertion (#1024): a re-check that
  // finished while synthesis ran must not lose its appended history to the pre-import snapshot.
  const mergedIocs = [
    ...next.iocs.map((i) => {
      const l = latestIocByVal.get(i.value.toLowerCase());
      return l
        ? {
            ...l,
            ...mergeIntelState(i, l),
            enrichedBy: [...new Set([...(i.enrichedBy ?? []), ...(l.enrichedBy ?? [])])],
          }
        : i;
    }),
    ...latest.iocs.filter(
      (i) => !snapIocVals.has(i.value.toLowerCase()) && !nextIocVals.has(i.value.toLowerCase()),
    ),
  ];

  const snapThreadIds = new Set(loaded.openThreads.map((t) => t.id));
  const nextThreadIds = new Set(next.openThreads.map((t) => t.id));
  const addedThreads = latest.openThreads.filter((t) => !snapThreadIds.has(t.id) && !nextThreadIds.has(t.id));

  const snapTimeline = new Set(loaded.timeline.map(timelineKey));
  const nextTimeline = new Set(next.timeline.map(timelineKey));
  const addedTimeline = latest.timeline.filter(
    (t) => !snapTimeline.has(timelineKey(t)) && !nextTimeline.has(timelineKey(t)),
  );

  // Re-annotate over the WHOLE merged state at the end: a sandbox import that annotated a sighting
  // while synthesis ran would otherwise have its registry record kept and its annotation lost,
  // because the sighting itself is taken from `next` (the pre-import snapshot) (#932 item 5). The
  // rename carry is re-run for the same reason (#1495): a row an import re-homed while synthesis
  // ran is taken from `next` too, and the unioned ledger below would otherwise be saved beside the
  // old asset — the pass recomputes every eligible row from its record name, so it lands the same.
  return carryHostRenames(
    annotateSightingsWithLabIntel({
      ...next,
      forensicTimeline: addedEvents.length
        ? sortByEventTime([...next.forensicTimeline, ...addedEvents])
        : next.forensicTimeline,
      iocs: mergedIocs,
      openThreads: addedThreads.length ? [...next.openThreads, ...addedThreads] : next.openThreads,
      timeline: addedTimeline.length ? [...next.timeline, ...addedTimeline] : next.timeline,
      // The sandbox registry is keyed, so two writers cannot conflict: union everything the snapshot
      // did not have with everything this synthesis kept (#932 item 5).
      labIntel: upsertLabIntel(next.labIntel, latest.labIntel ?? []),
      // The rename ledger an import wrote while synthesis ran is kept (#1495): keyed unions, no conflict.
      ...(mergeHostRenameRecords(next.hostRenames, latest.hostRenames).length
        ? { hostRenames: mergeHostRenameRecords(next.hostRenames, latest.hostRenames) }
        : {}),
      ...(next.collectorHostnames?.length || latest.collectorHostnames?.length
        ? {
            collectorHostnames: [
              ...new Set([...(next.collectorHostnames ?? []), ...(latest.collectorHostnames ?? [])]),
            ],
          }
        : {}),
      // Analyst decisions recorded while synthesis ran are kept: keyed by finding id, newest wins.
      intelRetirementDecisions: mergeRetirementDecisions(
        next.intelRetirementDecisions,
        latest.intelRetirementDecisions,
      ),
    }),
  ).state;
}

/** Union two decision lists by finding id, the newest `decidedAt` winning. */
export function mergeRetirementDecisions(
  a: readonly IntelRetirementDecision[] | undefined,
  b: readonly IntelRetirementDecision[] | undefined,
): IntelRetirementDecision[] {
  const byId = new Map<string, IntelRetirementDecision>();
  for (const d of [...(a ?? []), ...(b ?? [])]) {
    const cur = byId.get(d.findingId);
    if (!cur || d.decidedAt > cur.decidedAt) byId.set(d.findingId, d);
  }
  return [...byId.values()];
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
