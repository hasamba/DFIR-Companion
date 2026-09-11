import type { ForensicEvent, InvestigationState } from "../analysis/stateTypes.js";
import { diffTimeline, addedForensicEvents, type TimelineDiff } from "../analysis/timelineDiff.js";
import { diffIocs, type IocsDiff } from "../analysis/iocsDiff.js";

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
 * This used to be four inline copies (the generic import route twice, the two Velociraptor
 * external-ingest paths) and ZERO copies on the dedicated `import-*` routes, which called their
 * importer and resynthesized: an Info row from a dedicated route stayed in the forensic timeline
 * and reached the model, and never entered the super-timeline at all (#932 item 12 found it on
 * `/import-leapp`; #956 tracks the rest). One function, so a route cannot half-run the seam.
 *
 * `stateBefore` is the state captured under the import lock BEFORE the importer ran
 * (routes/importSection.ts) — the diff is only honest against that snapshot.
 */
export interface SettleDeps {
  stateStore: { load(caseId: string): Promise<InvestigationState> };
  superTimelineStore?: { append(caseId: string, events: ForensicEvent[]): Promise<number> };
  onSuperTimeline?: (caseId: string) => void;
  autoTagImported: (caseId: string, added: ForensicEvent[]) => Promise<void>;
  demoteForensicForCase: (caseId: string) => Promise<InvestigationState>;
}

export interface SettledImport {
  /** The case state after demote — what the forensic timeline holds now. */
  state: InvestigationState;
  /** Rows the super-timeline RETAINED from this import (0 when no store is wired). */
  superTimelineAddedCount: number;
  /** Forensic-timeline diff against `stateBefore`, computed post-demote. */
  timelineDiff: TimelineDiff;
  iocsDiff: IocsDiff;
}

export async function settleForensicImport(
  deps: SettleDeps,
  caseId: string,
  stateBefore: InvestigationState,
): Promise<SettledImport> {
  const imported = await deps.stateStore.load(caseId);
  // Dual-write FIRST, from the pre-demote state: the diff is lossy (time + description), so the
  // full events are resolved from the state that still holds every row this import merged.
  let superTimelineAddedCount = 0;
  if (deps.superTimelineStore) {
    const superDiff = diffTimeline(stateBefore.forensicTimeline, imported.forensicTimeline);
    const added = addedForensicEvents(imported.forensicTimeline, superDiff);
    if (added.length) {
      try {
        superTimelineAddedCount = await deps.superTimelineStore.append(caseId, added);
        deps.onSuperTimeline?.(caseId);
      } catch {
        /* non-fatal — the forensic record is intact; the analyst-only copy lags */
      }
      await deps.autoTagImported(caseId, added);
    }
  }
  const state = await deps.demoteForensicForCase(caseId);
  return {
    state,
    superTimelineAddedCount,
    timelineDiff: diffTimeline(stateBefore.forensicTimeline, state.forensicTimeline),
    iocsDiff: diffIocs(stateBefore.iocs, state.iocs),
  };
}
