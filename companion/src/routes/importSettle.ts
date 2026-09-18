import { randomUUID } from "node:crypto";
import type { ForensicEvent, InvestigationState } from "../analysis/stateTypes.js";
import { diffTimeline, type TimelineDiff } from "../analysis/timelineDiff.js";
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
 * This used to be six inline copies (the generic import route twice, the streamed ingest, the hunt
 * collector, the two Velociraptor external-ingest paths) and ZERO copies on the dedicated
 * `import-*` routes, which called their
 * importer and resynthesized: an Info row from a dedicated route stayed in the forensic timeline
 * and reached the model, and never entered the super-timeline at all (#932 item 12 found it on
 * `/import-leapp`; #956 tracks the rest). One function, so a route cannot half-run the seam.
 *
 * `stateBefore` is the state captured under the import lock BEFORE the importer ran
 * (routes/importSection.ts) — the diff is only honest against that snapshot.
 */
export interface SettleDeps {
  stateStore: {
    load(caseId: string): Promise<InvestigationState>;
    save(state: InvestigationState): Promise<void>;
  };
  superTimelineStore?: { append(caseId: string, events: ForensicEvent[]): Promise<number> };
  onSuperTimeline?: (caseId: string) => void;
  // Fired right after the importedAt/importBatchId stamp save below (#1174) — without it, dashboard
  // subscribers only learn about the new stamps whenever a LATER broadcast happens to fire (the
  // tagger, demote, or the resynthesis every caller triggers after settle returns), not at the
  // instant the stamps were actually persisted.
  onState?: (state: InvestigationState) => void;
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
  let imported = await deps.stateStore.load(caseId);
  // Select the added rows BY ID — exact. The time+description diff below is case-folded, so two
  // rows that differ only by case (two paths on a case-sensitive filesystem) counted as one there,
  // and the second was neither dual-written nor offered to the tagger. Ids are exact: a re-import
  // of the same evidence is absorbed by correlation's exact-duplicate pass into the existing row's
  // id before this runs, so a new id is a genuinely new row.
  const beforeIds = new Set(stateBefore.forensicTimeline.map((e) => e.id));
  let added = imported.forensicTimeline.filter((e) => !beforeIds.has(e.id));

  // #1157: stamp rows genuinely new to this case with WHEN the case received them and WHICH import
  // action did it — distinct from `timestamp`, the artifact's own recorded time. One instant, one
  // batch id, shared by every row this import added. Persisted BEFORE dual-write/tag/demote below:
  // both `autoTagImported` and `demoteForensicForCase` independently reload state from the store,
  // so an in-memory-only stamp would be silently discarded by their own reload/save cycles.
  if (added.length) {
    const importedAt = new Date().toISOString();
    const importBatchId = randomUUID();
    const addedIds = new Set(added.map((e) => e.id));
    imported = {
      ...imported,
      forensicTimeline: imported.forensicTimeline.map((e) =>
        addedIds.has(e.id) ? { ...e, importedAt, importBatchId } : e,
      ),
    };
    added = imported.forensicTimeline.filter((e) => addedIds.has(e.id));
    await deps.stateStore.save(imported);
    deps.onState?.(imported);
  }

  // Dual-write FIRST, from the pre-demote (now stamped) state.
  let superTimelineAddedCount = 0;
  if (deps.superTimelineStore && added.length) {
    try {
      superTimelineAddedCount = await deps.superTimelineStore.append(caseId, added);
      deps.onSuperTimeline?.(caseId);
    } catch {
      // Non-fatal by design: demote captures every row it removes into the super-timeline in
      // its own critical section and KEEPS the row in the forensic timeline when that capture
      // fails (composition/importIngest.ts demoteForensicForCase) — a row is never in neither
      // record. What this failure costs is the count above, which stays 0.
    }
    await deps.autoTagImported(caseId, added);
  }
  const state = await deps.demoteForensicForCase(caseId);
  return {
    state,
    superTimelineAddedCount,
    timelineDiff: diffTimeline(stateBefore.forensicTimeline, state.forensicTimeline),
    iocsDiff: diffIocs(stateBefore.iocs, state.iocs),
  };
}
