import type { AppOptions } from "./appOptions.js";
import type { ForensicEvent, InvestigationState } from "../analysis/stateTypes.js";
import { demoteBelowSeverity, resolveForensicMinSeverity, SEVERITY_RANK } from "../analysis/forensicGate.js";

/**
 * The forensic gate's demote: route sub-threshold (Info by default) telemetry to the super-timeline
 * only. The super-timeline already captured these rows (the dual-write at each import seam); this
 * drops them from the forensic timeline so the model only synthesizes graded signal. Promotion
 * re-adds them if the analyst wants (pipeline.promoteSuperTimeline, NOT this gate). Threshold:
 * per-case forensic-gate ?? DFIR_FORENSIC_MIN_SEVERITY ?? "Low". Lifted out of importIngest.ts.
 *
 * The demote is CASE-WIDE, so with concurrent imports it can fire between another import's snapshot
 * and that import's dual-write, stripping rows the owning import had not yet copied to super — they
 * would then exist in neither timeline. The capture below closes that: a row may only leave the
 * forensic timeline after it is written to the super-timeline in this same critical section, and a
 * failed capture keeps every row. append() dedups by id, so re-capturing a row the seam already
 * wrote is free. With no super-timeline store wired there is nowhere to capture to, and the gate
 * removes the rows anyway — the behaviour this path has always had.
 *
 * #1874: it no longer loads and saves the whole case. The severity index finds the candidates (a
 * missing or unrecognized severity is a candidate, as it always was), demoteBelowSeverity applies
 * the exact rule to them (a promoted row or a manual event stays, #1919), and the demoted rows are
 * deleted by row id.
 */
export interface ImportDemoteDeps {
  options: AppOptions;
  runStateExclusive: <T>(caseId: string, fn: () => Promise<T>) => Promise<T>;
}

export interface ImportDemote {
  /** Remove every sub-threshold forensic row; returns the rows removed, in timeline order. */
  demoteForensic(caseId: string): Promise<ForensicEvent[]>;
  /** The same demote, returning the case state afterwards (one load — for callers that diff it). */
  demoteForensicForCase(caseId: string): Promise<InvestigationState>;
}

export function createImportDemote({ options, runStateExclusive }: ImportDemoteDeps): ImportDemote {
  async function demoteForensic(caseId: string): Promise<ForensicEvent[]> {
    const stateStore = options.stateStore;
    const gate = options.forensicGateControlStore;
    if (!stateStore || !gate) return [];
    return runStateExclusive(caseId, async () => {
      const min = resolveForensicMinSeverity(
        (await gate.load(caseId)).minSeverity,
        process.env.DFIR_FORENSIC_MIN_SEVERITY,
      );
      const keep = Object.keys(SEVERITY_RANK).filter(
        (s) => SEVERITY_RANK[s as keyof typeof SEVERITY_RANK] >= SEVERITY_RANK[min],
      );
      const candidates = await stateStore.forensicRowsOutsideSeverities(caseId, keep);
      const byId = new Map(candidates.map((r) => [r.event, r.rowId]));
      const { demoted } = demoteBelowSeverity(
        candidates.map((r) => r.event),
        min,
      );
      if (!demoted.length) return [];
      if (options.superTimelineStore) {
        try {
          await options.superTimelineStore.append(caseId, demoted);
          options.onSuperTimeline?.(caseId);
        } catch {
          // Capture failed — keep the rows in the forensic timeline rather than dropping them on
          // the floor; the next import/demote will retry.
          return [];
        }
      }
      await stateStore.deleteForensicRows(
        caseId,
        demoted.map((e) => byId.get(e)!),
      );
      return demoted;
    });
  }

  async function demoteForensicForCase(caseId: string): Promise<InvestigationState> {
    const removed = await demoteForensic(caseId);
    const state = await options.stateStore!.load(caseId);
    if (removed.length) options.onState?.(state);
    return state;
  }

  return { demoteForensic, demoteForensicForCase };
}
