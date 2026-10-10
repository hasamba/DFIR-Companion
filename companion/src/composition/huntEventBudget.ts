import { SEVERITY_RANK } from "../analysis/forensicGate.js";
import type { Severity } from "../analysis/stateTypes.js";

/**
 * The hunt-wide forensic event budget (DFIR_MAX_EVENTS across every artifact of one hunt).
 *
 * Two rules, both about not losing detections to artifact order:
 *
 * 1. Only rows that will STAY in the forensic timeline are charged. Demote runs once after the whole
 *    hunt, so the per-artifact diff still holds the Info telemetry the gate is about to move to the
 *    super-timeline. Charging it let a few process/autorun listings spend the budget on rows that never
 *    reach synthesis, and a Hayabusa or THOR artifact read later was not imported at all.
 * 2. A spent budget no longer skips the remaining artifacts. They still import, with a floor that only
 *    lets Medium and above through, so a graded detection is never dropped because of where its
 *    artifact sat in the hunt. Only the low-value rows stop. The rows are persisted as evidence either
 *    way, as before.
 *
 * Every artifact keeps its own per-import cap (the same cap a standalone file import gets); the importer
 * keeps the most severe rows first under it.
 */
export const SPENT_BUDGET_FLOOR: Severity = "Medium";

export interface HuntEventBudget {
  /**
   * The next artifact's importer cap, plus the Medium floor once the budget is spent. The analyst's own
   * import floor still applies on top of it (the caller passes that separately, as before).
   */
  nextImport(): { maxEvents: number; minSeverity?: Severity };
  /**
   * Charge the rows one artifact added; only those at or above the forensic gate count. Freshly imported
   * rows are never analyst-placed, so severity alone decides what the gate keeps.
   */
  charge(added: readonly { severity: Severity }[], gateMin: Severity): void;
  readonly exhausted: boolean;
}

export function createHuntEventBudget(cap: number): HuntEventBudget {
  let charged = 0;
  return {
    nextImport() {
      return charged >= cap ? { maxEvents: cap, minSeverity: SPENT_BUDGET_FLOOR } : { maxEvents: cap };
    },
    charge(added, gateMin) {
      charged += added.filter((e) => SEVERITY_RANK[e.severity] >= SEVERITY_RANK[gateMin]).length;
    },
    get exhausted() {
      return charged >= cap;
    },
  };
}
