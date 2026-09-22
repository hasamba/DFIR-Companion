// The super-timeline half of the rename carry (#1508).
//
// carryHostRenames (analysis/hostRenameCarry.ts) re-homes the forensic timeline when a settle learns
// a hostname rename. The super-timeline holds its own copies of those rows — every forensic row is
// dual-written into it, and every Info row demote captured lives ONLY there — and nothing rewrote
// them: the raw record kept the former name beside the current one, and a re-append of the carried
// rows is a no-op because the store dedups by id. So the super-timeline is re-homed from its own
// rows: stream them, recompute each against the case's ledger, write back exactly the ones that
// differ. The re-homed rows keep their id, severity, row order and retention age.
//
// Nothing here reads the raw record for analysis — the pass changes which host a row is filed
// under, never what the model sees (ARCHITECTURE.md → "The forensic / super-timeline boundary").

import type { ForensicEvent, InvestigationState } from "../analysis/stateTypes.js";
import { rehomeEvents } from "../analysis/hostRenameCarry.js";

type RenameLedger = Pick<InvestigationState, "hostRenames" | "collectorHostnames">;

export interface SuperRehomeStore {
  eventBatches(caseId: string): AsyncIterable<ForensicEvent[]>;
  rehome(caseId: string, events: ForensicEvent[]): Promise<number>;
}

/**
 * True when the settle changed what the ledger says about any host: a rename learned, unlearned or
 * re-bounded, or a collector identity that now vetoes a fold. Content, not identity — the importer
 * rebuilds the state object on every save.
 */
export function renameLedgerChanged(before: RenameLedger, after: RenameLedger): boolean {
  return (
    JSON.stringify(before.hostRenames ?? []) !== JSON.stringify(after.hostRenames ?? []) ||
    JSON.stringify(before.collectorHostnames ?? []) !== JSON.stringify(after.collectorHostnames ?? [])
  );
}

/** Re-home every stored super-timeline row the ledger moves; returns the count rewritten. */
export async function rehomeSuperTimeline(
  store: SuperRehomeStore,
  caseId: string,
  state: RenameLedger,
): Promise<number> {
  if (!state.hostRenames?.length) return 0;
  let rewritten = 0;
  for await (const batch of store.eventBatches(caseId)) {
    const changed = rehomeEvents(batch, state);
    if (changed.length) rewritten += await store.rehome(caseId, changed);
  }
  return rewritten;
}
