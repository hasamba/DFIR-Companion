// The settle step that shows a service principal's name after its id on Azure activity rows (#2490,
// analysis/principalNameCarry.ts), over the rows it can change rather than the whole case (#1874).
//
// It runs AFTER demote: only rows that stay in the forensic timeline are rewritten, the tagger has
// already graded the raw text, and the super-timeline copies (dual-written before) keep the raw id.
// A ledger change (a name learned, a conflict, a name forgotten) can rename ANY old row, so the
// whole forensic timeline is scanned page by page then; otherwise only this import's own rows.

import type { ForensicEvent, InvestigationState } from "../analysis/stateTypes.js";
import { SCAN_PAGE_ROWS, type ForensicRowStore } from "../analysis/forensicRows.js";
import { principalNameCarrier } from "../analysis/principalNameCarry.js";
import { rewriteRows } from "./importSettleRows.js";

export async function nameCallersScoped(
  store: ForensicRowStore,
  caseId: string,
  ledger: Pick<InvestigationState, "principalNames">,
  opts: { scanAll: boolean; candidates: readonly ForensicEvent[] },
): Promise<number> {
  const carry = principalNameCarrier(ledger);
  const ids = new Set<string>();
  const read = (batch: readonly ForensicEvent[]): void => {
    for (const e of batch) if (carry(e) !== e) ids.add(e.id);
  };
  read(opts.candidates);
  if (opts.scanAll) {
    for await (const batch of store.forensicTimelineBatches(caseId, { limit: SCAN_PAGE_ROWS })) read(batch);
  }
  if (!ids.size) return 0;
  // Re-read under the caller's lock: a candidate may be stale, or gone after demote.
  const rows = await store.forensicRowsById(caseId, [...ids]);
  return (await rewriteRows(store, caseId, rows, carry)).length;
}
