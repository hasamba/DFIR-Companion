// What a promotion did to each row it was asked to move (#1761). Deciding that afterwards, from
// "is the requested id in the forensic timeline now?", cannot tell a new row from one that was already
// there, from one the correlation merge folded into an existing event, or from one that took an
// existing event's place. The missed-evidence review called every fold "refused by the promotion
// seam" and wrote the requested count into the case timeline. This compares the state the promotion
// started from with the state it saved, through the case lineage (#1715), which the merge extends in
// the same step that folds a row away.

import { stateEventResolver } from "../eventAliasLookup.js";
import type { InvestigationState } from "../stateTypes.js";

/** A requested row that did not keep its own id, and the event that holds it now. */
export interface FoldedRow {
  id: string;
  of: string;
}

export interface PromotionOutcome {
  /** New in the forensic timeline — the only rows a promotion may count as promoted. */
  added: string[];
  /** Already in the forensic timeline under their own id before this promotion. */
  alreadyPresent: string[];
  /** Held by an event the forensic timeline had before this promotion. */
  duplicates: FoldedRow[];
  /** Folded into another row of this same request, which was added. */
  mergedIntoSelected: FoldedRow[];
  /** Added rows that took the place of an event the case already held: `of` is that event. */
  replaced: FoldedRow[];
  /** Neither landed nor folded — the seam refused them. */
  refused: string[];
}

/** The outcome of a promotion that moved nothing. A fresh object each call, so no caller shares arrays. */
export const emptyPromotionOutcome = (): PromotionOutcome => ({
  added: [],
  alreadyPresent: [],
  duplicates: [],
  mergedIntoSelected: [],
  replaced: [],
  refused: [],
});

/** `before` is the state the promotion loaded under its lock; `after` is the state it saved. */
export function promotionOutcome(
  before: Pick<InvestigationState, "forensicTimeline">,
  after: Pick<InvestigationState, "forensicTimeline" | "eventAliases">,
  requestedIds: readonly string[],
): PromotionOutcome {
  const liveBefore = new Set(before.forensicTimeline.map((e) => e.id));
  const liveAfter = new Set(after.forensicTimeline.map((e) => e.id));
  const requested = [...new Set(requestedIds)];
  const added = requested.filter((id) => !liveBefore.has(id) && liveAfter.has(id));
  const addedSet = new Set(added);
  const resolve = stateEventResolver(after);
  const out: PromotionOutcome = { ...emptyPromotionOutcome(), added };
  for (const id of requested) {
    if (addedSet.has(id)) continue;
    if (liveBefore.has(id)) {
      out.alreadyPresent.push(id);
      continue;
    }
    const of = resolve(id);
    if (of === id) out.refused.push(id);
    else (addedSet.has(of) ? out.mergedIntoSelected : out.duplicates).push({ id, of });
  }
  // The fold keeps the most severe member's id, so a promoted row can absorb an event the case held.
  for (const id of liveBefore) {
    if (liveAfter.has(id)) continue;
    const survivor = resolve(id);
    if (addedSet.has(survivor)) out.replaced.push({ id: survivor, of: id });
  }
  return out;
}
