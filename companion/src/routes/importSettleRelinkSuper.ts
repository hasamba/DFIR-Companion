// #2619 — Undo an import, import the same file again: the forensic timeline holds the rows again
// under NEW ids (ids are per import), while the super-timeline's content dedup kept the OLD rows,
// whose ids the forensic timeline no longer holds — so the raw record shows them as not promoted.
//
// The dual-write reports each row it content-deduped onto a stored row of another id that the
// forensic timeline lacks. AFTER demote, the ones whose new id is still in the forensic timeline are
// relinked: the stored row takes the new id and the forensic row's grade, and its tags move with it.
// Running after demote is what keeps a plain re-import idempotent: its Info rows were demoted again,
// so they are not in the forensic timeline and nothing is rewritten. This writes only the raw record
// (the analyst-only surface) from the forensic rows; nothing here feeds the AI.

import { SCAN_PAGE_ROWS, type ForensicRowStore } from "../analysis/forensicRows.js";
import type { SuperRelink, SuperRelinkCandidate } from "../analysis/superTimelineStore.js";
import type { RunExclusive } from "./importSettleRows.js";
import { getServerLogger } from "../logging/serverLogger.js";

export interface RelinkSuperDeps {
  stateStore: Pick<ForensicRowStore, "forensicRowsById">;
  runStateExclusive: RunExclusive;
  superTimelineStore?: { relink?(caseId: string, links: readonly SuperRelink[]): Promise<number> };
  onSuperTimeline?: (caseId: string) => void;
}

/** Relink the candidates whose new id survived demote; returns the count rewritten. Non-fatal. */
export async function relinkSuperAfterSettle(
  deps: RelinkSuperDeps,
  caseId: string,
  candidates: readonly SuperRelinkCandidate[],
): Promise<number> {
  const store = deps.superTimelineStore;
  if (!store?.relink || !candidates.length) return 0;
  let rewritten = 0;
  try {
    for (let i = 0; i < candidates.length; i += SCAN_PAGE_ROWS) {
      const page = candidates.slice(i, i + SCAN_PAGE_ROWS);
      const rows = await deps.runStateExclusive(caseId, () =>
        deps.stateStore.forensicRowsById(
          caseId,
          page.map((c) => c.id),
        ),
      );
      const severityById = new Map(rows.map((r) => [r.event.id, r.event.severity]));
      const links = page.flatMap((c) => {
        const severity = severityById.get(c.id);
        return severity ? [{ fromId: c.storedId, toId: c.id, severity }] : [];
      });
      if (links.length) rewritten += await store.relink(caseId, links);
    }
  } catch (error) {
    getServerLogger().warn(
      `[import] ${caseId}: super-timeline relink failed — ${error instanceof Error ? error.message : String(error)}`,
      { caseId },
    );
  }
  if (rewritten) deps.onSuperTimeline?.(caseId);
  return rewritten;
}
