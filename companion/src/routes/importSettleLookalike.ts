import type { ForensicEvent } from "../analysis/stateTypes.js";
import { SCAN_PAGE_ROWS, type ForensicRowStore } from "../analysis/forensicRows.js";
import {
  caseAccountNames,
  caseLookalike,
  flagCaseLookalikeRow,
  lookalikeCandidateName,
  LOOKALIKE_ACCOUNT_MARKER,
} from "../analysis/lookalikeCaseAccount.js";
import { rewriteRows } from "./importSettleRows.js";

/**
 * Case-account look-alikes (#1971) over this import's new accounts and group members. It runs after
 * the tagger and before the build-time cap, so a corroborated build window still caps an account the
 * build itself created. The whole-case scan for account names happens only when the import added a
 * 4720 or a group-add row that is not already noted — most imports pay nothing (#1874). The names
 * come from the forensic timeline only, never the super-timeline (CLAUDE.md §7).
 */
export async function flagCaseLookalikesScoped(
  store: ForensicRowStore,
  caseId: string,
  added: readonly ForensicEvent[],
): Promise<number> {
  const candidates = new Map<string, string>();
  for (const e of added) {
    if ((e.description ?? "").includes(LOOKALIKE_ACCOUNT_MARKER)) continue;
    const name = lookalikeCandidateName(e);
    if (name) candidates.set(e.id, name);
  }
  if (!candidates.size) return 0;
  const pool = new Set<string>();
  for await (const batch of store.forensicTimelineBatches(caseId, { limit: SCAN_PAGE_ROWS })) {
    for (const e of batch) for (const name of caseAccountNames(e)) pool.add(name);
  }
  const hits = new Map<string, { name: string; match: string }>();
  for (const [id, name] of candidates) {
    const match = caseLookalike(name, pool);
    if (match) hits.set(id, { name, match });
  }
  if (!hits.size) return 0;
  const rows = await store.forensicRowsById(caseId, [...hits.keys()]);
  const written = await rewriteRows(store, caseId, rows, (e) => {
    const hit = hits.get(e.id);
    return hit ? flagCaseLookalikeRow(e, hit.name, hit.match) : e;
  });
  return written.length;
}
