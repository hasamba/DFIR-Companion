import type { StateStore } from "../analysis/stateStore.js";
import { SCAN_PAGE_ROWS } from "../analysis/forensicRows.js";
import { upgradeForensicEvent } from "../analysis/canonicalEvent.js";
import { nsrlMatchEvents, type NsrlLookup } from "../analysis/nsrl.js";
import { forensicFacts, hasRowFacts, refreshRowFacts, rowFactsStamp } from "../analysis/rowFacts.js";
import type { ForensicEvent } from "../analysis/stateTypes.js";

type EventMatches = ReturnType<typeof nsrlMatchEvents>;

/**
 * The forensic rows whose file hash the NSRL set knows, in timeline order (#1874) — what
 * nsrlMatchEvents over every row returns, without reading every row: the row facts hold each row's
 * normalized SHA-256 and MD5, so only the rows carrying a hash are looked up, and only the ones that
 * match (plus the rows written since the facts were computed) are read. Each matched row is matched
 * again as read, so the marker is built from the row exactly as the full pass would have seen it.
 */
export async function nsrlEventMatches(
  stateStore: StateStore,
  caseId: string,
  lookup: NsrlLookup,
): Promise<EventMatches> {
  if (!hasRowFacts(stateStore)) return scanMatches(stateStore, caseId, lookup);
  await refreshRowFacts(stateStore, caseId);
  const rows = await stateStore.factsCandidates(caseId, rowFactsStamp(), "nsrl");
  const hit = (sha: string | null | undefined, md5: string | null | undefined): boolean =>
    Boolean((sha && lookup(sha)) || (md5 && lookup(md5)));
  const matched = rows.filter((r) => {
    if (r.payload === undefined) return hit(r.sha, r.md5);
    const facts = forensicFacts(r.payload);
    return hit(facts.sha, facts.md5);
  });
  const known = matched.filter((r) => r.payload === undefined).map((r) => r.rowId);
  const read = new Map(
    (await stateStore.forensicRowsByRowId(caseId, known)).map((row) => [row.rowId, row.event]),
  );
  const events = matched
    .map((r) =>
      r.payload === undefined ? read.get(r.rowId) : upgradeForensicEvent(r.payload as ForensicEvent),
    )
    .filter((e): e is ForensicEvent => e !== undefined);
  return nsrlMatchEvents(events, lookup);
}

// Every row, a page at a time (a store without row facts).
async function scanMatches(
  stateStore: StateStore,
  caseId: string,
  lookup: NsrlLookup,
): Promise<EventMatches> {
  const out: EventMatches = [];
  for await (const batch of stateStore.forensicTimelineBatches(caseId, { limit: SCAN_PAGE_ROWS })) {
    out.push(...nsrlMatchEvents(batch, lookup));
  }
  return out;
}
