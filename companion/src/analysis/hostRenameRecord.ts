// One rename a case has learned (#1495) — the record persisted on the investigation state and
// handed to every later Windows-log import. Kept in the shared layer: stateTypes names the type and
// stateMerge unions the records; the evidence that produces them lives in analysis/ingest
// (hostRenameEvidence.ts), which imports this and never the other way round.

export type RenameBasis = "6011" | "machine-account" | "sam-domain" | "collector";

/**
 * `until` is the bound a record must be dated at or before to fold: for an evidence basis the
 * earliest observation of the renamed machine (an upper bound on the rename); for `collector` (a
 * hunt row whose Fqdn differed from its Computer, #1417) the last time the old name was seen — a
 * lower bound, so a record after it is NOT folded, the safe direction.
 */
export interface HostRenameRecord {
  formerName: string;
  currentName: string;
  until: string; // UTC ISO
  basis: RenameBasis;
}

// The first DNS label, upper-cased — the key hostIdentity.shortHostName compares on.
const hostKey = (name: string): string => name.trim().split(".")[0].toUpperCase();

/**
 * Union two ledgers by (former, current) short-name pair. The first spelling of a pair is kept; a
 * later, earlier-dated record only tightens the bound (and carries its basis). Order is stable —
 * `a`'s pairs first, then `b`'s new ones — so the state file does not churn.
 */
export function mergeHostRenameRecords(
  a: readonly HostRenameRecord[] = [],
  b: readonly HostRenameRecord[] = [],
): HostRenameRecord[] {
  const out = new Map<string, HostRenameRecord>();
  for (const r of [...a, ...b]) {
    if (!r.formerName.trim() || !r.currentName.trim() || Number.isNaN(Date.parse(r.until))) continue;
    const key = `${hostKey(r.formerName)}|${hostKey(r.currentName)}`;
    const cur = out.get(key);
    if (!cur) out.set(key, { ...r });
    else if (Date.parse(r.until) < Date.parse(cur.until))
      out.set(key, { ...cur, until: r.until, basis: r.basis });
  }
  return [...out.values()];
}
