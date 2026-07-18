// Run-to-run hunt diffing (issue #80) — the pure, unit-tested core.
//
// huntOutcomes.ts records a hit/miss delta against the whole CASE (resultRows snapshot,
// addedEvents/addedIocs cumulative after dedup) and dedups by VQL fingerprint, but that says nothing
// about a re-run of the SAME hunt (same fingerprint, a fresh Velociraptor huntId): an analyst
// re-deploying a recurring/scheduled hunt has no way to see which rows/hosts are new since the LAST
// time it ran. This module closes that gap: a bounded snapshot of each run's result rows is kept per
// fingerprint (HuntRunSnapshotStore), and diffHuntRuns compares consecutive runs — the hunt-result
// analog of diffIocs.ts / timelineDiff.ts.

export interface HuntRunSnapshot {
  rowKeys: string[];   // stable per-row fingerprints, capped — the run's row-identity set
  hosts: string[];     // distinct host identifiers extracted from the rows, capped
}

export interface HuntRunDiff {
  addedRows: number;
  removedRows: number;
  addedHosts: string[];    // hosts present in this run, not the previous one
  removedHosts: string[];  // hosts present in the previous run, not this one
  isFirstRun: boolean;     // no previous snapshot for this fingerprint yet — nothing to diff against
}

// Per-snapshot cap on distinct row keys / hosts so a hunt returning tens of thousands of rows doesn't
// blow up the persisted side file. Good enough to detect "something changed since last time", not a
// full audit log — a hunt whose distinct rows exceed this may show spurious added/removed noise at the
// margin (which rows survive the cap can vary run to run).
export const HUNT_RUN_SNAPSHOT_MAX_ROWS = 500;

// Field names likely to carry a host identity across Velociraptor artifacts (client-info style columns
// first, then common OS/EDR spellings). First match wins per row.
const HOST_FIELDS = ["Fqdn", "fqdn", "Hostname", "hostname", "ClientId", "client_id", "Computer", "computer", "Host", "host"];

function extractHost(row: unknown): string | undefined {
  if (!row || typeof row !== "object") return undefined;
  const obj = row as Record<string, unknown>;
  for (const field of HOST_FIELDS) {
    const v = obj[field];
    if (typeof v === "string" && v.trim()) return v.trim();
  }
  return undefined;
}

// A stable identity for a row: sorted-key JSON so field ORDER never causes a false "new" row, but any
// value change does (exact-match identity, mirroring diffIocs/diffTimeline's approach).
function rowKey(row: unknown): string {
  if (row && typeof row === "object" && !Array.isArray(row)) {
    const obj = row as Record<string, unknown>;
    const sorted = Object.keys(obj).sort().map((k) => [k, obj[k]] as const);
    return JSON.stringify(sorted);
  }
  return JSON.stringify(row);
}

function dedupeCapped(values: readonly string[], max: number): string[] {
  return [...new Set(values)].slice(0, Math.max(0, Math.floor(max)));
}

// Build a bounded snapshot of one hunt run's rows, from the artifact -> rows map a collect() returns.
export function buildHuntRunSnapshot(rowsByArtifact: Record<string, unknown[]>, maxRows: number = HUNT_RUN_SNAPSHOT_MAX_ROWS): HuntRunSnapshot {
  const rowKeys: string[] = [];
  const hosts: string[] = [];
  for (const rows of Object.values(rowsByArtifact ?? {})) {
    for (const row of rows ?? []) {
      rowKeys.push(rowKey(row));
      const host = extractHost(row);
      if (host) hosts.push(host);
    }
  }
  return { rowKeys: dedupeCapped(rowKeys, maxRows), hosts: dedupeCapped(hosts, maxRows) };
}

// Compare this run's snapshot against the PREVIOUS run's (undefined when this fingerprint has never
// been collected before — isFirstRun true, nothing meaningful to diff yet). Pure.
export function diffHuntRuns(previous: HuntRunSnapshot | undefined, current: HuntRunSnapshot): HuntRunDiff {
  const prevRows = new Set(previous?.rowKeys ?? []);
  const curRows = new Set(current.rowKeys);
  const prevHosts = new Set(previous?.hosts ?? []);
  const curHosts = new Set(current.hosts);
  let addedRows = 0;
  let removedRows = 0;
  for (const k of curRows) if (!prevRows.has(k)) addedRows++;
  for (const k of prevRows) if (!curRows.has(k)) removedRows++;
  const addedHosts: string[] = [];
  const removedHosts: string[] = [];
  for (const h of curHosts) if (!prevHosts.has(h)) addedHosts.push(h);
  for (const h of prevHosts) if (!curHosts.has(h)) removedHosts.push(h);
  return {
    addedRows,
    removedRows,
    addedHosts: addedHosts.sort(),
    removedHosts: removedHosts.sort(),
    isFirstRun: previous === undefined,
  };
}

// True when nothing changed (and it isn't the first run) — lets callers skip surfacing an empty diff.
export function isEmptyHuntRunDiff(diff: HuntRunDiff): boolean {
  return !diff.isFirstRun && diff.addedRows === 0 && diff.removedRows === 0 && diff.addedHosts.length === 0 && diff.removedHosts.length === 0;
}

// Compact human summary for the dashboard hunt-profile view, mirroring huntOutcomes.ts's summarizeResult.
export function summarizeHuntRunDiff(diff: HuntRunDiff): string {
  if (diff.isFirstRun) return "first run — no prior run to compare";
  const parts: string[] = [];
  if (diff.addedRows > 0) parts.push(`+${diff.addedRows} row${diff.addedRows === 1 ? "" : "s"} since last run`);
  if (diff.addedHosts.length) parts.push(`${diff.addedHosts.length} new host${diff.addedHosts.length === 1 ? "" : "s"}`);
  if (diff.removedRows > 0) parts.push(`-${diff.removedRows} row${diff.removedRows === 1 ? "" : "s"}`);
  if (!parts.length) return "no change since last run";
  return parts.join(", ");
}

// One case's ledger entry: the latest run snapshot recorded for a given VQL fingerprint, plus which
// huntId produced it — lets the caller (server.ts) tell "same run, more rows trickled in" apart from
// "a genuinely new run just started" before deciding whether a diff is meaningful to show.
export interface HuntRunRecord {
  vqlFingerprint: string;
  huntId: string;
  capturedAt: string;   // ISO
  snapshot: HuntRunSnapshot;
}

// Cap distinct fingerprints tracked per case (oldest-touched evicted first) so the side file stays
// small across a long investigation with many distinct hunts.
export const HUNT_RUN_RECORDS_MAX = 50;

export function findHuntRunRecord(records: readonly HuntRunRecord[], vqlFingerprint: string): HuntRunRecord | undefined {
  if (!vqlFingerprint) return undefined;
  return records.find((r) => r.vqlFingerprint === vqlFingerprint);
}

// Upsert the record for one fingerprint (prepended, newest first) and cap the tracked-fingerprint
// count. Pure — returns a new array, never mutates the input.
export function upsertHuntRunRecord(
  records: readonly HuntRunRecord[],
  input: HuntRunRecord,
  max: number = HUNT_RUN_RECORDS_MAX,
): HuntRunRecord[] {
  const rest = records.filter((r) => r.vqlFingerprint !== input.vqlFingerprint);
  const cap = Number.isFinite(max) && max > 0 ? Math.floor(max) : HUNT_RUN_RECORDS_MAX;
  return [input, ...rest].slice(0, cap);
}
