// The S3 ransomware-precursor join across uploads (#2563, part of #2542).
//
// The importer raises a bucket recovery check (GetBucketVersioning, GetBucketObjectLockConfiguration,
// PutBucketVersioning set to Suspended) to High when the SAME access key made a successful privileged
// change earlier IN THE SAME UPLOAD (awsPrecursorGrade.ts). A trail delivered as one file per region
// and five-minute slice puts the change and the check in different files, so that join never fires
// on a per-file import. This pass makes the same join over the whole forensic timeline, in the merge
// chain: a check row is raised when the case holds an earlier change by its key, whichever file
// brought either half. The other order — the check arrived first, was graded Info and demoted to the
// super-timeline — is the documented promotion in ingest/cloudPrecursorPromote.ts.
//
// Both halves are read from the row's `canonical.awsPrecursor` block, stamped by the importer from
// the raw record — never from description text, which carries attacker-chosen policy and user names.
// Rows imported before #2563 carry no block and are not joined. Compared by event time — a folded
// row's last occurrence, so checks folded across the change still join. Only raises;
// a row that already carries the note (from the import or an earlier merge) is left alone, so the
// pass is idempotent. Per-row: the incremental merge holds every row it reads (mergeIndex.ts).

import type { ForensicEvent, Severity } from "./stateTypes.js";
import { worstSeverity } from "./stateTypes.js";
import { appendDerivedNote } from "./derivedNote.js";

/** The registered note name (derivedNote.ts). The import-time raise writes it too. */
export const CLOUD_PRECURSOR_MARKER = "[ransomware precursor:";
const PRECURSOR_GRADE: Severity = "High";

export interface PrecursorChange {
  time: number;
  call: string;
}

/** Where the change was seen, as the note says it. */
export type PrecursorScope = "upload" | "case" | "promoted";

const SCOPE_TEXT: Record<PrecursorScope, string> = {
  upload: "earlier in this upload",
  case: "earlier in this case",
  promoted: "earlier in this case; promoted from the super-timeline when the change arrived",
};

/** The note's text, without the marker. Shared so every path states the join the same way. */
export function precursorNoteText(change: PrecursorChange, scope: PrecursorScope): string {
  const at = new Date(change.time).toISOString().slice(0, 19);
  return `the same access key made a privileged change ${SCOPE_TEXT[scope]} — ${change.call} at ${at}Z`;
}

/** The access key a row was signed with, lowercased, or "". */
export function precursorKey(e: Pick<ForensicEvent, "canonical">): string {
  return (e.canonical?.authentication?.credentialId ?? "").trim().toLowerCase();
}

const timeOf = (e: ForensicEvent): number => Date.parse(e.timestamp);
/** A folded row's LAST occurrence (aggregation keeps the first as its timestamp). */
const lastTimeOf = (e: ForensicEvent): number => Date.parse(e.endTimestamp ?? e.timestamp);
const hasNote = (e: ForensicEvent): boolean => (e.description ?? "").includes(CLOUD_PRECURSOR_MARKER);

/** A successful privileged change by an access key, as the importer stamped it. */
export function isPrecursorChange(e: ForensicEvent): boolean {
  return e.canonical?.awsPrecursor?.role === "change" && precursorKey(e) !== "";
}

/** A bucket recovery check by an access key that no join has raised yet. */
export function isOpenPrecursorCheck(e: ForensicEvent): boolean {
  return e.canonical?.awsPrecursor?.role === "check" && precursorKey(e) !== "" && !hasNote(e);
}

/** The earliest privileged change per access key. */
export function earliestPrecursorChanges(events: readonly ForensicEvent[]): Map<string, PrecursorChange> {
  const out = new Map<string, PrecursorChange>();
  for (const e of events) {
    if (!isPrecursorChange(e)) continue;
    const time = timeOf(e);
    if (!Number.isFinite(time)) continue;
    const key = precursorKey(e);
    const cur = out.get(key);
    if (!cur || time < cur.time) out.set(key, { time, call: e.canonical!.awsPrecursor!.call });
  }
  return out;
}

/** The check raised for an earlier change, or null when the join does not hold for it. */
export function raisePrecursorCheck(
  e: ForensicEvent,
  changes: ReadonlyMap<string, PrecursorChange>,
  scope: PrecursorScope,
): ForensicEvent | null {
  if (!isOpenPrecursorCheck(e)) return null;
  const change = changes.get(precursorKey(e));
  // A folded row of several checks joins when any of them came after the change.
  const time = lastTimeOf(e);
  if (!change || !Number.isFinite(time) || change.time >= time) return null;
  return {
    ...e,
    severity: worstSeverity(e.severity, PRECURSOR_GRADE),
    description: appendDerivedNote(e.description, CLOUD_PRECURSOR_MARKER, precursorNoteText(change, scope)),
  };
}

/** The merge-chain pass: raise every open check whose key made an earlier change in the case. */
export function raiseCasePrecursors(events: readonly ForensicEvent[]): ForensicEvent[] {
  const changes = earliestPrecursorChanges(events);
  if (!changes.size) return [...events];
  return events.map((e) => raisePrecursorCheck(e, changes, "case") ?? e);
}
