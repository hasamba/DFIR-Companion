// The M365 BEC pairings (#2550) as one join, used at import and across the whole case (#2570).
//
// 1. A hiding inbox rule within HIDE_PAIR_WINDOW_MS of a rule that forwards outside, by the same
//    actor on the same mailbox, in either order → the hiding rule is raised to Critical.
// 2. A privileged directory-role grant at most NEW_USER_GRANT_WINDOW_MS after an `Add user` for that
//    user → the grant is raised to High. The creation row keeps its grade.
//
// The importer (m365BecPairing.ts) stamps the facts as `canonical.m365Bec` from the raw record and
// runs this join over one parse. A streamed import parses in batches and a case is built from many
// uploads, so the same join runs again in the merge chain over every stored row (raiseCaseBecPairs):
// a pair whose halves were imported apart is raised when the second half arrives, whichever came
// first. Every side is graded above Info (forward-out rule High, hiding rule High, `Add user` Medium,
// privileged grant Medium/High), so both halves are forensic rows — nothing reads the super-timeline.
//
// Times come from the block itself — when the record whose facts it holds happened. A folded row (the
// importer's own aggregation, or a streamed import's budget aggregate of several users) keeps ONE
// member's block while its span stretches over every member, so the span is never read: folding can
// lose a pair but never borrows another member's time to invent one (#2570 review). Rows without the block (imported before #2570) never join.
// Only raises. Idempotent by state: a row below its pairing grade is raised; the note goes on once.
// Per-row: the incremental merge holds every row carrying the block (mergeIndex.ts).

import type { M365BecBlock } from "./canonicalMailbox.js";
import { appendDerivedNote } from "./derivedNote.js";
import { SEVERITY_RANK, type ForensicEvent, type Severity } from "./stateTypes.js";

/** The registered note name (derivedNote.ts). The import-time raise writes it too. */
export const BEC_PAIRING_MARKER = "[BEC pairing:";
export const HIDE_PAIR_WINDOW_MS = 10 * 60_000;
export const NEW_USER_GRANT_WINDOW_MS = 24 * 60 * 60_000;

/** Where the partner was seen, as the note says it. */
export type BecScope = "export" | "case";

/** One row as the join reads it: its block and the time of the record the block describes. */
export interface BecJoinRow {
  block: M365BecBlock;
  time: number;
}

/** The join row of a block, or null when it has no usable time. */
export function becJoinRow(block: M365BecBlock | undefined): BecJoinRow | null {
  const time = block ? Date.parse(block.at) : NaN;
  return block && Number.isFinite(time) ? { block, time } : null;
}

export interface BecRaise {
  severity: Severity;
  note: string;
}

const differ = (a?: string, b?: string): boolean => !!a && !!b && a !== b;

/** Same actor on the same mailbox, with no domain or tenant that tells the two apart. */
function sameMailbox(a: M365BecBlock, b: M365BecBlock): boolean {
  return (
    !!a.rule && a.rule === b.rule && !differ(a.mailboxDomain, b.mailboxDomain) && !differ(a.tenant, b.tenant)
  );
}

function hideRaises(rows: readonly (BecJoinRow | null)[], scope: BecScope, out: Map<number, BecRaise>): void {
  const forwards = rows.flatMap((r, i) => (r?.block.role === "rule" && r.block.forwardsOut ? [i] : []));
  rows.forEach((hide, i) => {
    if (hide?.block.role !== "rule" || !hide.block.hidesHard) return;
    const paired = forwards.some((f) => {
      const fwd = rows[f]!;
      return (
        f !== i && sameMailbox(hide.block, fwd.block) && Math.abs(hide.time - fwd.time) <= HIDE_PAIR_WINDOW_MS
      );
    });
    if (paired)
      out.set(i, {
        severity: "Critical",
        note: `hides mail; a forward-out rule by the same actor on this mailbox is within 10 minutes in this ${scope}`,
      });
  });
}

function grantRaises(
  rows: readonly (BecJoinRow | null)[],
  scope: BecScope,
  out: Map<number, BecRaise>,
): void {
  const created = rows.filter((r): r is BecJoinRow => r?.block.role === "created");
  if (!created.length) return;
  rows.forEach((g, i) => {
    if (g?.block.role !== "grant" || out.has(i)) return;
    const ids = new Set(g.block.ids ?? []);
    const hit = created.some(
      (c) =>
        !differ(c.block.tenant, g.block.tenant) &&
        (c.block.ids ?? []).some((id) => ids.has(id)) &&
        g.time >= c.time &&
        g.time - c.time <= NEW_USER_GRANT_WINDOW_MS,
    );
    if (hit)
      out.set(i, {
        severity: "High",
        note: `${g.block.roleName || "a privileged role"} granted to a user created within 24 hours in this ${scope}`,
      });
  });
}

/** Row index → the grade the pairing proves and the note that says why. */
export function becRaises(rows: readonly (BecJoinRow | null)[], scope: BecScope): Map<number, BecRaise> {
  const out = new Map<number, BecRaise>();
  hideRaises(rows, scope, out);
  grantRaises(rows, scope, out);
  return out;
}

/** The row raised to the pairing's grade, the note added once; the row itself when already there. */
export function applyBecRaise<T extends { severity: Severity; description: string }>(row: T, r: BecRaise): T {
  if (SEVERITY_RANK[row.severity] <= SEVERITY_RANK[r.severity]) return row;
  const noted = row.description.includes(BEC_PAIRING_MARKER);
  return {
    ...row,
    severity: r.severity,
    ...(noted ? {} : { description: appendDerivedNote(row.description, BEC_PAIRING_MARKER, r.note) }),
  };
}

/** The merge-chain pass: raise every stored row a pairing over the whole case proves. */
export function raiseCaseBecPairs(events: readonly ForensicEvent[]): ForensicEvent[] {
  const rows = events.map((e) => becJoinRow(e.canonical?.m365Bec));
  if (!rows.some(Boolean)) return [...events];
  const raise = becRaises(rows, "case");
  if (!raise.size) return [...events];
  return events.map((e, i) => {
    const r = raise.get(i);
    return r ? applyBecRaise(e, r) : e;
  });
}
