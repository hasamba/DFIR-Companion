import { SEVERITY_RANK, type ForensicEvent } from "./stateTypes.js";
import { byEventTime } from "./forensicSort.js";

/**
 * One synthesis seat per distinct CLOUD AUDIT operation (#2585).
 *
 * On a cloud audit timeline over the prompt budget, a flood of one operation (hundreds of High
 * "Consent to application" rows) used to take every seat, so the one Set-Mailbox forwarding change
 * or New-InboxRule never reached the model. The rarity and burst fills key on the description,
 * which a cloud row's actor/target/IP text defeats. The operation the importer itself read is the
 * stable key: `canonical.event.action` on the row's own audit-log envelope.
 *
 * Scope (product decision on #2585): Microsoft 365 / Entra / Exchange unified audit, AWS CloudTrail
 * and GCP audit rows only. Every other row has no key, so an endpoint case selects exactly as before.
 */

/** Share of the prompt cap reserved for one row per distinct cloud operation not already seated. */
export const BUDGET_CLOUD_OPERATION = 0.12;

// The audit logs whose envelope's `event.action` is the importer's operation name, by family. A row
// counts only when its envelope's FIRST raw record is one of these: a correlate merge keeps the
// winner's pointers first and the winner's `event.action`, so the two always describe one record.
const AUDIT_SOURCE_FAMILY: Readonly<Record<string, string>> = {
  "m365-ual": "m365", // UAL rows, Exchange cmdlets and Entra audit in UAL shape
  "entra-audit": "m365", // the Graph-shaped Entra audit export
  "aws-cloudtrail": "aws",
  "gcp-audit": "gcp",
};

// Summary rows DERIVED from those logs cite the same source but are not one operation each
// (mailboxChain.ts, gcpServiceAccountJoin.ts); their "omitted" rows are cap notes.
const DERIVED_EVENT_TYPES: ReadonlySet<string> = new Set(["mailbox-chain", "service-account-join"]);

/** `<family>|<operation>` for a cloud audit row, or null for every other row. */
export function cloudOperationKey(e: ForensicEvent): string | null {
  const c = e.canonical;
  const family = AUDIT_SOURCE_FAMILY[c?.evidence?.rawRecords?.[0]?.source ?? ""];
  if (!c || !family || DERIVED_EVENT_TYPES.has(c.event.type ?? "")) return null;
  // Entra writes both "Add user" and "Add user." for one activity.
  const op = (c.event.action ?? "").trim().replace(/\.$/, "").toLowerCase();
  if (!op || op === "omitted") return null;
  return `${family}|${op}`;
}

/** Seats for missing operations at this cap: the share, at least one, never more than are missing. */
export function operationShare(max: number, missing: number): number {
  if (missing <= 0) return 0;
  return Math.min(missing, Math.max(1, Math.floor(max * BUDGET_CLOUD_OPERATION)));
}

const sevRank = (e: ForensicEvent): number => (SEVERITY_RANK as Record<string, number>)[e.severity] ?? 9;

// Highest severity, then earliest, then id: the row that best stands for its operation.
const byRepresentative = (a: ForensicEvent, b: ForensicEvent): number =>
  sevRank(a) - sevRank(b) || byEventTime(a, b) || a.id.localeCompare(b.id);

/**
 * One representative per cloud operation that `represented` does not already cover, in seat
 * priority order: highest severity first, then earliest, then the key. Deterministic.
 */
export function missingOperations(
  events: readonly ForensicEvent[],
  represented: (key: string) => boolean,
): ForensicEvent[] {
  const best = new Map<string, ForensicEvent>();
  for (const e of events) {
    const key = cloudOperationKey(e);
    if (key === null || represented(key)) continue;
    const prev = best.get(key);
    if (!prev || byRepresentative(e, prev) < 0) best.set(key, e);
  }
  return [...best.values()].sort(byRepresentative);
}

/** The operation keys of `events` (rows with no key are skipped). */
export function operationKeys(events: Iterable<ForensicEvent>): Set<string> {
  const keys = new Set<string>();
  for (const e of events) {
    const key = cloudOperationKey(e);
    if (key !== null) keys.add(key);
  }
  return keys;
}

/**
 * Up to `n` anchors that may give up their seat to a missing operation: cloud rows whose operation
 * keeps another seated anchor. Walked from the LOWEST-ranked end of `rankedAnchors` (best first), and
 * the count drops as each is taken, so the last anchor of an operation is never chosen. An endpoint
 * anchor has no operation, so it is never a repeat and never chosen.
 */
export function repeatedCloudAnchors(rankedAnchors: readonly ForensicEvent[], n: number): ForensicEvent[] {
  if (n <= 0) return [];
  const perOp = new Map<string, number>();
  for (const e of rankedAnchors) {
    const key = cloudOperationKey(e);
    if (key !== null) perOp.set(key, (perOp.get(key) ?? 0) + 1);
  }
  const out: ForensicEvent[] = [];
  for (let i = rankedAnchors.length - 1; i >= 0 && out.length < n; i--) {
    const key = cloudOperationKey(rankedAnchors[i]);
    if (key === null || (perOp.get(key) ?? 0) < 2) continue;
    perOp.set(key, (perOp.get(key) ?? 0) - 1);
    out.push(rankedAnchors[i]);
  }
  return out;
}

/** How many distinct cloud operations in `pool` have no row in `shown` — the analyst disclosure. */
export function unsentOperationCount(pool: readonly ForensicEvent[], shown: ReadonlySet<string>): number {
  const all = new Set<string>();
  const sent = new Set<string>();
  for (const e of pool) {
    const key = cloudOperationKey(e);
    if (key === null) continue;
    all.add(key);
    if (shown.has(e.id)) sent.add(key);
  }
  return all.size - sent.size;
}
