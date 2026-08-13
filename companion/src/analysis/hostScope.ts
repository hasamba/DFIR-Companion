import { createHash } from "node:crypto";
import type { IrisTactic } from "./mitreTactics.js";
import {
  canonicalHostName,
  resolveHost,
  type FleetClient,
  type HostAliasIndex,
  type NearDuplicate,
} from "./hostAlias.js";
import type { HostEvidence, HostEvidenceMap } from "./hostScopeAggregate.js";
import { evaluateEligibility, type Eligibility } from "./hostScopeEligibility.js";
import type { HostScopeDecision, HostScopeStatus } from "./hostScopeStore.js";

// The host scope ledger: what is affected, what was never looked at, and what an analyst has
// asserted. Derived on read from evidence the case already holds — nothing here is persisted except
// the analyst decisions handed in. Pure — no I/O.
//
// Two rules carry the feature's integrity:
//   1. Derivation may only ESCALATE (unknown → suspected → confirmed). Only an analyst reaches
//      `cleared` / `out-of-scope`.
//   2. A decision always wins over derivation, but never silently: when the evidence behind it
//      changes, the row is flagged `stale` and the decision STANDS. Auto-reverting would retract a
//      claim a named analyst signed.

export type HostPresence = "collected" | "referenced" | "enrolled-only";

export interface HostScopeRow {
  name: string;
  presence: HostPresence;
  derivedStatus: HostScopeStatus;
  effectiveStatus: HostScopeStatus;
  decision?: HostScopeDecision;
  stale?: string;
  eligibility: Eligibility;
  sources: string[];
  firstSeen: string;
  lastSeen: string;
  eventCount: number;
  referencedBy: string[];
  gap?: string;
  fingerprint: string; // current evidence fingerprint — a new decision records this as its basis
}

export interface HostScopeLedger {
  hosts: HostScopeRow[];
  counts: Record<HostScopeStatus, number>;
  referencedNeverCollected: number;
  fleet: { enrolled: number; collected: number; snapshotAt: string } | null;
  nearDuplicates: NearDuplicate[];
}

export interface BuildHostScopeInput {
  evidence: HostEvidenceMap;
  decisions: readonly HostScopeDecision[];
  window: { start: string | null; end: string | null };
  caseTactics: readonly IrisTactic[];
  clients: readonly FleetClient[];
  fleetSnapshotAt: string;
  nearDuplicates: NearDuplicate[];
  // The same index the evidence was aggregated through. Omitted, every name is read literally —
  // which is only safe when nothing has been merged, so callers holding an index must pass it.
  aliasIndex?: HostAliasIndex;
}

function emptyEvidence(): HostEvidence {
  return {
    collected: false,
    sources: new Set(),
    firstSeen: "",
    lastSeen: "",
    eventCount: 0,
    maxSeverity: "Info",
    findingIds: new Set(),
    referencedBy: new Set(),
  };
}

// What a clearance was granted against. Any change here means the assertion deserves a fresh look.
export function evidenceFingerprint(
  evidence: HostEvidence,
  window: { start: string | null; end: string | null },
  caseTactics: readonly string[],
): string {
  const material = JSON.stringify([
    evidence.eventCount,
    evidence.lastSeen,
    [...evidence.sources].sort(),
    [...caseTactics].sort(),
    window.start,
    window.end,
  ]);
  return createHash("sha256").update(material).digest("hex").slice(0, 32);
}

// The fingerprint of a host the case holds no evidence for. A decision can legitimately be made on
// such a host ("decommissioned before the incident"), and it must record the same basis the ledger
// will compute for it — otherwise every first decision on an evidence-less host is born stale.
export function emptyHostFingerprint(
  window: { start: string | null; end: string | null },
  caseTactics: readonly string[],
): string {
  return evidenceFingerprint(emptyEvidence(), window, caseTactics);
}

function deriveStatus(evidence: HostEvidence): HostScopeStatus {
  if (evidence.findingIds.size > 0) return "confirmed";
  if (evidence.maxSeverity === "High" || evidence.maxSeverity === "Critical") return "suspected";
  return "unknown";
}

// The statuses an analyst ASSERTS over the evidence. Both are signed, carry a required reason, and
// are the only ones staleness can apply to — `unknown` is a retraction, not a claim.
const ASSERTING_STATUSES: readonly HostScopeStatus[] = ["cleared", "out-of-scope"];

// A decision to `unknown` is REOPEN — "return this host to automatic" — not an assertion that the
// host is unremarkable. Honouring it literally would let one click hide a Critical finding behind a
// stale flag nobody reads, which is the exact inversion of the escalate-only rule: derivation may
// raise concern, and no analyst action may lower it below what the evidence shows. Clearing and
// out-of-scope remain deliberate assertions and DO stand over derivation — those are signed, carry
// a required reason, and get flagged stale when the evidence moves under them.
function effectiveStatusOf(
  decision: HostScopeDecision | undefined,
  derivedStatus: HostScopeStatus,
): HostScopeStatus {
  if (!decision) return derivedStatus;
  if (decision.to === "unknown") return derivedStatus;
  return decision.to;
}

function presenceOf(evidence: HostEvidence, enrolled: boolean): HostPresence {
  if (evidence.collected) return "collected";
  if (evidence.referencedBy.size > 0) return "referenced";
  return enrolled ? "enrolled-only" : "referenced";
}

function gapOf(row: {
  presence: HostPresence;
  derivedStatus: HostScopeStatus;
  eligibility: Eligibility;
  referencedBy: string[];
}): string | undefined {
  if (row.presence === "referenced") {
    const by = row.referencedBy.length;
    return `named by ${by} collected host${by === 1 ? "" : "s"} but never collected`;
  }
  if (row.presence === "enrolled-only") return "enrolled in the fleet but no evidence collected";
  const sourceBreadth = row.eligibility.criteria.find((c) => c.id === "source-breadth");
  if (row.derivedStatus === "suspected" && sourceBreadth && !sourceBreadth.met) {
    return "suspected, but no host-level evidence has been collected";
  }
  const window = row.eligibility.criteria.find((c) => c.id === "window-coverage");
  if (window && !window.met) return `partial window coverage — ${window.detail}`;
  return undefined;
}

export function buildHostScopeLedger(input: BuildHostScopeInput): HostScopeLedger {
  const { evidence, decisions, window, caseTactics, clients, fleetSnapshotAt, nearDuplicates } = input;

  // Evidence was keyed through the alias index, so the fleet roster and the decision log must be
  // read through it too. Reading them literally splits a merged host into two rows — one carrying
  // the evidence, one enrolled-only and `unknown` — which inflates the not-yet-assessed count,
  // drops the host out of the fleet-collected figure, and detaches any clearance recorded against
  // the pre-merge spelling. Every one of those lands in the report as a false claim.
  const canonical = (raw: string): string =>
    input.aliasIndex ? resolveHost(input.aliasIndex, raw) : canonicalHostName(raw);

  const enrolledNames = new Set(clients.map((c) => canonical(c.fqdn || c.hostname || "")).filter(Boolean));
  // Latest decision per host wins; the full log stays in the store for the report's appendix.
  const latest = new Map<string, HostScopeDecision>();
  for (const decision of [...decisions].sort((a, b) => a.at.localeCompare(b.at))) {
    latest.set(canonical(decision.host), decision);
  }

  // Decision hosts join the roll call even when the case holds no evidence for them: an analyst who
  // marks a host out-of-scope must still see that row, not watch it disappear.
  const names = new Set<string>([...evidence.keys(), ...enrolledNames, ...latest.keys()]);

  const hosts: HostScopeRow[] = [];
  for (const name of [...names].sort()) {
    const ev = evidence.get(name) ?? emptyEvidence();
    const eligibility = evaluateEligibility({ evidence: ev, window, caseTactics });
    const derivedStatus = deriveStatus(ev);
    const decision = latest.get(name);
    const presence = presenceOf(ev, enrolledNames.has(name));
    const referencedBy = [...ev.referencedBy].sort();
    const fingerprint = evidenceFingerprint(ev, window, caseTactics);

    // Staleness applies ONLY to a decision that asserts something over the evidence. A reopen
    // (`unknown`) retracts the assertion and hands the host back to derivation, so there is nothing
    // left to go stale — flagging it anyway put "clearance needs review" at the top of the gap list
    // for a clearance that no longer exists, which is a worse lie than the one staleness prevents.
    let stale: string | undefined;
    if (decision && ASSERTING_STATUSES.includes(decision.to)) {
      if (!decision.basis.evidenceFingerprint) {
        stale = "the decision recorded no evidence basis";
      } else if (decision.basis.evidenceFingerprint !== fingerprint) {
        stale = "evidence for this host changed since the decision was recorded";
      } else if (decision.to === "cleared" && derivedStatus === "confirmed") {
        stale = "a finding now references this host";
      }
    }

    const row: HostScopeRow = {
      name,
      presence,
      derivedStatus,
      effectiveStatus: effectiveStatusOf(decision, derivedStatus),
      ...(decision ? { decision } : {}),
      ...(stale ? { stale } : {}),
      eligibility,
      sources: [...ev.sources].sort(),
      firstSeen: ev.firstSeen,
      lastSeen: ev.lastSeen,
      eventCount: ev.eventCount,
      referencedBy,
      fingerprint,
    };
    const gap = gapOf({ presence, derivedStatus, eligibility, referencedBy });
    if (gap) row.gap = gap;
    hosts.push(row);
  }

  const counts: Record<HostScopeStatus, number> = {
    unknown: 0,
    suspected: 0,
    confirmed: 0,
    cleared: 0,
    "out-of-scope": 0,
  };
  for (const host of hosts) counts[host.effectiveStatus] += 1;

  return {
    hosts,
    counts,
    referencedNeverCollected: hosts.filter((h) => h.presence === "referenced").length,
    fleet: fleetSnapshotAt
      ? {
          enrolled: enrolledNames.size,
          collected: hosts.filter((h) => h.presence === "collected" && enrolledNames.has(h.name)).length,
          snapshotAt: fleetSnapshotAt,
        }
      : null,
    nearDuplicates,
  };
}
