import type { ForensicEvent, Severity } from "./stateTypes.js";
import { SEVERITY_RANK } from "./stateTypes.js";
import { resolveHost, type HostAliasIndex } from "./hostAlias.js";

// Per-host evidence for the scope ledger, folded in ONE streaming pass over the super-timeline so a
// multi-million-event case never materializes. Memory is bounded by host count, not event count.
//
// The `collected` vs `referenced` distinction is the point of this module. A host is COLLECTED when
// evidence originated from it (an event whose `asset` is that host). It is merely REFERENCED when it
// only appears inside another host's event — a logon source workstation, a canonical host target, a
// named network peer. A referenced-but-never-collected host is the classic scoping miss.
//
// The self-reference guard matters: canonicalEvent.legacyCanonical() sets `target` to the event's own
// asset when upgrading pre-schema events, so a target equal to `asset` says nothing about a second
// machine and must not manufacture a phantom host. Pure — no I/O.

export interface HostEvidence {
  collected: boolean;
  sources: Set<string>;
  firstSeen: string;
  lastSeen: string;
  eventCount: number;
  maxSeverity: Severity;
  findingIds: Set<string>;
  referencedBy: Set<string>; // collected hosts whose events named this one
}

export type HostEvidenceMap = Map<string, HostEvidence>;

function blank(): HostEvidence {
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

function entry(acc: HostEvidenceMap, host: string): HostEvidence {
  const existing = acc.get(host);
  if (existing) return existing;
  const fresh = blank();
  acc.set(host, fresh);
  return fresh;
}

// Every host name this event NAMES other than its own asset.
function referencedHosts(event: ForensicEvent): string[] {
  const c = event.canonical;
  if (!c) return [];
  const names = [
    c.session?.terminal,
    c.target?.kind === "host" ? c.target.name : undefined,
    c.network?.source?.hostname,
    c.network?.destination?.hostname,
  ];
  return names.filter((n): n is string => typeof n === "string" && n.trim() !== "");
}

export function accumulate(
  events: readonly ForensicEvent[],
  index: HostAliasIndex,
  acc: HostEvidenceMap,
): HostEvidenceMap {
  for (const event of events) {
    const owner = event.asset ? resolveHost(index, event.asset) : "";

    if (owner) {
      const host = entry(acc, owner);
      host.collected = true;
      host.eventCount += 1;
      for (const source of event.sources ?? []) host.sources.add(source);
      for (const findingId of event.relatedFindingIds) host.findingIds.add(findingId);
      // SEVERITY_RANK is lower-is-worse (Critical: 0), so a smaller rank replaces the current max.
      if (SEVERITY_RANK[event.severity] < SEVERITY_RANK[host.maxSeverity]) {
        host.maxSeverity = event.severity;
      }
      const ts = event.timestamp;
      if (ts && (!host.firstSeen || ts < host.firstSeen)) host.firstSeen = ts;
      if (ts && (!host.lastSeen || ts > host.lastSeen)) host.lastSeen = ts;
    }

    for (const raw of referencedHosts(event)) {
      const other = resolveHost(index, raw);
      if (!other || other === owner) continue; // self-target says nothing about a second machine
      const host = entry(acc, other);
      if (owner) host.referencedBy.add(owner);
    }
  }
  return acc;
}

// Fold the CURRENT forensic timeline's finding links over an aggregate built from the super-timeline.
//
// This exists because the two timelines carry different things. Deterministic importers append to
// the super-timeline, but synthesis writes `relatedFindingIds` onto `state.forensicTimeline` and the
// super-timeline is deliberately never synthesized. An aggregate built from the super-timeline alone
// therefore sees no findings at all, and every compromised host would derive as `unknown` or at best
// `suspected` — the ledger's single most important call, silently wrong.
//
// Counts are NOT re-added for a host already present: the super-timeline is the superset, so adding
// forensic rows again would double-count its events. A host that appears ONLY in the forensic
// timeline (an AI-synthesized event with no imported row behind it) is added, because evidence about
// it exists even if no import produced it.
export function overlayFindingLinks(
  events: readonly ForensicEvent[],
  index: HostAliasIndex,
  acc: HostEvidenceMap,
): HostEvidenceMap {
  for (const event of events) {
    if (!event.asset) continue;
    const host = resolveHost(index, event.asset);
    if (!host) continue;

    const existing = acc.get(host);
    if (!existing) {
      accumulate([event], index, acc);
      continue;
    }
    for (const findingId of event.relatedFindingIds) existing.findingIds.add(findingId);
    for (const source of event.sources ?? []) existing.sources.add(source);
    if (SEVERITY_RANK[event.severity] < SEVERITY_RANK[existing.maxSeverity]) {
      existing.maxSeverity = event.severity;
    }
  }
  return acc;
}

export async function aggregateHostEvidence(
  store: { eventBatches(caseId: string): AsyncGenerator<ForensicEvent[]> },
  caseId: string,
  index: HostAliasIndex,
): Promise<HostEvidenceMap> {
  const acc: HostEvidenceMap = new Map();
  for await (const batch of store.eventBatches(caseId)) accumulate(batch, index, acc);
  return acc;
}
