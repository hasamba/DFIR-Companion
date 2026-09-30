import type { ForensicEvent, Severity } from "./stateTypes.js";
import { SEVERITY_RANK } from "./stateTypes.js";
import { resolveHost, type HostAliasIndex } from "./hostAlias.js";
import { isIdentifyingClientName } from "./hostBinding.js";

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
//
// The scan is split in two (#1881). collectRawHostEvidence folds events keyed by the RAW spellings
// as stored — no alias resolution — and foldRawHostEvidence then applies the alias index. The raw
// result depends only on the super-timeline's content, so it can be cached per content version and
// re-folded whenever the aliases change (a fleet refresh, an analyst merge) without a rescan. The
// fold never mutates the raw collection and returns fresh sets, because callers mutate its output.

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
    // Workstation Name is commonly recorded as "-" or "*" when unpopulated (#1231, mirroring
    // hostBinding.ts's own NON_IDENTIFYING_CLIENT_NAMES guard) — a literal host named "-" is junk.
    c.session?.terminal && isIdentifyingClientName(c.session.terminal) ? c.session.terminal : undefined,
    c.target?.kind === "host" ? c.target.name : undefined,
    c.network?.source?.hostname,
    c.network?.destination?.hostname,
  ];
  return names.filter((n): n is string => typeof n === "string" && n.trim() !== "");
}

// Evidence from events whose `asset` is spelled exactly this way.
export interface RawAssetEvidence {
  eventCount: number;
  sources: Set<string>;
  findingIds: Set<string>;
  maxSeverity: Severity;
  firstSeen: string;
  lastSeen: string;
}

export interface RawHostEvidence {
  assets: Map<string, RawAssetEvidence>; // raw event.asset → its evidence
  references: Map<string, Set<string>>; // raw owner ("" when the event has no asset) → raw names
}

export function emptyRawHostEvidence(): RawHostEvidence {
  return { assets: new Map(), references: new Map() };
}

// SEVERITY_RANK is lower-is-worse (Critical: 0), so a smaller rank wins.
function worse(a: Severity, b: Severity): Severity {
  return SEVERITY_RANK[b] < SEVERITY_RANK[a] ? b : a;
}

// "" means "no timestamp yet" and never wins against a real one.
function earlier(a: string, b: string): string {
  return b && (!a || b < a) ? b : a;
}

function later(a: string, b: string): string {
  return b && (!a || b > a) ? b : a;
}

function rawAsset(raw: RawHostEvidence, asset: string): RawAssetEvidence {
  const existing = raw.assets.get(asset);
  if (existing) return existing;
  const fresh: RawAssetEvidence = {
    eventCount: 0,
    sources: new Set(),
    findingIds: new Set(),
    maxSeverity: "Info",
    firstSeen: "",
    lastSeen: "",
  };
  raw.assets.set(asset, fresh);
  return fresh;
}

// Fold a batch into `raw` (a new accumulator when absent). Call once per batch; the result is the
// same however the events are split.
export function collectRawHostEvidence(
  events: readonly ForensicEvent[],
  raw: RawHostEvidence = emptyRawHostEvidence(),
): RawHostEvidence {
  for (const event of events) {
    const owner = event.asset ?? "";
    if (owner) {
      const asset = rawAsset(raw, owner);
      asset.eventCount += 1;
      for (const source of event.sources ?? []) asset.sources.add(source);
      for (const findingId of event.relatedFindingIds) asset.findingIds.add(findingId);
      asset.maxSeverity = worse(asset.maxSeverity, event.severity);
      asset.firstSeen = earlier(asset.firstSeen, event.timestamp);
      asset.lastSeen = later(asset.lastSeen, event.timestamp);
    }

    const names = referencedHosts(event);
    if (names.length === 0) continue;
    const edges = raw.references.get(owner) ?? new Set<string>();
    for (const name of names) edges.add(name);
    raw.references.set(owner, edges);
  }
  return raw;
}

// Resolve the raw collection under `index`. Same result as accumulate() over every event, but the
// cost is bounded by distinct spellings and edges, not by event count.
export function foldRawHostEvidence(raw: RawHostEvidence, index: HostAliasIndex): HostEvidenceMap {
  const acc: HostEvidenceMap = new Map();

  for (const [asset, evidence] of raw.assets) {
    const owner = resolveHost(index, asset);
    if (!owner) continue;
    const host = entry(acc, owner);
    host.collected = true;
    host.eventCount += evidence.eventCount;
    for (const source of evidence.sources) host.sources.add(source);
    for (const findingId of evidence.findingIds) host.findingIds.add(findingId);
    host.maxSeverity = worse(host.maxSeverity, evidence.maxSeverity);
    host.firstSeen = earlier(host.firstSeen, evidence.firstSeen);
    host.lastSeen = later(host.lastSeen, evidence.lastSeen);
  }

  for (const [rawOwner, names] of raw.references) {
    const owner = rawOwner ? resolveHost(index, rawOwner) : "";
    for (const name of names) {
      const other = resolveHost(index, name);
      if (!other || other === owner) continue; // self-target says nothing about a second machine
      const host = entry(acc, other);
      if (owner) host.referencedBy.add(owner);
    }
  }
  return acc;
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
  const raw = emptyRawHostEvidence();
  for await (const batch of store.eventBatches(caseId)) collectRawHostEvidence(batch, raw);
  return foldRawHostEvidence(raw, index);
}
