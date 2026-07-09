// IOC provenance CHAIN (#247) — for one IOC, the full story: which event(s) it was seen in, which
// enrichment lookups ran against it, and which findings cite it. Distinct from iocProvenance.ts
// (which only classes detection-linked vs telemetry-only) and iocCorroboration.ts (which only lists
// distinct TOOL names) — this assembles the actual timestamped steps. Pure, derived on read, like
// those siblings — never mutates state.
//
// IMPORTANT CAVEAT: not every importer records which specific event produced an IOC (addIoc() takes
// only a type+value in most of the ~20 importers), so the "extraction" leg falls back to APPROXIMATE
// — the same indexed exact-token match iocCorroboration/iocProvenance already use — whenever an IOC
// has no (or no resolvable) IOC.extractedFrom link. 5 priority importers (SIEM/EVTX, Security Onion,
// Network, Combined-log, Velociraptor) DO populate extractedFrom, so buildIocProvenanceChains prefers
// that authoritative link when present. Check `extractionAuthoritative` on the returned chain to see
// which path applied for a given IOC. Enrichment
// lookups ARE authoritative (IOC.enrichments already carries a real fetchedAt per hit). Findings ARE
// authoritative (Finding.relatedIocs is a real reference). There is no data model for "which playbook
// task referenced this IOC" (playbook tasks don't carry IOC ids) — that leg is intentionally omitted
// rather than faked as an always-empty field; playbook linkage would need new state, tracked in #247.

import type { Finding, ForensicEvent, IOC } from "./stateTypes.js";

const TOKEN_RE = /[\w.@:/\\-]{3,}/g;
const MAX_EXTRACTION_EVENTS = 25;

export interface ProvenanceExtractionEvent {
  eventId: string;
  timestamp: string;
  description: string;
  severity: ForensicEvent["severity"];
  sources?: string[];
  artifactName?: string;   // the specific artifact/source-tool identifier (e.g. "Windows.Network.DNS"),
                           // finer-grained than `sources` (e.g. "Velociraptor") — set by importers that know it
}

export interface ProvenanceEnrichmentLookup {
  source: string;
  verdict: string;
  score?: string;
  fetchedAt: string;
  link?: string;
}

export interface ProvenanceFindingRef {
  findingId: string;
  title: string;
  severity: Finding["severity"];
  status: Finding["status"];
  firstSeen: string;
}

export interface IocProvenanceChain {
  iocId: string;
  value: string;
  type: IOC["type"];
  extraction: ProvenanceExtractionEvent[];
  extractionTruncated: number;   // count of matching events dropped past MAX_EXTRACTION_EVENTS, 0 if none
  extractionAuthoritative: boolean; // true when extraction came from IOC.extractedFrom (a real link),
                                     // false when it's the value-match guess below
  enrichment: ProvenanceEnrichmentLookup[];
  findings: ProvenanceFindingRef[];
}

// Build the chain for every IOC in one pass: index events + findings ONCE (O(events + findings)),
// then look each IOC up (O(iocs)) — same shape as deriveIocSources, so it scales to a real case's
// IOC count without re-scanning the timeline per IOC.
export function buildIocProvenanceChains(
  iocs: readonly IOC[],
  events: readonly ForensicEvent[],
  findings: readonly Finding[],
): Record<string, IocProvenanceChain> {
  const out: Record<string, IocProvenanceChain> = {};
  if (iocs.length === 0) return out;

  const eventIndex = new Map<string, ForensicEvent[]>();
  const addEvent = (raw: string | undefined, e: ForensicEvent): void => {
    if (!raw) return;
    const key = raw.trim().toLowerCase();
    if (key.length < 3) return;
    let list = eventIndex.get(key);
    if (!list) { list = []; eventIndex.set(key, list); }
    list.push(e);
  };
  for (const e of events) {
    addEvent(e.sha256, e); addEvent(e.md5, e); addEvent(e.srcIp, e); addEvent(e.dstIp, e); addEvent(e.path, e);
    const tokens = (e.description || "").match(TOKEN_RE);
    if (tokens) for (const t of tokens) addEvent(t, e);
  }

  const eventById = new Map<string, ForensicEvent>();
  for (const e of events) eventById.set(e.id, e);

  const findingIndex = new Map<string, Finding[]>();
  for (const f of findings) {
    for (const iocId of f.relatedIocs || []) {
      let list = findingIndex.get(iocId);
      if (!list) { list = []; findingIndex.set(iocId, list); }
      list.push(f);
    }
  }

  for (const ioc of iocs) {
    const authoritativeIds = (ioc.extractedFrom ?? []).filter((id) => eventById.has(id));
    const extractionAuthoritative = authoritativeIds.length > 0;
    let dedup: ForensicEvent[];
    if (extractionAuthoritative) {
      const seen = new Set<string>();
      dedup = [];
      for (const id of authoritativeIds) {
        if (!seen.has(id)) { seen.add(id); dedup.push(eventById.get(id)!); }
      }
    } else {
      const key = ioc.value.trim().toLowerCase();
      const matched = key.length >= 3 ? (eventIndex.get(key) ?? []) : [];
      const seenIds = new Set<string>();
      dedup = [];
      for (const e of matched) { if (!seenIds.has(e.id)) { seenIds.add(e.id); dedup.push(e); } }
    }
    dedup.sort((a, b) => a.timestamp.localeCompare(b.timestamp));
    const extractionTruncated = Math.max(0, dedup.length - MAX_EXTRACTION_EVENTS);
    const extraction: ProvenanceExtractionEvent[] = dedup.slice(0, MAX_EXTRACTION_EVENTS).map((e) => ({
      eventId: e.id, timestamp: e.timestamp, description: e.description, severity: e.severity,
      sources: e.sources && e.sources.length ? e.sources : undefined,
      artifactName: e.artifactName,
    }));

    const enrichment: ProvenanceEnrichmentLookup[] = (ioc.enrichments ?? [])
      .slice()
      .sort((a, b) => a.fetchedAt.localeCompare(b.fetchedAt))
      .map((en) => ({ source: en.source, verdict: en.verdict, score: en.score, fetchedAt: en.fetchedAt, link: en.link }));

    const citing: ProvenanceFindingRef[] = (findingIndex.get(ioc.id) ?? [])
      .slice()
      .sort((a, b) => a.firstSeen.localeCompare(b.firstSeen))
      .map((f) => ({ findingId: f.id, title: f.title, severity: f.severity, status: f.status, firstSeen: f.firstSeen }));

    out[ioc.id] = {
      iocId: ioc.id, value: ioc.value, type: ioc.type, extraction, extractionTruncated,
      extractionAuthoritative, enrichment, findings: citing,
    };
  }
  return out;
}
