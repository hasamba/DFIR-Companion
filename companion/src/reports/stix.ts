import { createHash } from "node:crypto";
import type { InvestigationState, IOC, IocEnrichment } from "../analysis/stateTypes.js";

// Build a STIX 2.1 bundle (https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html) from the
// case state — a deterministic transform, no AI, no new storage. The bundle is what every CTI
// ecosystem (OpenCTI, MISP, Anomali, ThreatConnect, …) natively ingests, so it makes a case
// portable to any TIP without vendor lock-in. Mirrors reports/markdown.ts / reports/csv.ts.
//
// Objects emitted:
//   identity      — the producing org (always) + the victim/customer org (when known)
//   report        — the case itself, object_refs pointing at everything in the bundle
//   indicator     — one per IOC that maps to a STIX observable, with a STIX `pattern`
//   attack-pattern— one per MITRE technique referenced (ATT&CK external_reference)
//   malware       — one per distinct family/classification tag from threat-intel enrichment
//   relationship  — indicator →indicates→ attack-pattern (from findings) and → malware
//
// Every object id is a deterministic UUIDv5 (namespace + case id + content), and every
// created/modified timestamp is the case's `updatedAt`, so re-exporting an unchanged case
// produces a byte-identical bundle (stable diffs, safe to re-share).

// ---------------------------------------------------------------------------
// STIX object shapes (the subset we emit). Each SDO/SRO carries the common
// required properties plus its type-specific fields under the index signature.
// ---------------------------------------------------------------------------
export interface StixObject {
  type: string;
  spec_version: "2.1";
  id: string;
  created: string;
  modified: string;
  [key: string]: unknown;
}

export interface StixBundle {
  type: "bundle";
  id: string;
  objects: StixObject[];
}

export interface StixExportOptions {
  organization?: string; // victim/customer org → an `identity` SDO (omitted when blank)
  producer?: string;     // creating org name (the investigating firm); default "DFIR Companion"
  incidentId?: string;   // optional human incident id, folded into the report name
}

// Fixed v5 namespace for DFIR Companion STIX ids. Any 16 bytes work as a namespace; this one is
// constant so ids stay reproducible across machines and releases.
const DFIR_STIX_NAMESPACE = "9b7c5e2a-1b9d-4f6c-8b2e-1a0f9c8d7e6b";

// RFC 4122 UUIDv5 (SHA-1, name-based) — deterministic id from the fixed namespace + a name.
function uuidv5(name: string): string {
  const ns = Buffer.from(DFIR_STIX_NAMESPACE.replace(/-/g, ""), "hex");
  const b = createHash("sha1").update(ns).update(name, "utf8").digest().subarray(0, 16);
  b[6] = (b[6] & 0x0f) | 0x50; // version 5
  b[8] = (b[8] & 0x3f) | 0x80; // RFC 4122 variant
  const hex = b.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

// Normalize any value to a STIX-compliant UTC timestamp; fall back when unparseable.
function stixTime(value: string | undefined, fallback: string): string {
  if (value) {
    const t = new Date(value);
    if (!Number.isNaN(t.getTime())) return t.toISOString();
  }
  return fallback;
}

// A technique ("T1059") or sub-technique ("T1059.001") id — anchored so a tactic id or free text
// never slips in. Mirrors attackLayer.ts.
const TECHNIQUE_RE = /^T\d{4}(?:\.\d{3})?$/;
function normalizeTechnique(id: string): string | null {
  const t = id.trim().toUpperCase();
  return TECHNIQUE_RE.test(t) ? t : null;
}

// Escape a value for embedding inside a STIX single-quoted pattern literal.
function escPattern(s: string): string {
  return s.replace(/\\/g, "\\\\").replace(/'/g, "\\'");
}

const HASH_ALGO: Record<number, string> = { 32: "MD5", 40: "SHA-1", 64: "SHA-256", 128: "SHA-512" };
function hashAlgo(value: string): string | null {
  return /^[a-f0-9]+$/i.test(value) ? HASH_ALGO[value.length] ?? null : null;
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const IPV4_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/;
const DOMAIN_RE = /^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$/;

// Best-effort observable for an `other`/unknown IOC: sniff email / url / ip / domain from the
// value, else give up (the IOC is omitted from the STIX indicators rather than emitting an
// invalid pattern — DFIR IOCs are overwhelmingly the typed kinds below, so this set is tiny).
function otherPattern(value: string): string | null {
  if (EMAIL_RE.test(value)) return `[email-addr:value = '${escPattern(value)}']`;
  if (/^https?:\/\//i.test(value)) return `[url:value = '${escPattern(value)}']`;
  if (IPV4_RE.test(value)) return `[ipv4-addr:value = '${escPattern(value)}']`;
  if (DOMAIN_RE.test(value)) return `[domain-name:value = '${escPattern(value)}']`;
  return null;
}

// Build the STIX pattern for an IOC, or null when it can't be expressed as a valid observable.
export function iocToStixPattern(ioc: IOC): string | null {
  const v = ioc.value.trim();
  if (!v) return null;
  switch (ioc.type) {
    case "ip":
      return `[${v.includes(":") ? "ipv6-addr" : "ipv4-addr"}:value = '${escPattern(v)}']`;
    case "domain":
      return `[domain-name:value = '${escPattern(v)}']`;
    case "url":
      return `[url:value = '${escPattern(v)}']`;
    case "hash": {
      const algo = hashAlgo(v);
      return algo ? `[file:hashes.'${algo}' = '${escPattern(v)}']` : null;
    }
    case "file":
      return `[file:name = '${escPattern(v)}']`;
    case "process":
      return `[process:command_line = '${escPattern(v)}']`;
    case "other":
    default:
      return otherPattern(v);
  }
}

// Worst-wins verdict across an IOC's threat-intel enrichments (malicious > suspicious > …).
const VERDICT_RANK: Record<IocEnrichment["verdict"], number> = {
  malicious: 3, suspicious: 2, harmless: 1, unknown: 0,
};
const INDICATOR_TYPE: Record<IocEnrichment["verdict"], string> = {
  malicious: "malicious-activity", suspicious: "anomalous-activity", harmless: "benign", unknown: "unknown",
};

function worstVerdict(ioc: IOC): IocEnrichment["verdict"] | null {
  let best: IocEnrichment["verdict"] | null = null;
  for (const e of ioc.enrichments ?? []) {
    if (best === null || VERDICT_RANK[e.verdict] > VERDICT_RANK[best]) best = e.verdict;
  }
  return best;
}

// Human-readable enrichment summary, e.g. "VirusTotal: malicious (52/73 detections) | ThreatFox: malicious".
function enrichmentSummary(ioc: IOC): string {
  return (ioc.enrichments ?? [])
    .map((e) => `${e.source}: ${e.verdict}${e.score ? ` (${e.score})` : ""}`)
    .join(" | ");
}

/**
 * Build a STIX 2.1 bundle from the investigation state. Pure — depends only on its arguments.
 * The state should already be scope/legitimate-filtered (the ReportWriter does this) so the
 * bundle matches the report.
 */
export function buildStixBundle(state: InvestigationState, opts: StixExportOptions = {}): StixBundle {
  const now = stixTime(state.updatedAt, new Date(0).toISOString());
  const objects: StixObject[] = [];

  // Stable id helper: UUIDv5 over (case id + a content key) so ids are reproducible and unique
  // across cases. The key encodes the object type and its distinguishing content.
  const idFor = (type: string, key: string): string => `${type}--${uuidv5(`${state.caseId}|${type}|${key}`)}`;

  const producerName = opts.producer?.trim() || "DFIR Companion";
  const producerId = idFor("identity", `producer|${producerName}`);

  // Build a STIX object with the common required props baked in. `owner` defaults to the producer
  // identity (created_by_ref); pass false for the producer identity itself (no self-reference).
  const sdo = (type: string, id: string, props: Record<string, unknown>, owner = true): StixObject => ({
    type, spec_version: "2.1", id, created: now, modified: now,
    ...(owner ? { created_by_ref: producerId } : {}),
    ...props,
  });

  // --- identities ---------------------------------------------------------
  objects.push(sdo("identity", producerId, {
    name: producerName, identity_class: "organization",
    description: "Producer of this STIX bundle (DFIR Companion case export).",
  }, false));

  const victimName = opts.organization?.trim();
  if (victimName) {
    objects.push(sdo("identity", idFor("identity", `victim|${victimName}`), {
      name: victimName, identity_class: "organization",
      description: "Victim / customer organization for this investigation.",
    }));
  }

  // --- attack-patterns (one per referenced MITRE technique) ---------------
  // Collect every technique referenced by the case, with the best name we have for it.
  const techniqueNames = new Map<string, string>();
  const noteTechnique = (raw: string, name?: string): void => {
    const id = normalizeTechnique(raw);
    if (!id) return;
    const existing = techniqueNames.get(id);
    // Fill the name from the techniques list; never let a blank/id-only entry clobber a real name.
    if (!existing || (name?.trim() && existing === id)) techniqueNames.set(id, name?.trim() || existing || id);
  };
  for (const t of state.mitreTechniques) noteTechnique(t.id, t.name);
  for (const f of state.findings) for (const t of f.mitreTechniques) noteTechnique(t);
  for (const e of state.forensicTimeline) for (const t of e.mitreTechniques) noteTechnique(t);

  const attackPatternId = new Map<string, string>(); // techniqueId → stix id
  for (const techId of [...techniqueNames.keys()].sort()) {
    const id = idFor("attack-pattern", techId);
    attackPatternId.set(techId, id);
    objects.push(sdo("attack-pattern", id, {
      name: techniqueNames.get(techId) || techId,
      external_references: [{ source_name: "mitre-attack", external_id: techId }],
    }));
  }

  // --- indicators (one per mappable IOC) ----------------------------------
  const indicatorId = new Map<string, string>(); // ioc.id → stix id
  for (const ioc of [...state.iocs].sort((a, b) => a.value.localeCompare(b.value))) {
    const pattern = iocToStixPattern(ioc);
    if (!pattern) continue;
    const id = idFor("indicator", `${ioc.type}|${ioc.value}`);
    indicatorId.set(ioc.id, id);
    const verdict = worstVerdict(ioc);
    const summary = enrichmentSummary(ioc);
    objects.push(sdo("indicator", id, {
      name: ioc.value,
      pattern, pattern_type: "stix",
      valid_from: stixTime(ioc.firstSeen, now),
      indicator_types: [INDICATOR_TYPE[verdict ?? "unknown"]],
      description: summary
        ? `Threat-intel verdict: ${verdict} — ${summary}`
        : "Indicator observed during the investigation (no threat-intel enrichment).",
    }));
  }

  // --- malware (one per distinct enrichment family/classification tag) -----
  // Threat-intel tags ARE family/classification labels (see IocEnrichment.tags). Group by a
  // case-insensitive key, keeping the first-seen casing, and remember which IOCs carried each
  // so we can wire indicator →indicates→ malware edges.
  const malwareIocs = new Map<string, Set<string>>(); // tagKey → ioc ids
  const malwareName = new Map<string, string>();       // tagKey → display name
  for (const ioc of state.iocs) {
    for (const e of ioc.enrichments ?? []) {
      for (const tag of e.tags ?? []) {
        const name = tag.trim();
        if (!name) continue;
        const key = name.toLowerCase();
        if (!malwareName.has(key)) malwareName.set(key, name);
        let set = malwareIocs.get(key);
        if (!set) malwareIocs.set(key, (set = new Set()));
        set.add(ioc.id);
      }
    }
  }
  const malwareId = new Map<string, string>(); // tagKey → stix id
  for (const key of [...malwareName.keys()].sort()) {
    const id = idFor("malware", key);
    malwareId.set(key, id);
    objects.push(sdo("malware", id, {
      name: malwareName.get(key)!, is_family: true, malware_types: ["unknown"],
    }));
  }

  // --- relationships ------------------------------------------------------
  // indicator →indicates→ attack-pattern, derived from findings (an IOC + a technique on the same
  // finding implies the indicator evidences that technique). Deduped by (source, target).
  const relSeen = new Set<string>();
  const pushRel = (sourceRef: string, targetRef: string): void => {
    const dedup = `${sourceRef}->${targetRef}`;
    if (relSeen.has(dedup)) return;
    relSeen.add(dedup);
    objects.push(sdo("relationship", idFor("relationship", `indicates|${dedup}`), {
      relationship_type: "indicates", source_ref: sourceRef, target_ref: targetRef,
    }));
  };
  for (const f of state.findings) {
    const indicators = f.relatedIocs.map((iid) => indicatorId.get(iid)).filter((x): x is string => Boolean(x));
    const patterns = f.mitreTechniques
      .map((t) => normalizeTechnique(t))
      .map((t) => (t ? attackPatternId.get(t) : undefined))
      .filter((x): x is string => Boolean(x));
    for (const src of indicators) for (const tgt of patterns) pushRel(src, tgt);
  }
  // indicator →indicates→ malware, from shared enrichment tags.
  for (const key of [...malwareName.keys()].sort()) {
    const mid = malwareId.get(key)!;
    for (const iocId of [...(malwareIocs.get(key) ?? [])].sort()) {
      const src = indicatorId.get(iocId);
      if (src) pushRel(src, mid);
    }
  }

  // --- report (references everything created above) -----------------------
  const reportName = opts.incidentId?.trim()
    ? `Incident ${opts.incidentId.trim()} — ${state.caseId}`
    : `DFIR Companion — ${state.caseId}`;
  objects.push(sdo("report", idFor("report", "case"), {
    name: reportName,
    description: state.lastSummary?.trim() || state.attackerPath?.trim() ||
      `STIX export of DFIR Companion case ${state.caseId}.`,
    report_types: ["threat-report"], published: now,
    // object_refs is required and must be non-empty — the producer identity guarantees that.
    object_refs: objects.map((o) => o.id),
  }));

  return { type: "bundle", id: `bundle--${uuidv5(`${state.caseId}|bundle`)}`, objects };
}
