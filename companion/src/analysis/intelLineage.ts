// Intel lineage (#933 item 18): what one threat-intel hit says about WHERE its claim comes from, and
// how many ORIGINS stand behind an IOC's verdict — as opposed to how many providers answered.
//
// "Three feeds agree" when all three copied one abuse.ch report is the analytic failure this exists to
// end. A provider is not an origin: MISP, OpenCTI and YETI RELAY records other parties created (their
// default feeds are abuse.ch pulls); VirusTotal and AbuseIPDB AGGREGATE other parties' answers into one;
// abuse.ch (via Hunting.ch) and CrowdStrike assert FIRST-PARTY; Hashlookup relays datasets. So the count that matters is distinct
// origin FAMILIES with a recorded name — and a hit whose record names nobody is "not recorded", which
// counts as NO origin. It never silently becomes a second confirmation.
//
// Two named origins are two names. Nothing here demonstrates that they observed independently, and the
// words never say "independent" — only a Medium+ event in this case (iocAnchors.iocHasBehavioralEvent)
// upgrades a hit, and it is described as what it is. PURE: derived on read, never persisted.

export type OriginKind = "first-party" | "aggregate" | "relay";

export interface IntelLineage {
  kind: OriginKind;
  origins: string[]; // the creator names the record carries (cleaned); [] = not recorded
  inferred: boolean; // true when read from the legacy provider table, not from the record
}

export interface IntelOrigins {
  hits: number; // malicious/suspicious records
  origins: string[]; // distinct recorded origin families, first-seen order
  unrecorded: number; // hits whose record names nobody — never counted
  folded: number; // hits whose family was already counted (MISP-by-abuse.ch beside ThreatFox)
  unrecordedVia: string[]; // provider labels of the unrecorded hits, for the words
  hitLabels: string[]; // provider/source labels of every hit, first-seen order
}

// Names that are ONE publisher. Built-in and exact (lowercased) — no fuzzy match, so a relay-controlled
// creator name can fold INTO a family (lowering the count) but never mint a second one by spelling.
const ORIGIN_FAMILIES: Record<string, string> = {
  "abuse.ch": "abuse.ch",
  abusech: "abuse.ch",
  threatfox: "abuse.ch",
  urlhaus: "abuse.ch",
  malwarebazaar: "abuse.ch",
  yaraify: "abuse.ch",
  "feodo tracker": "abuse.ch",
  feodotracker: "abuse.ch",
  "ssl blacklist": "abuse.ch",
  sslbl: "abuse.ch",
  "hunting.ch": "abuse.ch",
  virustotal: "VirusTotal",
  vt: "VirusTotal",
  abuseipdb: "AbuseIPDB",
  crowdstrike: "CrowdStrike",
  "crowdstrike intel": "CrowdStrike",
  "crowdstrike malquery": "CrowdStrike",
  "alienvault otx": "AlienVault OTX",
  alienvault: "AlienVault OTX",
  otx: "AlienVault OTX",
  circl: "CIRCL",
  "circl.lu": "CIRCL",
};

// Pre-change records carry no lineage. What the adapter name alone tells us — marked inferred. The relay
// platforms are absent on purpose: they never recorded a creator, so their legacy hits are "not recorded".
const LEGACY_PROVIDER_LINEAGE: Record<string, IntelLineage> = {
  virustotal: { kind: "aggregate", origins: ["VirusTotal"], inferred: true },
  abuseipdb: { kind: "aggregate", origins: ["AbuseIPDB"], inferred: true },
  "hunting.ch": { kind: "first-party", origins: ["abuse.ch"], inferred: true },
  malwarebazaar: { kind: "first-party", origins: ["abuse.ch"], inferred: true },
  threatfox: { kind: "first-party", origins: ["abuse.ch"], inferred: true },
  urlhaus: { kind: "first-party", origins: ["abuse.ch"], inferred: true },
  yaraify: { kind: "first-party", origins: ["abuse.ch"], inferred: true },
  crowdstrike: { kind: "first-party", origins: ["CrowdStrike"], inferred: true },
  "crowdstrike intel": { kind: "first-party", origins: ["CrowdStrike"], inferred: true },
  "crowdstrike malquery": { kind: "first-party", origins: ["CrowdStrike"], inferred: true },
  rockyraccoon: { kind: "first-party", origins: ["RockyRaccoon"], inferred: true },
  hashlookup: { kind: "relay", origins: [], inferred: true },
  misp: { kind: "relay", origins: [], inferred: true },
  opencti: { kind: "relay", origins: [], inferred: true },
  yeti: { kind: "relay", origins: [], inferred: true },
};

export const MAX_ORIGINS_PER_RECORD = 5;
const MAX_ORIGIN_NAME = 80;

// A creator name is text from a remote system: control characters out, whitespace collapsed, bounded.
export function cleanOriginName(raw: unknown): string {
  if (typeof raw !== "string") return "";
  return raw
    .replace(/[\u0000-\u001f\u007f]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, MAX_ORIGIN_NAME);
}

// Distinct cleaned names, bounded, plus how many were cut — the adapter's helper for `origins`.
export function boundOrigins(names: readonly unknown[]): { origins: string[]; moreOrigins?: number } {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const n of names) {
    const c = cleanOriginName(n);
    if (!c || seen.has(c.toLowerCase())) continue;
    seen.add(c.toLowerCase());
    out.push(c);
  }
  const origins = out.slice(0, MAX_ORIGINS_PER_RECORD);
  const cut = out.length - origins.length;
  return cut > 0 ? { origins, moreOrigins: cut } : { origins };
}

export function originFamily(name: string): string {
  const key = name.trim().toLowerCase();
  return ORIGIN_FAMILIES[key] ?? key;
}

// The slice of a record this module reads — `IocEnrichment` satisfies it, and so does the loose
// shape iocAnchors.classifyVerdict accepts.
export interface LineageInput {
  verdict?: string;
  source?: string;
  provider?: string;
  originKind?: OriginKind;
  origins?: string[];
}

// The lineage ONE record carries. A record that states its kind is read as stated (its `origins` may still
// be empty — a relay naming nobody). A legacy record falls back to the adapter table; an adapter the
// table does not know is "not recorded" (conservative: it can only lower the count).
export function lineageOf(e: LineageInput): IntelLineage | undefined {
  if (e.originKind) {
    return {
      kind: e.originKind,
      origins: (e.origins ?? []).map(cleanOriginName).filter(Boolean),
      inferred: false,
    };
  }
  const key = (e.provider || e.source || "").trim().toLowerCase();
  return LEGACY_PROVIDER_LINEAGE[key];
}

function isHit(e: LineageInput): boolean {
  return e.verdict === "malicious" || e.verdict === "suspicious";
}

// Count origins across an IOC's malicious/suspicious hits. Pure; does not touch its input.
export function intelOrigins(enrichments: readonly LineageInput[] | undefined): IntelOrigins {
  const out: IntelOrigins = {
    hits: 0,
    origins: [],
    unrecorded: 0,
    folded: 0,
    unrecordedVia: [],
    hitLabels: [],
  };
  const families = new Set<string>();
  for (const e of enrichments ?? []) {
    if (!isHit(e)) continue;
    out.hits += 1;
    const label = (e.source || e.provider || "?").trim();
    if (!out.hitLabels.includes(label)) out.hitLabels.push(label);
    const lin = lineageOf(e);
    const named = lin?.origins ?? [];
    if (!named.length) {
      out.unrecorded += 1;
      if (!out.unrecordedVia.includes(label)) out.unrecordedVia.push(label);
      continue;
    }
    let added = false;
    for (const n of named) {
      const fam = originFamily(n);
      if (families.has(fam)) continue;
      families.add(fam);
      out.origins.push(displayFamily(fam, n));
      added = true;
    }
    if (!added) out.folded += 1;
  }
  return out;
}

// A known family shows under its canonical spelling; anything else under the name the record carried.
function displayFamily(fam: string, raw: string): string {
  return Object.values(ORIGIN_FAMILIES).includes(fam) ? fam : raw.trim();
}

export type IntelClass = "corroborated" | "multi-origin" | "lone-intel";

// The words for the IOC risk factor (dashboard tooltip, Markdown IOC table, CSV) — one line, and the
// only place "corroborated" is used is beside the local event that earned it.
export function originsFactor(o: IntelOrigins, cls: IntelClass): string {
  const list = o.origins.join(", ");
  if (cls === "corroborated") {
    const who = o.origins.length
      ? `${o.origins.length} named origin${o.origins.length === 1 ? "" : "s"}: ${list}`
      : "lineage not recorded";
    return `intel verdict (${who}) carried by a Medium+ event in this case`;
  }
  if (cls === "multi-origin") {
    return `intel verdict from ${o.origins.length} named origins (${list}) — independence not established`;
  }
  const notCounted = o.unrecorded
    ? `${o.unrecorded} hit${o.unrecorded === 1 ? "" : "s"} with lineage not recorded (${o.unrecordedVia.join(", ")}) — not counted as an origin; re-check with force to record the creator`
    : "";
  if (!o.origins.length) return notCounted;
  const hits =
    o.hits - o.unrecorded > 1 ? `${list} — ${o.hits - o.unrecorded} hits: ${o.hitLabels.join(", ")}` : list;
  return `single intel origin (${hits}), not seen in a Medium+ event in this case (unverified lead)${
    notCounted ? `; ${notCounted}` : ""
  }`;
}

// The bracketed tag on a prompt verdict line — short, and it says what the class rests on.
export function originsTag(o: IntelOrigins, cls: IntelClass): string {
  if (cls === "corroborated") return "[corroborated: carried by a Medium+ event in this case]";
  if (cls === "multi-origin")
    return `[multi-origin: ${o.origins.length} named origins — ${o.origins.join(", ")}; independence not established]`;
  if (!o.origins.length) return "[lone-intel: lineage not recorded]";
  const counted = o.hits - o.unrecorded;
  return counted > 1 ? `[lone-intel: ${counted} hits, 1 origin]` : "[lone-intel: 1 named origin]";
}
