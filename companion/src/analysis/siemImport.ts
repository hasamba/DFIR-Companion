// Deterministic importer for SIEM / EDR JSON exports — the second JSON ingest path besides THOR. Where THOR
// has a fixed JSON-Lines schema, SIEM/EDR exports vary wildly (Elastic/Kibana, Splunk, an EDR console, a
// raw winlogbeat dump…), so this module:
//
//   1. UNWRAPS the common container envelopes to a flat array of event records: Elastic/Kibana table export
//      ({ data: [{ _source }] }), an Elasticsearch search response ({ hits: { hits: [{ _source }] } }), a
//      plain JSON array, NDJSON (one JSON object per line, optionally _source-wrapped), or {
//      events|records|results|logs: [...] }.
//   2. MAPS each record to a forensic event DETERMINISTICALLY (no AI call). Windows Event Log + Sysmon
//      records (the dominant SIEM data, and the attached example file) get a rich per-EID mapping (label,
//      derived severity, MITRE, structured IOC/asset extraction). Any OTHER SIEM/EDR record falls back to
//      field auto-detection (timestamp / host / message / severity), so a CrowdStrike / Defender /
//      SentinelOne export still produces dated events + IOCs.
//   3. AGGREGATES repetitive identical events into one counted row (like THOR / logAggregate) and caps the
//      total, so an 11k-event export does not flood the timeline. Synthesis + the high-severity backfill
//      still cover everything.
//
// Windows logs carry no maliciousness score (`level` is "Information" for almost everything), so severity
// is DERIVED from the event type (WIN_EVENTS / SYSMON_EVENTS), with a conservative bump for LOLBin /
// suspicious command lines and LSASS access.

import { worstSeverity as worst, type ForensicEvent, type Severity, type TlpMarking } from "./stateTypes.js";
import { MONTHS, parseBsdTime } from "./bsdTime.js";
import { isInternalIpv4 } from "./internalIp.js";
import { winRoleBlocks } from "./winAccountRoles.js";
import {
  createCanonicalEvent,
  stampSourceArtifactHash,
  type CanonicalEventEnvelope,
} from "./canonicalEvent.js";
import { toUtcIso } from "./timeUtc.js";
import { reconTechniques } from "./reconTechniques.js";
import { tradecraftSignal, scriptBlockSignal, STRONG_CMD, SUSP_CMD } from "./tradecraftRules.js";
import { decodeDefenderEvent, defenderDescription } from "./defenderEvents.js";
import { commandCandidates } from "./commandNormalize.js";
import { secretSpillSignal } from "./secretSpillRules.js";
import { streamOverlay } from "./ntfsStreams.js";
import { boundDnsVariants } from "./dnsRecord.js";
import { runWindowsDnsConnJoin } from "./siemDnsConnJoin.js";
import { WIN_EVENTS, channelTable, windowsDnsOverlay, type WinEventDef } from "./winEventTables.js";
export { WIN_EVENTS, type WinEventDef };
import { processGuid, processOverlay } from "./processAccess.js";
import { aggregateEvents, maxEventsDefault } from "./eventAggregate.js";
import { evtxRecordIdentity } from "./evtxRecordId.js";
import { LOLBINS, NOISY_LOLBINS, SUSP_PATH } from "./winProcessBaseline.js";
import { extractDomains, TEXT_DOMAIN_SKIP_RE, TEXT_FILE_EXT_RE, hasPlausibleTld } from "./textDomains.js";
import { trimSentencePunctuation } from "../ingest/textUriTrim.js";

// Re-exported for the sibling importers, which already source their shared helpers
// (aggregateEvents / addIoc / cleanIp) from this module. `hasPlausibleTld` now lives in
// textDomains.ts; bashHistoryImport keeps importing it from here.
export { MONTHS, parseBsdTime, isInternalIpv4, hasPlausibleTld };

export interface SiemImportOptions {
  // Collapse repetitive identical events into one counted row. Default true.
  aggregate?: boolean;
  // Drop events below this severity floor (e.g. "Low" drops Info noise like logoffs / process-terminated). Default undefined = keep everything.
  minSeverity?: Severity;
  // Safety cap on emitted events. Default 2000 (overridable via DFIR_MAX_EVENTS).
  maxEvents?: number;
  // Safety cap on emitted IOCs. Default 5000.
  maxIocs?: number;
}

// A delta-shaped forensic event (matches deltaSchema.forensicEvents), produced deterministically.
export interface SiemEvent extends Pick<ForensicEvent, "origin"> {
  id: string;
  timestamp: string;
  description: string;
  severity: Severity;
  mitreTechniques: string[];
  // The modification time the source artifact recorded for this file — see ForensicEvent.
  fileModified?: string;
  canonical?: CanonicalEventEnvelope;
  count?: number;
  endTimestamp?: string;
  sha256?: string;
  md5?: string;
  path?: string;
  asset?: string;
  sources?: string[];
  processName?: string;
  parentName?: string;
  pid?: number;
  commandLine?: string; // process-creation command line, forwarded to ForensicEvent for chainSignature (#68)
  srcIp?: string;
  dstIp?: string;
  port?: number;
  // The source artifact/rule that produced this event (e.g. a Velociraptor VQL artifact name).
  artifactName?: string;
  // Identity of the ONE underlying log record this event was mapped from, when the parser reported
  // it — `evtx:<channel>:<EventRecordID>` for a Windows event log. Two different parsers reading the
  // same EVTX file mint the same value, which is what lets correlate.ts recognise a Hayabusa row and
  // a Chainsaw row as one observation instead of two (#688). Never set on an AGGREGATED event —
  // a collapsed group represents many records, so one record's id would misidentify it.
  sourceRecordId?: string;
  // Full, untruncated event message/detail (beyond the truncated `description`) when the mapper had it.
  message?: string;
  // The YEAR in `timestamp` was supplied by the parser, not read from the record (a year-less RFC
  // 3164 / Cisco ASA / Snort line). Forwarded to ForensicEvent.yearInferred, which is the only thing
  // the merge's year-clamp is allowed to re-anchor (#739). STICKY across aggregation: a group that
  // collapsed even one year-less row is year-ambiguous as a whole.
  yearInferred?: boolean;
  // The row's own aggKey, carried through unconditionally (independent of the `aggregate` option)
  // so IOC provenance linkage (mergeRowIocs/resolveExtractedFrom) always has a stable key to
  // resolve against — not persisted on ForensicEvent, stripped before it reaches case state.
  aggKey?: string;
  sharingMarking?: TlpMarking; // See ForensicEvent.sharingMarking (#933 item 21).
}

export interface SiemIoc {
  type: "ip" | "domain" | "hash" | "file" | "process" | "url" | "sid" | "other";
  value: string;
  // Import-scoped only: the aggKey(s) of the row(s) that produced this IOC within one parse call.
  // Resolved to real case-scoped event ids by pipeline.ts and converted into `extractedFrom`;
  // never itself persisted into case state.
  sourceAggKeys?: string[];
  // Case-scoped event id(s) this IOC was authoritatively extracted from. Set by pipeline.ts after
  // resolving sourceAggKeys; empty/absent falls back to iocProvenanceChain.ts's approximate matcher.
  extractedFrom?: string[];
}

export interface SiemParseResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  total: number; // records found in the container
  kept: number; // events emitted (after aggregation + cap)
  dropped: number; // records not represented (below floor / capped / unparseable)
  groups: number; // distinct event groups before the cap
  format: string; // detected container shape (elastic-data / elastic-hits / ndjson / array / events:<key> / single)
  hostname: string; // best-effort dominant host
}

type Row = Record<string, unknown>;

// Aggregation lives in eventAggregate.ts (siemImport is a ledgered oversized file, #385).
// Re-exported here so the importers that have always taken it from this module still can.
export {
  maxEventsDefault,
  createEventAggregator,
  aggregateEvents,
  type EventAggregator,
} from "./eventAggregate.js";

// ───────────────────────────── small value helpers ─────────────────────────────

export function isObject(v: unknown): v is Row {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
export function str(v: unknown): string {
  return typeof v === "string" ? v : v == null ? "" : typeof v === "object" ? "" : String(v);
}
export function oneLine(s: string): string {
  return s.replace(/\s*[\r\n]+\s*/g, " ").trim();
}
export function baseName(p: string): string {
  return p.trim().split(/[\\/]/).pop() || p.trim();
}
// Case-insensitive single-key lookup.
export function getCI(row: Row, key: string): unknown {
  if (key in row) return row[key];
  const lower = key.toLowerCase();
  for (const k of Object.keys(row)) if (k.toLowerCase() === lower) return row[k];
  return undefined;
}
// First non-empty string across candidate keys (case-insensitive), supporting dotted paths.
export function firstStr(row: Row, keys: string[]): string {
  for (const k of keys) {
    const v = k.includes(".") ? getPath(row, k) : getCI(row, k);
    const s = str(v).trim();
    if (s) return s;
  }
  return "";
}
// Dotted-path getter ("host.name", "event.action"), case-insensitive per segment.
export function getPath(row: Row, path: string): unknown {
  let cur: unknown = row;
  for (const seg of path.split(".")) {
    if (!isObject(cur)) return undefined;
    cur = getCI(cur, seg);
  }
  return cur;
}

// Pull MITRE technique ids out of any tactic/tag/meta/classification text. Shared across importers
// (Velociraptor's Sigma/YARA/detection mappers, PersistenceSniper) so each doesn't reimplement it.
export function mitreFromText(...parts: string[]): string[] {
  const out = new Set<string>();
  for (const p of parts) for (const m of p.matchAll(/\bt\d{4}(?:\.\d{3})?\b/gi)) out.add(m[0].toUpperCase());
  return [...out];
}

// ───────────────────────────── container unwrapping ─────────────────────────────

// If an element wraps its real fields under `_source` (Elastic), return that; else the element.
function unwrapSource(el: unknown): Row | null {
  if (!isObject(el)) return null;
  const src = getCI(el, "_source");
  return isObject(src) ? src : el;
}

const RECORD_ARRAY_KEYS = [
  "events",
  "Events",
  "records",
  "Records",
  "results",
  "Results",
  "logs",
  "Logs",
  "rows",
  "items",
  "alerts",
  "Alerts",
  "value",
];

// Parse the file and extract the flat array of event records + a label for the shape.
import { parseConcatenatedJson } from "./concatenatedJson.js";
export { parseConcatenatedJson };

export function extractRecords(text: string): { records: Row[]; format: string } {
  const trimmed = text.trim();
  if (!trimmed) return { records: [], format: "empty" };

  // First try the whole thing as one JSON value.
  let root: unknown;
  let parsed = false;
  try {
    root = JSON.parse(trimmed);
    parsed = true;
  } catch {
    /* fall through to NDJSON */
  }

  if (parsed) {
    if (Array.isArray(root)) {
      return { records: root.map(unwrapSource).filter((r): r is Row => r !== null), format: "array" };
    }
    if (isObject(root)) {
      // Elastic/Kibana table export: { data: [ { _source } ] }
      const data = getCI(root, "data");
      if (Array.isArray(data)) {
        return {
          records: data.map(unwrapSource).filter((r): r is Row => r !== null),
          format: "elastic-data",
        };
      }
      // Elasticsearch search response: { hits: { hits: [ { _source } ] } }
      const hits = getPath(root, "hits.hits");
      if (Array.isArray(hits)) {
        return {
          records: hits.map(unwrapSource).filter((r): r is Row => r !== null),
          format: "elastic-hits",
        };
      }
      // { events: [...] } / { records: [...] } / { results: [...] } …
      for (const key of RECORD_ARRAY_KEYS) {
        const arr = getCI(root, key);
        if (Array.isArray(arr)) {
          return {
            records: arr.map(unwrapSource).filter((r): r is Row => r !== null),
            format: `events:${key}`,
          };
        }
      }
      // A single event object.
      const single = unwrapSource(root);
      return { records: single ? [single] : [], format: "single" };
    }
    return { records: [], format: "unknown" };
  }

  // NDJSON: one JSON object per line (winlogbeat / filebeat / `_source`-wrapped lines).
  // Skip Elastic _bulk action lines ({ "index": {...} }) — those have no event fields.
  const records: Row[] = [];
  for (const line of trimmed.split(/\r\n|\r|\n/)) {
    const l = line.trim();
    if (!l) continue;
    let obj: unknown;
    try {
      obj = JSON.parse(l);
    } catch {
      continue;
    }
    const rec = unwrapSource(obj);
    if (rec && Object.keys(rec).length > 0) records.push(rec);
  }
  if (records.length > 0) return { records, format: "ndjson" };

  // Last resort: concatenated pretty-printed JSON values (Hayabusa `json-timeline` default —
  // multi-line objects, no array, no commas). NDJSON's per-line parse can't see these.
  const concat: Row[] = [];
  for (const v of parseConcatenatedJson(trimmed)) {
    if (Array.isArray(v)) {
      for (const e of v) {
        const r = unwrapSource(e);
        if (r && Object.keys(r).length > 0) concat.push(r);
      }
    } else {
      const r = unwrapSource(v);
      if (r && Object.keys(r).length > 0) concat.push(r);
    }
  }
  if (concat.length > 0) return { records: concat, format: "concatenated-json" };
  return { records: [], format: "ndjson" };
}

// ───────────────────────────── Windows / Sysmon tables ─────────────────────────────

// Groups whose membership IS privilege. An add to one of these is the difference between routine
// user administration and an attacker granting themselves the domain — so it, not the bare event id,
// is what earns a group change its High.
const PRIVILEGED_GROUP =
  /\b(?:domain admins|enterprise admins|schema admins|administrators|account operators|server operators|backup operators|print operators|dnsadmins|group policy creator owners|domain controllers|enterprise key admins|key admins)\b/i;

// The name above is English. AD localises built-in group display names at domain creation, so the
// same add reads "Admins du domaine" on a French domain and "Domänen-Admins" on a German one, and
// the regex misses the one event class where a miss costs a High — and with it the deterministic
// finding backfill that a High guarantees. A group's SID does not localise, so it is checked
// ALONGSIDE the name, never instead of it: DnsAdmins is created by the DNS Server role with a
// variable domain RID, so it has no well-known SID and is only ever reachable by name.
// Builtin groups (S-1-5-32-<rid>): Administrators, Account/Server/Backup/Print Operators. 545
// (Users) and the rest are deliberately absent — they are where routine provisioning lands.
const BUILTIN_PRIVILEGED_RIDS = new Set([544, 548, 549, 550, 551]);
// Domain-relative (S-1-5-21-<3 domain ids>-<rid>): Enterprise Read-only Domain Controllers 498,
// Domain Admins 512, Domain Controllers 516, Schema Admins 518, Enterprise Admins 519, Group Policy
// Creator Owners 520, Read-only Domain Controllers 521, Cloneable Domain Controllers 522, Key
// Admins 526, Enterprise Key Admins 527. Domain Users 513 is NOT privilege.
// 498 and 522 are here because the name check already grades them — both end in "Domain
// Controllers", which PRIVILEGED_GROUP matches — so leaving them out would make the SID path grade
// a localised domain STRICTLY worse than an English one, which is the whole bug this fixes.
const DOMAIN_PRIVILEGED_RIDS = new Set([498, 512, 516, 518, 519, 520, 521, 522, 526, 527]);
const BUILTIN_SID_RE = /^S-1-5-32-(\d{1,10})$/i;
// Same shape as TEXT_SID_RE below: exactly three domain sub-authorities, then the RID.
const DOMAIN_SID_RE = /^S-1-5-21-(?:\d{1,10}-){3}(\d{1,10})$/i;

function isPrivilegedGroupSid(sid: string): boolean {
  const trimmed = sid.trim();
  const builtin = BUILTIN_SID_RE.exec(trimmed);
  if (builtin) return BUILTIN_PRIVILEGED_RIDS.has(Number(builtin[1]));
  const domain = DOMAIN_SID_RE.exec(trimmed);
  return domain ? DOMAIN_PRIVILEGED_RIDS.has(Number(domain[1])) : false;
}

// Channel → short tool label for the description and source tag.
function channelLabel(channel: string): string {
  if (/sysmon/i.test(channel)) return "Sysmon";
  if (/security/i.test(channel)) return "Windows Security";
  if (/system/i.test(channel)) return "Windows System";
  if (/powershell/i.test(channel)) return "Windows PowerShell";
  if (/application/i.test(channel)) return "Windows Application";
  return "Windows Event Log";
}

// ───────────────────────────── timestamps ─────────────────────────────

// Normalize a "YYYY-MM-DD HH:MM:SS(.fff)" (Sysmon UtcTime) to ISO "…Z"; pass ISO through
// toUtcIso (which converts a numeric offset to UTC and leaves "…Z"/naive untouched).
export function normalizeTime(s: string): string {
  const t = s.trim();
  if (!t) return "";
  const m = /^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(\.\d+)?Z?$/.exec(t);
  if (m && !/[+-]\d{2}:?\d{2}$|Z$/.test(t)) return `${m[1]}T${m[2]}${m[3] ?? ""}Z`;
  const kib = parseKibanaDate(t);
  if (kib) return kib;
  return toUtcIso(t);
}

// Kibana's Discover / CSV-export display format, e.g. "May 7, 2026 @ 16:31:04.000". Carries no
// timezone, so — consistent with this codebase's naive-time convention — we read it as UTC. (Kibana
// renders in the browser TZ unless `dateFormat:tz` is UTC; without offset info that's unrecoverable.)
const KIBANA_DATE = /^([A-Z][a-z]{2}) (\d{1,2}), (\d{4}) @ (\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?$/;
function parseKibanaDate(t: string): string {
  const m = KIBANA_DATE.exec(t);
  if (!m) return "";
  const mon = MONTHS[m[1]];
  if (!mon) return "";
  const ms = (m[7] ?? "").padEnd(3, "0");
  return `${m[3]}-${mon}-${m[2].padStart(2, "0")}T${m[4]}:${m[5]}:${m[6]}.${ms || "000"}Z`;
}

const TIME_KEYS = [
  "@timestamp",
  "timestamp",
  "_time",
  "eventTime",
  "EventTime",
  "event_time",
  "DeviceEventTime",
  "createdAt",
  "created",
  "event.created",
  "ingested",
  "generated_time",
  "received_time",
  "observed_timestamp",
  "time",
  "date",
  "@time",
];

// The event's own time. For Sysmon prefer the structured UtcTime (the in-event clock —
// the artifact's own time); otherwise the record's @timestamp / common time fields.
// Never the import time.
function pickTimestamp(rec: Row, ed: Row | undefined): string {
  const sysmonUtc = ed ? str(getCI(ed, "UtcTime")).trim() : "";
  return normalizeTime(sysmonUtc || firstStr(rec, TIME_KEYS));
}

const HOST_KEYS = [
  "computer_name",
  "Computer",
  "hostname",
  "host.name",
  "host",
  "host_name",
  "agent.hostname",
  "beat.hostname",
  "device.hostname",
  "endpoint.name",
  "MachineName",
  "src_host",
  "source.host",
  "winlog.computer_name",
];

export function pickHost(rec: Row): string {
  for (const k of HOST_KEYS) {
    const v = k.includes(".") ? getPath(rec, k) : getCI(rec, k);
    if (typeof v === "string" && v.trim()) return v.trim();
    if (isObject(v)) {
      const n = str(getCI(v, "name")).trim();
      if (n) return n;
    } // ECS host:{name}
  }
  return "";
}

// ───────────────────────────── IOC / hash helpers ─────────────────────────────

const IPV4 = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/; // octet-validated: a version like 1.457.375.0 is not an IP
const HEX_HASH = /^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i;
const NOISE_IP = new Set(["::1", "127.0.0.1", "0.0.0.0", "::", "-", "::ffff:127.0.0.1"]);
// A real IPv6 shape check (full + every valid "::"-compressed form), NOT just "contains a colon" —
// that naive check let ANY colon-bearing string through as a "valid" IPv6 IOC, including free-text
// blobs (a PowerShell cmdletization proxy dump, `cim:ModifyInstance`, `::new(...)`, etc. all contain
// colons) whenever the field happened to reach cleanIp — e.g. a key loosely matching /ip|addr/i.
const IPV6_RE =
  /^(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}$|^(?:[0-9a-f]{1,4}:){1,7}:$|^(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}$|^(?:[0-9a-f]{1,4}:){1,5}(?::[0-9a-f]{1,4}){1,2}$|^(?:[0-9a-f]{1,4}:){1,4}(?::[0-9a-f]{1,4}){1,3}$|^(?:[0-9a-f]{1,4}:){1,3}(?::[0-9a-f]{1,4}){1,4}$|^(?:[0-9a-f]{1,4}:){1,2}(?::[0-9a-f]{1,4}){1,5}$|^[0-9a-f]{1,4}:(?:(?::[0-9a-f]{1,4}){1,6})$|^:(?:(?::[0-9a-f]{1,4}){1,7}|:)$/i;

// Strip an IPv4-mapped IPv6 prefix ("::ffff:10.0.0.1" → "10.0.0.1"); drop loopback/empty.
export function cleanIp(raw: string): string {
  let v = raw.trim();
  if (!v || NOISE_IP.has(v)) return "";
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(v);
  if (mapped) v = mapped[1];
  if (NOISE_IP.has(v)) return "";
  if (IPV4.test(v)) return v;
  // Keep a routable, well-shaped IPv6, but not link-local/loopback.
  if (IPV6_RE.test(v) && !/^fe80:|^::$/i.test(v)) return v;
  return "";
}

// Parse a Sysmon "Hashes" string ("SHA1=..,MD5=..,SHA256=..,IMPHASH=..") + a hashes_ex
// object into { sha256, md5 } (lowercased).
export function parseHashes(rec: Row, ed: Row | undefined): { sha256?: string; md5?: string } {
  const out: { sha256?: string; md5?: string } = {};
  const take = (algo: string, val: string): void => {
    const v = val.trim().toLowerCase();
    if (!HEX_HASH.test(v)) return;
    if (algo === "SHA256" && v.length === 64) out.sha256 ??= v;
    if (algo === "MD5" && v.length === 32) out.md5 ??= v;
  };
  const hashStr = ed ? firstStr(ed, ["Hashes", "Hash"]).trim() : "";
  for (const pair of hashStr.split(",")) {
    const [k, val] = pair.split("=");
    if (k && val) take(k.trim().toUpperCase(), val);
  }
  const hx = getCI(rec, "hashes_ex");
  if (isObject(hx)) {
    take("SHA256", str(getCI(hx, "SHA256")));
    take("MD5", str(getCI(hx, "MD5")));
  }
  return out;
}

// ───────────────────────────── Windows record → event ─────────────────────────────

// event_data fields rendered into the description (curated + stable — no volatile ports,
// GUIDs, or logon IDs, so identical events aggregate). User/domain handled by winAccounts.
const SUBJECT_KEYS = [
  "LogonType",
  "IpAddress",
  "WorkstationName",
  "ServiceName",
  // 4697 (Security) names the binary ServiceFileName; 7045 (System) names it ImagePath. Only the
  // first spelling was listed, so every System-log service install arrived carrying a service
  // DISPLAY NAME and nothing else — and a display name alone cannot be judged. That is how a stock
  // "Intel(R) PRO/1000 …" NIC driver load reads as a fake driver name planted to blend into
  // Services.msc: the field that settles it (\SystemRoot\System32\drivers\e1i68x64.sys, a
  // kernel-mode driver in a protected directory) was dropped before anyone saw the event. All three
  // are stable per service, so aggregation is unaffected.
  "ImagePath",
  "ServiceFileName",
  "ServiceType",
  "StartType",
  "Image",
  "CommandLine",
  // For a PowerShell script block the SCRIPT IS the subject, exactly as the command line is the
  // subject of a process creation — and for the same reason it must be here: this list feeds the
  // aggregation key, so without it two entirely different scripts on the same channel shared one
  // key and collapsed into a single event. That was survivable while a script block yielded no
  // indicators; now that it does, every IOC scraped from the merged-away records would be stamped
  // with the surviving event's id, pointing an analyst at a script that never contained them (the
  // #640 failure, in a new place). NOT ScriptBlockId — that is a per-COMPILATION guid, so keying on
  // it would stop genuine repeats of one script from ever aggregating.
  "ScriptBlockText",
  // 4103's spelling of the same thing: 4104 logs the script TEXT, 4103 logs the command as it was
  // INVOKED, under Payload. Here for the reason above — a 4103 rendered none of it, so every
  // pipeline record on one host shared a key and aggregated into one row naming one command. NOT
  // ContextInfo, its companion field: that is per-session boilerplate (severity, host app, user),
  // identical across thousands of records, so keying on it would separate nothing and only pad the
  // description. Note renderFields caps each field at 140 chars, so two commands that first differ
  // beyond that still merge — the same pre-existing limit ScriptBlockText lives with.
  "Payload",
  "NewProcessName",
  "ParentImage",
  "ParentCommandLine",
  "SourceImage",
  "TargetImage",
  "TargetFilename",
  "ImageLoaded",
  "DestinationIp",
  "DestinationPort",
  "DestinationHostname",
  "Protocol",
  "ShareName",
  "RelativeTargetName",
  "TaskName",
  "PipeName",
  "TargetObject",
  "MemberName",
  "Status",
  "SubStatus",
  "FailureReason",
];

// This event's own binary, best spelling first — ONE list so `path` and the file-IOC scrape agree.
const IMAGE_PATH_KEYS = [
  "Image",
  "NewProcessName",
  "ImageLoaded",
  "TargetFilename",
  "ServiceFileName",
  "ImagePath",
];

function renderFields(ed: Row, keys: string[]): string {
  const parts: string[] = [];
  for (const k of keys) {
    const v = str(getCI(ed, k)).trim();
    if (v && v !== "-" && v !== "%%1833") parts.push(`${k}=${oneLine(v).slice(0, 140)}`);
  }
  return parts.join(" - ");
}

// Compose DOMAIN\user (or UPN) account references so the asset graph picks them up.
function winAccounts(ed: Row): string[] {
  const out = new Set<string>();
  const pairs: [string, string][] = [
    ["TargetDomainName", "TargetUserName"],
    ["SubjectDomainName", "SubjectUserName"],
  ];
  for (const [dk, uk] of pairs) {
    const user = str(getCI(ed, uk)).trim();
    if (!user || user === "-" || user === "*") continue;
    const dom = str(getCI(ed, dk)).trim();
    if (user.includes("@"))
      out.add(user); // already a UPN
    else if (dom && dom !== "-") out.add(`${dom}\\${user}`);
    else out.add(user);
  }
  return [...out];
}

// Grade a process image + command line for attacker tradecraft: "strong" (mimikatz / lsadump /
// log-clearing), "weak" (an encoded / hidden / download command, a user-writable image path, or an
// UNCOMMON LOLBin image), or null. Exported so the memory-forensics importer can bump a Volatility
// `cmdline` row the same way.
export function isSuspiciousCmd(image: string, cmd: string): "strong" | "weak" | null {
  // The original and its de-escaped reading, as separate strings (#908 item 1) — never joined, or
  // a rule matches across the join. See commandNormalize.ts.
  const blobs = commandCandidates(image, cmd);
  if (blobs.some((b) => STRONG_CMD.test(b))) return "strong";
  if (blobs.some((b) => SUSP_CMD.test(b)) || SUSP_PATH.test(image)) return "weak";
  // A LOLBin IMAGE on its own grades only when the binary is not itself an everyday one: cmd.exe and
  // powershell.exe spawn continuously on a healthy endpoint, so the name proves nothing without a
  // command-line or path signal to go with it, and grading it Medium buried the rare real one.
  const base = baseName(image).toLowerCase();
  return LOLBINS.has(base) && !NOISY_LOLBINS.has(base) ? "weak" : null;
}

export interface MappedEvent extends Pick<ForensicEvent, "origin"> {
  timestamp: string;
  description: string;
  severity: Severity;
  // The modification time the source artifact recorded for this file — see ForensicEvent.
  fileModified?: string;
  mitre: string[];
  aggKey: string;
  canonical?: CanonicalEventEnvelope;
  sha256?: string;
  md5?: string;
  path?: string;
  asset?: string;
  processName?: string;
  parentName?: string;
  pid?: number;
  commandLine?: string; // full command line of a process-creation event (#68 cross-tool correlation)
  // Per-event tool source(s). siem mapping leaves this unset (the pipeline tags the whole
  // import); reused by chainsawImport, which tags each event Chainsaw/EVTX individually.
  sources?: string[];
  srcIp?: string;
  dstIp?: string;
  port?: number;
  // The source artifact/rule that produced this event (carried through aggregation to SiemEvent).
  artifactName?: string;
  // Identity of the single log record behind this row (see SiemEvent.sourceRecordId); stripped again by the aggregator whenever rows collapse into a group.
  sourceRecordId?: string;
  // Full, untruncated event message/detail (beyond the truncated `description`) when available.
  message?: string;
  // See SiemEvent.yearInferred. Set per PARSED LINE, so one export may carry both dated (RFC 5424)
  // and year-less (RFC 3164) rows and only the latter become clamp-eligible.
  yearInferred?: boolean;
  sharingMarking?: TlpMarking; // See ForensicEvent.sharingMarking (#933 item 21).
}

// Parse a Windows pid that may be decimal ("5292") or hex ("0x14ac", as 4688 renders it). Returns a
// positive integer or undefined.
export function parsePid(raw: string): number | undefined {
  const s = raw.trim();
  if (!s || s === "-") return undefined;
  const n = /^0x[0-9a-f]+$/i.test(s) ? parseInt(s, 16) : Number(s);
  return Number.isInteger(n) && n > 0 ? n : undefined;
}

// Map a Windows Event Log / Sysmon record. Returns null if it is not a Windows record.
// RC4 Kerberos ticket-encryption types (0x17 RC4-HMAC, 0x18 RC4-HMAC-EXP) — the weak cipher an
// attacker forces so a service ticket can be cracked offline. Sourced from the Kerberoasting
// detection tell in Anthropic-Cybersecurity-Skills `detecting-kerberoasting-attacks` (Apache-2.0):
// a TGS-REQ (4769) encrypted with RC4 against a *user* service account (SPN owner) is the classic
// roasting request. Sibling AS-REP roasting (4768 with pre-auth disabled) is standard AD tradecraft.
const RC4_ENC_TYPES = new Set(["0x17", "0x18"]);

// Verdict-OVERLAY (we grade + tag the otherwise-Low 4769/4768, we do not re-detect): conservative to
// respect signal-to-noise — RC4 to a machine account (`name$`) or the krbtgt service is normal in a
// mixed AD and stays Low; a single RC4 request isn't proof, so we grade Medium and rely on the
// technique tag + high-volume-spray correlation (many 4769s → the burst/asset views) to surface it.
export function kerberosRoastSignal(eid: number, ed: Row): { severity: Severity; mitre: string[] } | null {
  if (eid !== 4769 && eid !== 4768) return null;
  const enc = str(getCI(ed, "TicketEncryptionType")).trim().toLowerCase();
  if (!RC4_ENC_TYPES.has(enc)) return null;
  if (eid === 4769) {
    // TGS-REQ: the account the ticket is FOR is the ServiceName (the SPN owner).
    const service = str(getCI(ed, "ServiceName")).trim();
    if (!service || service.endsWith("$") || service.toLowerCase().includes("krbtgt")) return null;
    return { severity: "Medium", mitre: ["T1558.003"] }; // Kerberoasting
  }
  // AS-REQ (4768): AS-REP roasting only when pre-authentication is disabled (PreAuthType 0) — RC4 on
  // a normal logon is far too common to flag, so require the roastable-account tell to stay low-FP.
  const preAuth = str(getCI(ed, "PreAuthType")).trim();
  const target = str(getCI(ed, "TargetUserName")).trim();
  if (preAuth !== "0" || !target || target.endsWith("$")) return null;
  return { severity: "Medium", mitre: ["T1558.004"] }; // AS-REP roasting
}

// Windows logon-type codes (4624/4625 `LogonType`) → human name. Mirrors Timesketch's login analyzer
// LOGON_TYPES, which only tags; we additionally GRADE the risky ones (see logonRisk).
export const LOGON_TYPES: Record<number, string> = {
  2: "Interactive",
  3: "Network",
  4: "Batch",
  5: "Service",
  7: "Unlock",
  8: "NetworkCleartext",
  9: "NewCredentials",
  10: "RemoteInteractive/RDP",
  11: "CachedInteractive",
};

// A routable (public) IPv4 source? RFC1918 / loopback / link-local / CGNAT are internal → not a
// remote-access signal on their own. Non-IPv4 / blank ("-", "::1", "127.0.0.1") count as internal —
// so this must stay "IPv4-shaped AND not internal", never a plain !isInternalIpv4 (which would call
// a blank/IPv6 source public and make logonRisk grade e.g. a blank-source type-3 logon external).
function isPublicIpv4(ip: string): boolean {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(ip.trim()) && !isInternalIpv4(ip);
}

// Risk overlay for a successful logon (4624). Decodes the logon type and grades the ones that carry
// lateral-movement / credential-abuse signal, keyed on the source IP where the internal-vs-external
// distinction matters. Returns the decoded type name plus an optional severity bump + ATT&CK ids.
// Conservative on purpose (signal-to-noise): an ordinary interactive / internal-network logon is left
// at the table's Low and gets NO technique — only the genuinely noteworthy shapes escalate.
//   • Type 10 RemoteInteractive (RDP)  → T1021.001; Medium when the source IP is public (external RDP).
//   • Type 3  Network from a PUBLIC IP → T1078; internet-facing network logon (SMB/WinRM/etc.).
//   • Type 8  NetworkCleartext        → T1078, Medium; credentials sent in cleartext (legacy/basic auth).
//   • Type 9  NewCredentials          → T1550.002, Medium; runas /netonly — the overpass/pass-the-hash shape.
export function logonRisk(
  logonType: number,
  sourceIp: string,
): { typeName: string; severity?: Severity; mitre: string[] } {
  const typeName = LOGON_TYPES[logonType] ?? `type ${logonType}`;
  const external = isPublicIpv4(sourceIp);
  switch (logonType) {
    case 10:
      return { typeName, severity: external ? "Medium" : undefined, mitre: ["T1021.001"] };
    case 3:
      return external ? { typeName, severity: "Medium", mitre: ["T1078"] } : { typeName, mitre: [] };
    case 8:
      return { typeName, severity: "Medium", mitre: ["T1078"] };
    case 9:
      return { typeName, severity: "Medium", mitre: ["T1550.002"] };
    default:
      return { typeName, mitre: [] };
  }
}

interface CanonicalRecordContext {
  source: string;
  recordIndex: number;
}

export function mapWindows(
  rec: Row,
  host: string,
  iocSink: Map<string, SiemIoc>,
  canonicalContext: CanonicalRecordContext = { source: "windows-event", recordIndex: 0 },
): MappedEvent | null {
  const eidRaw =
    getCI(rec, "event_id") ??
    getCI(rec, "EventID") ??
    getPath(rec, "winlog.event_id") ??
    getPath(rec, "event.code");
  const eid = Number(typeof eidRaw === "object" && isObject(eidRaw) ? getCI(eidRaw, "#text") : eidRaw);
  const channel = firstStr(rec, ["log_name", "channel", "Channel", "winlog.channel", "source_name"]);
  if (!Number.isFinite(eid) || !channel) return null;

  const edRaw = getCI(rec, "event_data") ?? getPath(rec, "winlog.event_data") ?? getCI(rec, "EventData");
  const defender = decodeDefenderEvent(channel, eid, isObject(edRaw) ? edRaw : {}); // #930 item 1
  const ed: Row = isObject(edRaw) ? edRaw : {};
  const [isSysmon, isPwsh] = [/sysmon/i.test(channel), /powershell/i.test(channel)];
  // The rendered event message, verbatim. It was read for the unknown-event LABEL and then dropped,
  // so a Windows event reached the case with `message` UNSET while every other importer populated
  // it — and the content tagger's default ruleset matches `message`. Twelve of its rules, the ones
  // targeting Windows event evidence, therefore matched NOTHING on the very events they name: dead
  // promotion paths that looked live. Kept raw (newlines and tabs intact, uncapped, as
  // velociraptorImport and hayabusaImport keep theirs) because a rule anchors on that rendering —
  // `Logon Type:\t\t3` is a real condition — and because the field's contract is the FULL detail
  // behind the 600-char description.
  const rawMessage = firstStr(rec, ["message", "Message"]).trim();
  const def: WinEventDef = defender?.def ??
    channelTable(channel)[eid] ?? {
      label: oneLine(rawMessage.split(/[\r\n]/)[0] || `Event ${eid}`).slice(0, 120),
      severity: "Info",
    };

  const tool = channelLabel(channel);
  // The PowerShell payload this record carries, under either of its two spellings — 4104's script
  // text or 4103's invoked command. One binding because both readers below must see the same text:
  // the one that GRADES it and the one that scrapes its indicators. They never co-occur on a record.
  // ScriptBlockText names its own contents, so it is read wherever it appears — #652 turns on every
  // shape that reaches a parsed 4104 (Sigma and DetectRaptor rows included) being graded here.
  // `Payload` does NOT: it is a generic event_data key that any provider may use for anything, so it
  // counts as a PowerShell payload only on the PowerShell channel. Read it unconditionally and an
  // unrelated Application event quoting the word IEX is promoted and tagged T1059.001.
  const psText = isPwsh ? firstStr(ed, ["ScriptBlockText", "Payload"]) : str(getCI(ed, "ScriptBlockText"));
  const accts = winAccounts(ed);
  const subject = renderFields(ed, def.kind === "dns" ? SUBJECT_KEYS : [...SUBJECT_KEYS, "QueryName"]); // the overlay owns it
  let description = defender
    ? defenderDescription(def.label, eid, accts, subject, host)
    : `${tool} ${def.label} (EID ${eid})`;
  if (accts.length && !defender) description += ` - ${accts.join(", ")}`;
  if (subject && !defender) description += ` - ${subject}`;
  if (host && !defender) description += ` @ ${host}`;
  description = description.slice(0, 600);

  // The service binary, under either channel's spelling (4697 says ServiceFileName, 7045 says
  // ImagePath). Read before the severity block because that block now grades it.
  const serviceExe = firstStr(ed, ["ServiceFileName", "ImagePath"]).trim();

  // Severity — start from the table, then bump on suspicious process/command.
  let severity = def.severity;
  let mitre = [...(def.mitre ?? [])];
  if (def.kind === "process") {
    const image = str(getCI(ed, "Image")) || str(getCI(ed, "NewProcessName"));
    const cmd = str(getCI(ed, "CommandLine"));
    const susp = isSuspiciousCmd(image, cmd);
    if (susp === "strong") {
      severity = worst(severity, "High");
      if (!mitre.includes("T1003")) mitre.push("T1003");
    } else if (susp === "weak") severity = worst(severity, "Medium");
    // Deterministic attacker-tradecraft grading harvested from real intrusions (Defender-disable,
    // recovery inhibition, reverse-tunnel C2, Impacket lateral movement, cloud exfil, RMM/C2 tooling)
    // with the CORRECT ATT&CK technique per match (not isSuspiciousCmd's T1003 default).
    const tc = tradecraftSignal(image, cmd);
    if (tc) {
      severity = worst(severity, tc.weight === "strong" ? "High" : "Medium");
      for (const t of tc.mitre) if (!mitre.includes(t)) mitre.push(t);
    }
    // A credential passed on the command line is readable by any user on the host and is now in the
    // event log forever. Graded here explicitly rather than relying on whichever tradecraft rule
    // happened to also match, so the same secret grades identically on every sensor — see
    // secretSpillRules.ts.
    const spill = secretSpillSignal(cmd);
    if (spill) {
      severity = worst(severity, "Medium");
      for (const t of spill.mitre) if (!mitre.includes(t)) mitre.push(t);
    }
    // Tag discovery / credential-access recon (whoami, net group /domain, dir /s, findstr password,
    // .ssh/id_rsa, …) so the case identifies the enumeration phase even when each command is Info/Low.
    for (const t of reconTechniques(image, cmd)) if (!mitre.includes(t)) mitre.push(t);
  }
  // Sysmon 15: what the stream is decides (ntfsStreams.ts, #932 item 3), never the event id.
  const ads = def.kind === "stream" ? streamOverlay((k) => str(getCI(ed, k)), description, severity) : null;
  if (ads) ({ description, severity } = ads);
  for (const t of ads?.mitre ?? []) if (!mitre.includes(t)) mitre.push(t);
  // A logged script block or pipeline payload is executable content — the same thing a command line
  // is — so it is graded by the same tables (scriptBlockSignal). Keyed on the FIELD, not the channel
  // or `kind`: every shape that reaches a parsed 4104/4103 funnels through here, as the IOC scrape
  // below does.
  const sbs = scriptBlockSignal(psText);
  if (sbs) {
    if (sbs.weight) severity = worst(severity, sbs.weight === "strong" ? "High" : "Medium");
    for (const t of sbs.mitre) if (!mitre.includes(t)) mitre.push(t);
  }
  // What earns a persistence install its High: the payload, not the event id. A service names its
  // binary in a structured field; a scheduled task hides its action inside the rendered message,
  // which is the only place the command it runs appears at all. Graded by the same tables a process
  // creation is, so `sc create` pointing at \Temp\ and a task launching rundll32 from AppData both
  // land where they did before, while the Chrome and Edge updaters that fire on every endpoint all
  // day settle at Medium — in the timeline, out of the auto-finding backfill.
  if (!isSysmon) {
    const payload =
      eid === 4697 || eid === 7045 ? serviceExe : eid === 4698 || eid === 4702 ? rawMessage : "";
    if (payload && (isSuspiciousCmd(payload, payload) || tradecraftSignal("", payload)))
      severity = worst(severity, "High");
    // A group add is High when the GROUP is privileged — see PRIVILEGED_GROUP. 4728/4732/4756 name
    // the group in TargetUserName and the member in MemberName, not the other way round. The name
    // is localised and the SID is not, so either identifying the group is enough — see
    // isPrivilegedGroupSid for why neither check subsumes the other.
    if (
      (eid === 4728 || eid === 4732 || eid === 4756) &&
      (PRIVILEGED_GROUP.test(str(getCI(ed, "TargetUserName"))) ||
        isPrivilegedGroupSid(str(getCI(ed, "TargetSid"))))
    )
      severity = worst(severity, "High");
  }
  // Sysmon 10/8/25: what the record establishes — rights, call trace, thread start, both process
  // identities — decides (processAccess.ts, #932 item 9); the table's technique was the overclaim.
  const pa =
    def.kind === "procaccess" || def.kind === "thread" || def.kind === "tamper"
      ? processOverlay({
          kind: def.kind,
          field: (k) => str(getCI(ed, k)),
          has: (k) => getCI(ed, k) !== undefined,
          description,
          severity,
          mitre,
          recordId: str(getCI(rec, "EventRecordID")),
          row: canonicalContext.recordIndex,
        })
      : null;
  if (pa) ({ description, severity, mitre } = pa);
  // Sysmon 22 / DNS-Client (dnsRecord.ts, #933 item 2) or DNS Server 257/258/259 (dnsServerRecord.ts, #996).
  const dq = windowsDnsOverlay(def.dns, eid, (k) => getCI(isObject(edRaw) ? ed : rec, k), description);
  if (dq) ({ description } = dq);
  // Kerberoasting / AS-REP roasting: an RC4-encrypted Kerberos ticket request for a user service
  // account grades the otherwise-Low 4769/4768 with the correct technique (see kerberosRoastSignal).
  if (!isSysmon) {
    const roast = kerberosRoastSignal(eid, ed);
    if (roast) {
      severity = worst(severity, roast.severity);
      for (const t of roast.mitre) if (!mitre.includes(t)) mitre.push(t);
    }
  }
  // Logon-type overlay for a successful logon (4624): decode the type into the description (so an
  // analyst sees "RemoteInteractive/RDP" not "type 10"), and grade the risky ones (external RDP,
  // internet-facing network logon, cleartext creds, runas /netonly) — see logonRisk.
  if (!isSysmon && eid === 4624) {
    const ltRaw = str(getCI(ed, "LogonType")).trim();
    const lt = Number(ltRaw);
    if (ltRaw && Number.isFinite(lt)) {
      const src = cleanIp(str(getCI(ed, "IpAddress")));
      const r = logonRisk(lt, src);
      description = `${description} [${r.typeName}${src ? ` from ${src}` : ""}]`.slice(0, 600);
      if (r.severity) severity = worst(severity, r.severity);
      for (const t of r.mitre) if (!mitre.includes(t)) mitre.push(t);
    }
  }

  // Structured correlation/IOC fields.
  const { sha256, md5 } = parseHashes(rec, ed);
  // A file event (Sysmon 11 / 23 / 26) is ABOUT its TargetFilename: that is the row's path, and the
  // Image is the process that touched it (kept on the envelope's process block below).
  const imagePath = // a stream's host file (ntfsStreams.ts); else the flagged file, when the record names no image
    ads?.hostPath ||
    (def.fileAction
      ? // Only the target file: a row with no TargetFilename names no file, and the Image must
        // never stand in for it — that would claim a create/delete of the touching process.
        firstStr(ed, ["TargetFilename"]).replace(/^-$/, "")
      : firstStr(ed, [...IMAGE_PATH_KEYS, "TargetImage"]) || defender?.image || "");
  const processName =
    def.kind === "process" || def.kind === "procaccess"
      ? baseName(
          str(getCI(ed, "Image")) || str(getCI(ed, "SourceImage")) || str(getCI(ed, "NewProcessName")),
        ) || undefined
      : undefined;
  const parentName = baseName(str(getCI(ed, "ParentImage"))) || undefined;
  // Subject pid on process-CREATION events only: 4688 NewProcessId (hex), Sysmon 1 ProcessId (decimal).
  const pidKey = !isSysmon && eid === 4688 ? "NewProcessId" : isSysmon && eid === 1 ? "ProcessId" : "";
  const pid = parsePid(str(getCI(ed, pidKey)));
  const commandLine = def.kind === "process" ? str(getCI(ed, "CommandLine")) : "";
  const observedTimestamp = str(getCI(ed, "UtcTime")).trim() || firstStr(rec, TIME_KEYS);
  const normalizedTimestamp = pickTimestamp(rec, ed);
  const sourceIp = cleanIp(firstStr(ed, eid === 5156 ? ["SourceAddress"] : ["IpAddress", "SourceIp"])); // #996
  const destinationIp = cleanIp(firstStr(ed, eid === 5156 ? ["DestAddress"] : ["DestinationIp"]));
  const destinationPort = Number(firstStr(ed, eid === 5156 ? ["DestPort"] : ["DestinationPort"]));
  const logonTypeRaw = str(getCI(ed, "LogonType")).trim();
  const logonType = logonTypeRaw && Number.isFinite(Number(logonTypeRaw)) ? Number(logonTypeRaw) : undefined;
  const isLogon = !isSysmon && (eid === 4624 || eid === 4625);
  // Who acted / who initiated / the acting SID / the typed Kerberos ticket (winAccountRoles.ts).
  const roles = winRoleBlocks(eid, isSysmon, (k) => str(getCI(ed, k)));
  const accountName = roles.actor?.name; // kept for the rawFieldMap entry
  const category = roles.event
    ? roles.event.category
    : isLogon
      ? "authentication"
      : def.kind === "process" || pa
        ? "process"
        : def.kind === "network" || def.kind === "dns"
          ? "network"
          : def.kind === "file"
            ? "file"
            : def.kind === "service"
              ? "service"
              : str(getCI(ed, "TaskName"))
                ? "task"
                : str(getCI(ed, "TargetObject"))
                  ? "registry"
                  : "other";
  const canonical = createCanonicalEvent({
    event: {
      category,
      type: roles.event
        ? roles.event.type
        : isLogon
          ? "logon"
          : def.kind === "process"
            ? "start"
            : pa
              ? pa.type
              : def.kind === "network"
                ? "connection"
                : def.kind === "dns"
                  ? "query"
                  : (defender?.eventType ?? def.fileAction ?? def.kind ?? "event"),
      ...(roles.event?.outcome
        ? { outcome: roles.event.outcome }
        : isLogon
          ? { outcome: eid === 4624 ? "success" : "failed" }
          : pa
            ? { action: pa.action }
            : defender
              ? defender.event
              : {}),
    },
    ...(roles.actor ? { actor: roles.actor } : {}),
    ...(host ? { target: { kind: "host" as const, name: host } } : {}),
    ...(defender
      ? { object: defender.object, defender: { ...defender.block, ...(sha256 ? { sha256 } : {}) } }
      : (pa?.entities ?? {})),
    ...(roles.account ? { account: roles.account } : {}),
    ...(roles.subject ? { subject: roles.subject } : {}),
    ...(roles.object ? { object: roles.object } : {}),
    ...(roles.authentication ? { authentication: roles.authentication } : {}),
    ...(isLogon
      ? {
          authentication: {
            ...(logonType !== undefined ? { logonType } : {}),
            ...(str(getCI(ed, "TargetLogonId")).trim()
              ? { sessionId: str(getCI(ed, "TargetLogonId")).trim() }
              : {}),
          },
          ...(str(getCI(ed, "WorkstationName")).trim()
            ? { session: { terminal: str(getCI(ed, "WorkstationName")).trim() } }
            : {}),
        }
      : {}),
    ...(sourceIp || destinationIp || (Number.isInteger(destinationPort) && destinationPort > 0)
      ? {
          network: {
            ...(sourceIp ? { source: { address: sourceIp } } : {}),
            ...(destinationIp || (Number.isInteger(destinationPort) && destinationPort > 0)
              ? {
                  destination: {
                    ...(destinationIp ? { address: destinationIp } : {}),
                    ...(Number.isInteger(destinationPort) && destinationPort > 0
                      ? { port: destinationPort }
                      : {}),
                  },
                }
              : {}),
            ...(str(getCI(ed, "Protocol")).trim() ? { protocol: str(getCI(ed, "Protocol")).trim() } : {}),
          },
        }
      : {}),
    ...(pa ? { process: pa.process } : {}),
    ...(dq ? { dns: dq.dns } : {}),
    // A file event carries the process that touched the file, by image and GUID, so the created
    // file and its creator can be joined without reading the text.
    ...(def.fileAction && str(getCI(ed, "Image")).trim()
      ? {
          process: {
            ...(processGuid(str(getCI(ed, "ProcessGuid")))
              ? { id: processGuid(str(getCI(ed, "ProcessGuid"))) }
              : {}),
            executable: str(getCI(ed, "Image")).trim(),
          },
        }
      : {}),
    ...(def.kind === "process"
      ? {
          process: {
            ...(processGuid(str(getCI(ed, "ProcessGuid")))
              ? { id: processGuid(str(getCI(ed, "ProcessGuid"))) }
              : {}),
            ...(pid !== undefined ? { pid } : {}),
            ...(processName ? { name: processName } : {}),
            ...(imagePath ? { executable: imagePath } : {}),
            ...(commandLine ? { commandLine } : {}),
            ...(parentName
              ? {
                  parent: {
                    name: parentName,
                    ...(str(getCI(ed, "ParentImage")).trim()
                      ? { executable: str(getCI(ed, "ParentImage")).trim() }
                      : {}),
                  },
                }
              : {}),
          },
        }
      : {}),
    ...(imagePath || sha256 || md5
      ? {
          file: {
            ...(imagePath ? { path: imagePath, name: baseName(imagePath) } : {}),
            ...(sha256 ? { sha256 } : {}),
            ...(md5 ? { md5 } : {}),
          },
        }
      : {}),
    ...(roles.file ? { file: roles.file } : {}),
    ...(roles.process ? { process: roles.process } : {}),
    ...(str(getCI(ed, "TargetObject")).trim()
      ? {
          registry: {
            key: str(getCI(ed, "TargetObject")).trim(),
            ...(str(getCI(ed, "Details")).trim() ? { valueData: str(getCI(ed, "Details")).trim() } : {}),
          },
        }
      : {}),
    ...(def.kind === "service"
      ? {
          service: {
            ...(str(getCI(ed, "ServiceName")).trim() ? { name: str(getCI(ed, "ServiceName")).trim() } : {}),
            ...(serviceExe ? { executable: serviceExe } : {}),
          },
        }
      : {}),
    ...(str(getCI(ed, "TaskName")).trim()
      ? {
          task: {
            name: str(getCI(ed, "TaskName")).trim(),
            ...(commandLine ? { command: commandLine } : {}),
          },
        }
      : {}),
    time: { observed: observedTimestamp, normalized: normalizedTimestamp },
    evidence: {
      rawRecords: [
        {
          source: canonicalContext.source,
          locator: `row:${canonicalContext.recordIndex}`,
          ...(str(getCI(rec, "EventRecordID")).trim()
            ? { recordId: str(getCI(rec, "EventRecordID")).trim() }
            : {}),
        },
      ],
    },
    producer: {
      importer: "windows-event",
      parserVersion: "1",
      // v3: a Sysmon file event's file is its TargetFilename and its type create / delete.
      mappingVersion: pa ? "windows-event-v2" : def.fileAction ? "windows-event-v3" : "windows-event-v1",
      ruleVersions: ["windows-event-severity-v1"],
    },
    rawFieldMap: {
      "time.observed": ["EventData.UtcTime", ...TIME_KEYS],
      ...(pa?.rawFields ?? {}),
      ...(roles.actorFields ? { "actor.name": roles.actorFields } : {}),
      ...(host ? { "target.name": ["Computer", "host.name"] } : {}),
      ...(logonType !== undefined ? { "authentication.logonType": ["EventData.LogonType"] } : {}),
      ...(sourceIp ? { "network.source.address": ["EventData.IpAddress", "EventData.SourceIp"] } : {}),
      ...(destinationIp ? { "network.destination.address": ["EventData.DestinationIp"] } : {}),
      ...(processName && !pa
        ? { "process.name": ["EventData.Image", "EventData.NewProcessName", "EventData.SourceImage"] }
        : {}),
      ...(pid !== undefined ? { "process.pid": ["EventData.ProcessId", "EventData.NewProcessId"] } : {}),
      ...(processGuid(str(getCI(ed, "ProcessGuid"))) ? { "process.id": ["EventData.ProcessGuid"] } : {}),
      ...(commandLine ? { "process.commandLine": ["EventData.CommandLine"] } : {}),
    },
  });

  // IOCs from the structured fields. SourceAddress/DestAddress are WFP 5156's own spellings (#1211).
  const WFP_5156_IP_KEYS = ["SourceAddress", "DestAddress"];
  for (const ipKey of ["IpAddress", "DestinationIp", "SourceIp", "ClientAddress", ...WFP_5156_IP_KEYS]) {
    const ip = cleanIp(str(getCI(ed, ipKey)));
    if (ip) addIoc(iocSink, "ip", ip);
  }
  if (sha256) addIoc(iocSink, "hash", sha256);
  else if (md5) addIoc(iocSink, "hash", md5);
  for (const fk of IMAGE_PATH_KEYS) {
    const f = str(getCI(ed, fk)).trim();
    if (f && f !== "-" && /[\\/]/.test(f)) addIoc(iocSink, "file", f);
  }
  if (processName) addIoc(iocSink, "process", processName);
  // Scrape indicators embedded in a process command line's free-text (download / exfil URLs, C2
  // domains, public IPs) — the structured-field extraction above misses these, so an exfil URL like
  // `Invoke-RestMethod -Uri https://mft.attacker.tld -InFile loot.zip` never became an IOC. textIocs
  // already skips internal AD/mDNS zones (.local/.lan/.corp) and filenames, so this stays signal-rich.
  if (def.kind === "process") textIocs(str(getCI(ed, "CommandLine")), iocSink);
  // A PowerShell payload is evidence in exactly the same way a command line is — it is where the
  // download cradle names its C2 — but it arrives under `ScriptBlockText` (4104) or `Payload` (4103)
  // with no `kind: "process"` to trigger the scrape above, so a natively-parsed row yielded NO IOCs
  // at all: not the URL, not the IP, not the domain (#652). Scraped here rather than on any one
  // importer's path because every shape that reaches a PARSED 4104/4103 — Velociraptor eventlog,
  // Sigma and DetectRaptor rows, raw EVTX XML, Chainsaw, generic SIEM records — funnels through
  // mapWindows. Hayabusa does NOT: it renders events through its own output profile and has its own
  // mapper, which scrapes the script block itself.
  textIocs(psText, iocSink);
  if (dq?.dns.indicator) addIoc(iocSink, "domain", dq.dns.query); // a real queried name; never a returned address

  const recordIdentity = evtxRecordIdentity(channel, getCI(rec, "EventRecordID"));

  return {
    timestamp: normalizedTimestamp,
    description,
    severity,
    mitre,
    canonical,
    // The HOST leads the key. Without it, ONE attacker action on N machines collapsed into one counted
    // row naming one of them; the other N-1 left the case (timeline, assetGraph, every IOC scraped off
    // the merged rows) and `count: N` cannot say repeats-on-one from one-on-N — a service dropped on
    // 12 servers read as one (#659). Every other mapper keys on the host; the cost (500 workstations'
    // benign 4624 = 500 rows) is the trade networkTokens.ts settled for #640: a silent merge is a
    // report-integrity failure, an unmerged repeat is visible noise. Lowercased as a whole (SRV-A and
    // srv-a stay one host); a host-less export keys on "". pid keeps process creations distinct; a
    // Sysmon 15 stream carries its exact path's digest and the host file's hash (ntfsStreams.ts).
    aggKey:
      `win|${host}|${channel}|${eid}|${accts.join(",")}${isSysmon && accountName ? `|u=${accountName}` : ""}|${pa ? "" : subject}${pid !== undefined ? `|pid=${pid}` : ""}${defender ? `|${defender.identity}` : ""}${ads?.identity ?? ""}${pa?.identity ?? ""}${dq?.identity ?? ""}`.toLowerCase(),
    ...(sha256 ? { sha256 } : {}),
    ...(md5 ? { md5 } : {}),
    ...(imagePath ? { path: imagePath } : {}),
    ...(host ? { asset: host } : {}),
    ...(processName ? { processName } : {}),
    ...(def.kind === "process" && parentName ? { parentName } : {}),
    ...(pid !== undefined ? { pid } : {}),
    // Command line on process-creation events → chainSignature for cross-tool correlation (#68).
    ...(commandLine ? { commandLine } : {}),
    ...(rawMessage ? { message: rawMessage } : {}),
    // The record's own identity, when the export carried it. Lets a second parser's reading of the
    // SAME Windows record merge with this one instead of doubling the timeline (#688). Every
    // natively-parsed EVTX shape reaches this mapper — raw EVTX XML, Velociraptor eventlog rows,
    // generic SIEM records — so one line here covers them all.
    ...(recordIdentity ? { sourceRecordId: recordIdentity } : {}),
  };
}

// The worst-wins comparator lives beside SEVERITY_RANK in stateTypes.ts (worstSeverity);
// re-exported under its historical name for the sibling importers, like isInternalIpv4 above.
export { worst };

// ───────────────────────────── generic record → event ─────────────────────────────

const SEV_WORDS: Record<string, Severity> = {
  critical: "Critical",
  crit: "Critical",
  emergency: "Critical",
  alert: "Critical",
  fatal: "Critical",
  high: "High",
  error: "High",
  err: "High",
  medium: "Medium",
  med: "Medium",
  moderate: "Medium",
  warning: "Medium",
  warn: "Medium",
  low: "Low",
  notice: "Low",
  info: "Info",
  informational: "Info",
  debug: "Info",
};
const SEVERITY_FIELD_KEYS = [
  "severity",
  "Severity",
  "alert.severity",
  "event.severity",
  "priority",
  "Priority",
  "risk",
  "risk_level",
  "risk_score",
  "score",
  "threat_level",
  "confidence",
  "level",
];

// Best-effort severity for a non-Windows record from an explicit severity/level field.
function pickGenericSeverity(rec: Row): Severity {
  for (const k of SEVERITY_FIELD_KEYS) {
    const v = k.includes(".") ? getPath(rec, k) : getCI(rec, k);
    if (v == null) continue;
    if (typeof v === "number") {
      // Common 0-10 / 0-100 risk scales: map high→Critical, etc.
      if (v >= 90 || (v >= 9 && v <= 10)) return "Critical";
      if (v >= 70 || (v >= 7 && v < 9)) return "High";
      if (v >= 40 || (v >= 4 && v < 7)) return "Medium";
      if (v > 0) return "Low";
      continue;
    }
    const w = SEV_WORDS[str(v).trim().toLowerCase()];
    if (w) return w;
  }
  return "Low";
}

const GENERIC_MSG_KEYS = [
  "message",
  "Message",
  "description",
  "Description",
  "desc",
  "Desc",
  "event.action",
  "action",
  "rule.name",
  "ruleName",
  "signature",
  "signature_name",
  "name",
  "alert_name",
  "title",
  "event.original",
  "_raw",
  "raw",
  "summary",
];

// Flatten a record to dotted key/value string pairs (objects one+ levels deep).
export function flatten(obj: Row, out: [string, string][], prefix = "", depth = 0): void {
  if (depth > 3) return;
  for (const [k, v] of Object.entries(obj)) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (typeof v === "string" || typeof v === "number" || typeof v === "boolean") {
      out.push([key, String(v)]);
    } else if (isObject(v)) {
      flatten(v, out, key, depth + 1);
    } else if (Array.isArray(v)) {
      for (const item of v) {
        if (typeof item === "string" || typeof item === "number") out.push([key, String(item)]);
        else if (isObject(item)) flatten(item, out, key, depth + 1);
      }
    }
  }
}

// IOC extraction for non-Windows records, driven by key-name heuristics.
export function genericIocs(pairs: [string, string][], iocSink: Map<string, SiemIoc>): void {
  for (const [key, value] of pairs) {
    const k = key.toLowerCase();
    const v = value.trim();
    if (!v || v === "-") continue;
    if (
      /(?:^|[._])(?:ip|ipaddr|ipaddress|src_ip|dst_ip|source_ip|dest_ip|destination_ip|remote_ip|client_ip|address)$/.test(
        k,
      )
    ) {
      const ip = cleanIp(v);
      if (ip) addIoc(iocSink, "ip", ip);
      continue;
    }
    if (/sha256|sha1|\bmd5\b|imphash|(?:^|[._])hash$/.test(k) && HEX_HASH.test(v)) {
      addIoc(iocSink, "hash", v.toLowerCase());
      continue;
    }
    if (/(?:url|uri)$/.test(k) && /^https?:\/\//i.test(v)) {
      addIoc(iocSink, "url", v.slice(0, 300));
      continue;
    }
    if (
      /(?:domain|fqdn|dns|query|host_name|hostname)$/.test(k) &&
      /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(v) &&
      !IPV4.test(v) &&
      !TEXT_DOMAIN_SKIP_RE.test(v) &&
      !TEXT_FILE_EXT_RE.test(v) &&
      hasPlausibleTld(v)
    ) {
      addIoc(iocSink, "domain", v.toLowerCase());
      continue;
    }
    if (/(?:image|process|exe|process_name|processname|command_line|commandline|cmdline)$/.test(k)) {
      const bn = baseName(v);
      if (/\.\w{2,4}$/.test(bn)) addIoc(iocSink, "process", bn);
      continue;
    }
    if (/(?:file|filename|filepath|file_path|path|target_filename)$/.test(k) && /[\\/]/.test(v)) {
      addIoc(iocSink, "file", v.slice(0, 300));
      continue;
    }
  }
}

// Scan a record's free-text human message for embedded indicators that live INSIDE the message
// rather than in a dedicated structured field — e.g. an SSH auth line
// "Failed password for svc_mgmt from 10.44.20.20 port 52310 on PROXY-BO-01". genericIocs only reads
// IP-/hash-/url-NAMED keys, so without this an indicator that only appears in the message text lands
// in the timeline (which renders the description) but never becomes an IOC. Internal RFC1918 IPs are
// kept (an internal SSH source is investigative); the `.local` mDNS suffix is skipped so every event's
// AD hostname doesn't flood the IOC list.
// Brackets and parens are ADMITTED and left to trimSentencePunctuation, which can tell the URI's
// own `)` from the sentence's. No match may CONTAIN `](`, which keeps a markdown-style link from
// becoming one match (#755) — see veloTextIocs.ts for why the guard sits on the `(`. The pipe and
// semicolon stay excluded because a SIEM message is often delimited by them.
const TEXT_URL_RE = /\bhttps?:\/\/(?:[^\s'"|;>(]|(?<!\])\()+/gi;
const TEXT_IPV4_RE = /\b\d{1,3}(?:\.\d{1,3}){3}\b/g;
const TEXT_HASH_RE = /\b[a-f0-9]{64}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{32}\b/gi;
// Windows domain/local ACCOUNT SIDs only (S-1-5-21-<3 domain ids>-<RID>). These name a specific
// principal and are genuinely investigative. Deliberately NOT the well-known service/builtin SIDs
// (S-1-5-18/19/20 LocalSystem etc., S-1-5-32-* builtin groups) — those ride nearly every Windows
// event and would flood the IOC list, exactly the signal-to-noise trap the analyst wants avoided.
const TEXT_SID_RE = /\bS-1-5-21(?:-\d{1,10}){4}\b/gi;

export function textIocs(text: string, sink: Map<string, SiemIoc>): void {
  if (!text) return;
  // Every regex here is linear in the length of `text` (see TEXT_DOMAIN_RE's label bound), so this
  // runs on the WHOLE message. An input cap would be the wrong tool: it bounds one call but not the
  // total, since this runs per record and maxEvents only caps the events finally EMITTED — and it
  // would silently drop indicators past the cap, which for a DFIR tool is the failure that matters.
  // The SHARED rule, not a private copy. This scraper kept its own unconditional strip and had
  // already drifted from the four #752 unified: it cut a quoted URL's trailing dot and a path's
  // own balanced `)`, so one C2 URL became two indicators depending on whether a Velociraptor row
  // or a Windows 4104 row carried it (#756).
  for (const m of text.matchAll(TEXT_URL_RE))
    addIoc(sink, "url", trimSentencePunctuation(m[0], text, m.index ?? 0).slice(0, 300));
  for (const m of text.match(TEXT_SID_RE) ?? []) addIoc(sink, "sid", m.toUpperCase());
  for (const m of text.match(TEXT_HASH_RE) ?? []) addIoc(sink, "hash", m.toLowerCase());
  for (const m of text.match(TEXT_IPV4_RE) ?? []) {
    const ip = cleanIp(m);
    if (ip) addIoc(sink, "ip", ip);
  }
  for (const d of extractDomains(text)) addIoc(sink, "domain", d);
}

// Document/transport metadata that carries no investigative signal — excluded from the fallback
// field dump so the description leads with real content (e.g. Elasticsearch hit metadata).
const META_KEYS = new Set([
  "_id",
  "_index",
  "_type",
  "_score",
  "_version",
  "_ignored",
  "_routing",
  "_seq_no",
  "_primary_term",
  "sort",
  "clientid",
  "flowid",
  "highlight",
]);
// Field names worth surfacing first when there's no standard message field (detections, rule hits,
// command lines, paths, …). Matched against flattened (possibly dotted) key names.
const SALIENT_RE =
  /(name|message|detection|rule|signature|title|desc|stringhit|scriptblock|command|cmdline|action|alert|artifact|reference|keyword|path|process|original|user|account)/i;

// Build a one-line summary from a record's fields when it has no recognized message field: drop
// metadata noise, prefer salient fields, and fall back to the first handful of the rest.
function summarizePairs(pairs: [string, string][]): string {
  const meaningful = pairs.filter(([k]) => !k.startsWith("_") && !META_KEYS.has(k.toLowerCase()));
  const salient = meaningful.filter(([k]) => SALIENT_RE.test(k));
  return (salient.length ? salient : meaningful)
    .slice(0, 8)
    .map(([k, v]) => `${k}=${v}`)
    .join(" - ");
}

export function mapGeneric(rec: Row, host: string, iocSink: Map<string, SiemIoc>): MappedEvent {
  const vendor = detectVendor(rec);
  const msg = firstStr(rec, GENERIC_MSG_KEYS);
  const pairs: [string, string][] = [];
  flatten(rec, pairs);
  genericIocs(pairs, iocSink);

  const base = msg ? oneLine(msg) : summarizePairs(pairs);
  textIocs(base, iocSink); // scrape indicators embedded in the free-text message (not in a named field)
  let description = `${vendor ?? "SIEM event"}: ${base}`.slice(0, 600);
  if (host && !description.toLowerCase().includes(host.toLowerCase()))
    description = `${description} @ ${host}`.slice(0, 600);

  const severity = pickGenericSeverity(rec);
  // Aggregate identical generic events, normalizing volatile numbers/GUIDs out of the key.
  const aggKey = `gen|${vendor ?? ""}|${host}|${base}`
    .toLowerCase()
    .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/g, "<guid>")
    .replace(/\d+/g, "#")
    .slice(0, 400);

  return {
    timestamp: pickTimestamp(rec, undefined),
    description,
    severity,
    mitre: [],
    aggKey,
    ...(host ? { asset: host } : {}),
  };
}

// Detect the vendor/tool behind a generic record from its source/provider/index fields.
function detectVendor(rec: Row): string | undefined {
  const blob = firstStr(rec, [
    "vendor",
    "product",
    "source_name",
    "provider",
    "provider_guid",
    "_index",
    "agent.type",
    "observer.vendor",
    "tags",
  ]);
  if (/sentinel.?one/i.test(blob)) return "SentinelOne";
  if (/crowdstrike|falcon/i.test(blob)) return "CrowdStrike Falcon";
  if (/defender|mde/i.test(blob)) return "Microsoft Defender";
  if (/carbon.?black/i.test(blob)) return "Carbon Black";
  if (/cortex|palo.?alto/i.test(blob)) return "Cortex XDR";
  if (/splunk/i.test(blob)) return "Splunk";
  if (/elastic|kibana|winlogbeat|filebeat|beats/i.test(blob)) return "Elastic";
  if (/qradar/i.test(blob)) return "QRadar";
  if (/wazuh/i.test(blob)) return "Wazuh";
  return undefined;
}

// ───────────────────────────── IOC sink ─────────────────────────────

export function addIoc(sink: Map<string, SiemIoc>, type: SiemIoc["type"], value: string): void {
  const v = value.trim();
  if (!v) return;
  const key = `${type}:${v.toLowerCase()}`;
  if (!sink.has(key)) sink.set(key, { type, value: v });
}

// Merge a per-row IOC sink into the file-level sink once that row's aggKey (from its MappedEvent)
// is known, unioning sourceAggKeys so a value seen across multiple rows keeps every row's link.
// Call with no aggKey for a row that produced IOCs but no event (e.g. non-alert network telemetry)
// — the value still merges in, just without a link, matching today's approximate-only behavior.
export function mergeRowIocs(
  fileSink: Map<string, SiemIoc>,
  rowSink: Map<string, SiemIoc>,
  aggKey?: string,
): void {
  for (const [key, ioc] of rowSink) {
    const existing = fileSink.get(key);
    const keys = existing?.sourceAggKeys ?? [];
    const nextKeys = aggKey && !keys.includes(aggKey) ? [...keys, aggKey] : keys;
    fileSink.set(key, { ...(existing ?? ioc), ...(nextKeys.length ? { sourceAggKeys: nextKeys } : {}) });
  }
}

// Resolve each IOC's sourceAggKeys against a final aggKey->event-id lookup (built once events have
// their case-scoped ids), stamping extractedFrom. An aggKey with no match (e.g. the event was
// capped by maxEvents) is silently dropped — that IOC just falls back to approximate matching.
export function resolveExtractedFrom(
  iocs: readonly SiemIoc[],
  eventIdByAggKey: ReadonlyMap<string, string>,
): SiemIoc[] {
  return iocs.map((c) => {
    if (!c.sourceAggKeys?.length) return c;
    const ids = [
      ...new Set(c.sourceAggKeys.map((k) => eventIdByAggKey.get(k)).filter((x): x is string => !!x)),
    ];
    return ids.length ? { ...c, extractedFrom: ids } : c;
  });
}

// ───────────────────────────── top-level parse ─────────────────────────────

// Map a flat array of already-extracted records to the SIEM result (Windows per-EID mapping,
// generic field auto-detection fallback, aggregation + caps). Shared by parseSiemExport (which
// unwraps JSON/NDJSON containers first) and the Windows-Event-XML importer (which parses the XML
// envelope to the same record shape) so both produce an identical SiemParseResult. Pure.
export function buildSiemResult(
  records: Row[],
  format: string,
  opts: SiemImportOptions = {},
  sourceText?: string,
): SiemParseResult {
  const maxIocs = opts.maxIocs ?? 5000;
  const total = records.length;

  const iocSink = new Map<string, SiemIoc>();
  const hostTally = new Map<string, number>();
  const mapped: MappedEvent[] = [];

  for (const [recordIndex, rec] of records.entries()) {
    const host = pickHost(rec);
    if (host) hostTally.set(host, (hostTally.get(host) ?? 0) + 1);
    const rowSink = new Map<string, SiemIoc>();
    const m =
      mapWindows(rec, host, rowSink, { source: format, recordIndex }) ?? mapGeneric(rec, host, rowSink);
    mergeRowIocs(iocSink, rowSink, m.aggKey);
    mapped.push(m);
  }

  if (opts.aggregate !== false) boundDnsVariants(mapped, iocSink); // dnsRecord.ts, #933 item 2
  runWindowsDnsConnJoin(mapped, iocSink); // #996 — always after boundDnsVariants
  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? maxEventsDefault(),
  });

  const finalEvents = sourceText ? stampSourceArtifactHash(events, sourceText) : events;
  const represented = finalEvents.reduce((n, e) => n + (e.count ?? 1), 0);
  const hostname = [...hostTally.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] ?? "";

  return {
    events: finalEvents,
    iocs: [...iocSink.values()].slice(0, maxIocs),
    total,
    kept: events.length,
    dropped: Math.max(0, total - represented),
    groups,
    format,
    hostname,
  };
}

export function parseSiemExport(text: string, opts: SiemImportOptions = {}): SiemParseResult {
  const { records, format } = extractRecords(text);
  return buildSiemResult(records, format, opts, text);
}
