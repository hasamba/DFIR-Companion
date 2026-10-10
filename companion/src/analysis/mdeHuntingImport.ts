import type { Severity } from "./stateTypes.js";
import {
  extractRecords,
  aggregateEvents,
  addIoc,
  oneLine,
  isObject,
  getCI,
  normalizeTime,
  cleanIp,
  type MappedEvent,
  type SiemEvent,
  type SiemIoc,
  maxEventsDefault,
} from "./siemImport.js";
import type { ImportDebugRecorder } from "./importDebug.js";

// Deterministic importer for Microsoft 365 Defender / Defender XDR advanced-hunting exports (#2097).
// One AH export can mix table shapes in one file — DeviceEvents (endpoint, with DeviceName and the
// InitiatingProcess* actor), IdentityDirectoryEvents (MDI, DeviceName → DestinationDeviceName) and
// CloudAppEvents (no device; AccountObjectId / AccountDisplayName). Every row carries Timestamp and
// ActionType, which is what this importer keys on.
//
// Before this importer the file fell to the SIEM catch-all: everything Low, no host on cloud rows,
// and nothing graded the two signals that matter in a Golden SAML chain — directory replication
// requested from a machine that is not the destination DC (DCSync, T1003.006) and an LDAP read of
// the AD FS DKM container (the key that decrypts the token-signing certificate, T1552.004).
//
// Plain rows default Low, matching the SIEM importer. Only the named shapes in GRADE_RULES are
// graded up. This is not a detection engine: each rule is "worth an analyst's attention".

type Row = Record<string, unknown>;

export interface MdeHuntingImportOptions {
  aggregate?: boolean;
  minSeverity?: Severity;
  maxEvents?: number;
  maxIocs?: number;
  /** This attempt's import debug recorder (#1736): decisions and counts only, never row content. */
  debug?: ImportDebugRecorder;
}

export interface MdeHuntingParseResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  total: number;
  kept: number;
  dropped: number;
  groups: number;
  format: string; // "mde-advanced-hunting" | "empty"
}

export const MDE_HUNTING_SOURCE = "Microsoft Defender XDR (advanced hunting)";
const DEFAULT_SEVERITY: Severity = "Low";
const DESCRIPTION_CAP = 600;
const CLAUSE_CAP = 240;
// Log Analytics suffixes a column with its type when it re-exports AH data (AdditionalFields_string).
const TYPE_SUFFIXES = ["", "_string", "_long", "_datetime", "_dynamic", "_int", "_bool"] as const;
const TIME_KEYS = ["Timestamp", "TimeGenerated"] as const;
// Any one of these beside Timestamp + ActionType marks an AH row rather than arbitrary JSON.
const AH_ANCHOR_KEYS = ["DeviceName", "AccountObjectId", "AdditionalFields", "ReportId"] as const;
const HASH_KEYS = ["SHA256", "InitiatingProcessSHA256"] as const;
const IP_KEYS = ["IPAddress", "RemoteIP"] as const;

const ADFS_DKM_DN_RE = /CN=ADFS,CN=Microsoft,CN=Program Data/i;
const DOMAIN_ADMINS_FILTER_RE = /memberOf=CN=Domain Admins/i;
const REPLICATION_ACTION_RE = /^directory services replication$/i;
const LDAP_ACTION_RE = /^ldapsearch$/i;
const DELEGATED_GRANT_RE = /^add delegated permission grant/i;

/** Read `name` or its Log-Analytics type-suffixed twin (`name_string`, `name_long`, …). */
export function readField(row: Row, name: string): unknown {
  for (const suffix of TYPE_SUFFIXES) {
    const v = getCI(row, name + suffix);
    if (v != null && v !== "") return v;
  }
  return undefined;
}

function text(value: unknown): string {
  return typeof value === "string" ? value : value == null ? "" : String(value);
}

function str(row: Row, name: string): string {
  return text(readField(row, name)).trim();
}

/** Detection signature: a time key, a non-empty ActionType string, and one AH anchor column. */
export function looksLikeMdeHunting(s: Row): boolean {
  if (!TIME_KEYS.some((k) => readField(s, k) != null)) return false;
  const action = readField(s, "ActionType");
  if (typeof action !== "string" || !action.trim()) return false;
  return AH_ANCHOR_KEYS.some((k) => readField(s, k) != null);
}

// Python-repr dicts (`{'a': False}`) appear in some AH re-exports; convert them only as a fallback.
const REPR_WORDS: Record<string, string> = { True: "true", False: "false", None: "null" };
const REPR_SIMPLE_ESCAPES: Record<string, string> = {
  n: "\n",
  t: "\t",
  r: "\r",
  b: "\b",
  f: "\f",
  "0": "\0",
};
/** Python repr's hex escapes and their digit counts: \xNN, \uNNNN and the non-BMP \UNNNNNNNN. */
const REPR_HEX_ESCAPES: Record<string, number> = { x: 2, u: 4, U: 8 };

/** Decode one backslash escape at s[i] (the char after the backslash); returns text and next index. */
function readReprEscape(s: string, i: number): [string, number] | null {
  const c = s[i];
  const hexLen = REPR_HEX_ESCAPES[c];
  if (hexLen) {
    const hex = s.slice(i + 1, i + 1 + hexLen);
    if (!new RegExp(`^[0-9a-fA-F]{${hexLen}}$`).test(hex)) return null;
    const code = parseInt(hex, 16);
    if (code > 0x10ffff) return null;
    return [String.fromCodePoint(code), i + 1 + hexLen];
  }
  if (c in REPR_SIMPLE_ESCAPES) return [REPR_SIMPLE_ESCAPES[c], i + 1];
  if (c === "\\" || c === "'" || c === '"') return [c, i + 1];
  // Python keeps an unrecognised escape verbatim, backslash included — never drop it (#2109).
  return [`\\${c}`, i + 1];
}

/** Read a quoted string starting at s[start]; returns its JSON encoding and the index after it. */
function readReprString(s: string, start: number): [string, number] | null {
  const quote = s[start];
  let out = "";
  let i = start + 1;
  while (i < s.length) {
    const c = s[i];
    if (c === quote) return [JSON.stringify(out), i + 1];
    if (c !== "\\") {
      out += c;
      i += 1;
      continue;
    }
    if (i + 1 >= s.length) return null;
    const esc = readReprEscape(s, i + 1);
    if (!esc) return null;
    out += esc[0];
    i = esc[1];
  }
  return null;
}

/**
 * Quote-aware Python-repr to JSON: strings of either quote style are re-encoded verbatim, and only
 * bare True/False/None outside strings are mapped. Returns null on anything it cannot read.
 */
function reprToJson(s: string): string | null {
  let out = "";
  let i = 0;
  while (i < s.length) {
    const c = s[i];
    if (c === "'" || c === '"') {
      const str = readReprString(s, i);
      if (!str) return null;
      out += str[0];
      i = str[1];
    } else if (/[-\d]/.test(c)) {
      const num = /^-?\d[\d.eE+-]*/.exec(s.slice(i))?.[0] ?? c;
      out += num;
      i += num.length;
    } else if (/[A-Za-z_]/.test(c)) {
      const word = /^[A-Za-z_]\w*/.exec(s.slice(i))![0];
      if (!(word in REPR_WORDS)) return null;
      out += REPR_WORDS[word];
      i += word.length;
    } else {
      out += c;
      i += 1;
    }
  }
  return out;
}

function tryParseObject(s: string): Row | null {
  try {
    const v: unknown = JSON.parse(s);
    return isObject(v) ? v : null;
  } catch {
    return null;
  }
}

/** AdditionalFields as an object: object, JSON string or Python-repr string; `{}` otherwise. */
export function parseAdditionalFields(v: unknown): Row {
  if (isObject(v)) return v;
  if (typeof v !== "string" || !v.trim()) return {};
  const direct = tryParseObject(v);
  if (direct) return direct;
  const json = reprToJson(v);
  return (json && tryParseObject(json)) || {};
}

function joinAccount(domain: string, name: string): string {
  if (!name) return "";
  return domain ? `${domain}\\${name}` : name;
}

/** Actor precedence: AccountUpn > Domain\Name > InitiatingProcess UPN > its Domain\Name > display name. */
function actorOf(row: Row): string {
  return (
    str(row, "AccountUpn") ||
    joinAccount(str(row, "AccountDomain"), str(row, "AccountName")) ||
    str(row, "InitiatingProcessAccountUpn") ||
    joinAccount(str(row, "InitiatingProcessAccountDomain"), str(row, "InitiatingProcessAccountName")) ||
    str(row, "AccountDisplayName") ||
    str(row, "AccountObjectId")
  );
}

interface RowView {
  action: string;
  device: string;
  destDevice: string;
  dn: string;
  filter: string;
}

interface GradeRule {
  match: (v: RowView) => boolean;
  severity: Severity;
  mitre: string[];
}

// Ordered; first match wins.
const GRADE_RULES: readonly GradeRule[] = [
  {
    // DCSync: replication requested by a device that is not the replication destination.
    match: (v) =>
      REPLICATION_ACTION_RE.test(v.action) &&
      !!v.device &&
      !!v.destDevice &&
      v.device.toLowerCase() !== v.destDevice.toLowerCase(),
    severity: "High",
    mitre: ["T1003.006"],
  },
  {
    // AD FS DKM key read: the container holding the key that decrypts the token-signing cert.
    match: (v) => LDAP_ACTION_RE.test(v.action) && ADFS_DKM_DN_RE.test(v.dn),
    severity: "High",
    mitre: ["T1552.004"],
  },
  {
    match: (v) => LDAP_ACTION_RE.test(v.action) && DOMAIN_ADMINS_FILTER_RE.test(v.filter),
    severity: "Medium",
    mitre: ["T1087.002"],
  },
  {
    match: (v) => DELEGATED_GRANT_RE.test(v.action),
    severity: "Medium",
    mitre: ["T1098.003"],
  },
];

function grade(view: RowView): { severity: Severity; mitre: string[] } {
  const rule = GRADE_RULES.find((r) => r.match(view));
  return rule
    ? { severity: rule.severity, mitre: [...rule.mitre] }
    : { severity: DEFAULT_SEVERITY, mitre: [] };
}

function clause(s: string): string {
  return oneLine(s).slice(0, CLAUSE_CAP);
}

// The shape-specific, high-signal clause goes first so the description cap never cuts it.
function detailOf(row: Row, view: RowView): string {
  if (view.filter || view.dn) {
    const parts = [view.filter && `filter ${clause(view.filter)}`, view.dn && `base ${clause(view.dn)}`];
    return parts.filter(Boolean).join(" ");
  }
  if (view.destDevice) return `→ ${clause(view.destDevice)}`;
  const app = str(row, "Application");
  const object = str(row, "ObjectName");
  return [app, object && object !== view.action ? clause(object) : ""].filter(Boolean).join(": ");
}

function describe(row: Row, view: RowView, actor: string, ip: string): string {
  let d = view.action;
  if (view.device) d += ` on ${view.device}`;
  const detail = detailOf(row, view);
  if (detail) d += ` ${detail}`;
  if (actor) d += ` by ${actor}`;
  const proc = str(row, "InitiatingProcessFileName");
  if (proc) d += ` via ${proc}`;
  if (ip) d += ` from ${ip}`;
  return d.slice(0, DESCRIPTION_CAP);
}

function collectIocs(row: Row, sink: Map<string, SiemIoc>): string {
  let firstIp = "";
  for (const k of IP_KEYS) {
    const ip = cleanIp(str(row, k));
    if (!ip) continue;
    addIoc(sink, "ip", ip);
    firstIp ||= ip;
  }
  for (const k of HASH_KEYS) {
    const h = str(row, k).toLowerCase();
    if (/^[0-9a-f]{64}$/.test(h)) addIoc(sink, "hash", h);
  }
  return firstIp;
}

function mapRow(row: Row, sink: Map<string, SiemIoc>, debug?: ImportDebugRecorder): MappedEvent {
  const af = parseAdditionalFields(readField(row, "AdditionalFields"));
  const view: RowView = {
    action: str(row, "ActionType"),
    device: str(row, "DeviceName"),
    destDevice: str(row, "DestinationDeviceName"),
    dn: text(getCI(af, "DistinguishedName")).trim(),
    filter: text(getCI(af, "SearchFilter")).trim(),
  };
  const actor = actorOf(row);
  if (actor) debug?.field("user", "actor");
  const ip = collectIocs(row, sink);
  const { severity, mitre } = grade(view);
  const time = text(readField(row, "Timestamp") ?? readField(row, "TimeGenerated"));
  const sha256 = str(row, "SHA256").toLowerCase() || undefined;
  const timestamp = normalizeTime(time);
  return {
    timestamp,
    description: describe(row, view, actor, ip),
    severity,
    mitre,
    ...(view.device ? { asset: view.device } : {}),
    ...(sha256 && /^[0-9a-f]{64}$/.test(sha256) ? { sha256 } : {}),
    // Time is part of the key: only exact duplicate rows collapse. Two replication requests minutes
    // apart are two DCSync attempts, not one event with a count.
    aggKey:
      `mde|${timestamp}|${view.action}|${view.device}|${view.destDevice}|${actor}|${view.dn}|${view.filter}|${ip}`
        .toLowerCase()
        .slice(0, 400),
    sources: [MDE_HUNTING_SOURCE],
  };
}

export function parseMdeHunting(input: string, opts: MdeHuntingImportOptions = {}): MdeHuntingParseResult {
  const maxIocs = opts.maxIocs ?? 5000;
  const empty: MdeHuntingParseResult = {
    events: [],
    iocs: [],
    total: 0,
    kept: 0,
    dropped: 0,
    groups: 0,
    format: "empty",
  };
  const trimmed = input.trim();
  if (!trimmed) return empty;
  const records = extractRecords(trimmed).records;
  const total = records.length;
  if (total === 0) return empty;

  const iocSink = new Map<string, SiemIoc>();
  const mapped: MappedEvent[] = [];
  for (const raw of records) {
    if (!isObject(raw)) {
      opts.debug?.skipped("not_an_object");
      continue;
    }
    if (!looksLikeMdeHunting(raw)) {
      opts.debug?.skipped("unrecognized_record");
      continue;
    }
    mapped.push(mapRow(raw, iocSink, opts.debug));
  }

  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? maxEventsDefault(),
  });
  const represented = events.reduce((n, e) => n + (e.count ?? 1), 0);
  return {
    events,
    iocs: [...iocSink.values()].slice(0, maxIocs),
    total,
    kept: events.length,
    dropped: Math.max(0, total - represented),
    groups,
    format: mapped.length ? "mde-advanced-hunting" : "empty",
  };
}
