// Deterministic importer for the **sysdig / Falco** family — the runtime-syscall side of Linux
// (and container) visibility. The third Linux-host ingest path (closes #62, with auditd +
// journald); no AI call.
//
// A `.scap` capture is binary, so — like the binary `.msg` email case — the import pipeline (which
// is text-only) consumes the TEXTUAL exports of a capture:
//   • **Falco** alert JSON (`falco -o json_output.json` / `falcosidekick`): rule hits with a
//     `priority`, human `output`, `output_fields`, ATT&CK `tags`, and an ISO `time`. Per the
//     Companion's post-detection principle these are the DETECTIONS → timeline events, mapped
//     VERDICT-FIRST (priority → severity, tags → MITRE).
//   • **sysdig** event JSON (`sysdig -j` / `csysdig`): one object per captured syscall keyed by
//     dotted fields (`evt.num`, `evt.time`/`evt.datetime`/`evt.rawtime`, `proc.name`, `evt.type`,
//     `evt.dir`, `evt.info`). This is high-volume TELEMETRY with no verdict → Info evidence events
//     (aggregated + capped), with proc/file/network IOCs scraped from the fields.
//
// Both forms are routed per-record (a file may mix them), read at each event's OWN time, and tagged
// "Falco" / "sysdig" for cross-source correlation.

import type { Severity } from "./stateTypes.js";
import {
  extractRecords,
  aggregateEvents,
  cleanIp,
  addIoc,
  str,
  getCI,
  isObject,
  baseName,
  oneLine,
  normalizeTime,
  type MappedEvent,
  type SiemEvent,
  type SiemIoc,
} from "./siemImport.js";

type Row = Record<string, unknown>;

export interface SysdigImportOptions {
  aggregate?: boolean;
  minSeverity?: Severity;
  maxEvents?: number;
  maxIocs?: number;
}

export interface SysdigParseResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  total: number;
  kept: number;
  dropped: number;
  groups: number;
  alerts: number;   // Falco rule hits seen
  format: string;   // "falco" | "sysdig" | "mixed" | "empty"
  hostname: string;
}

const IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;
const IPV4_G = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const HEX_HASH = /^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i;
const DOMAIN = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;

// Falco priority (also the syslog severity words) → our Severity.
const FALCO_SEVERITY: Record<string, Severity> = {
  emergency: "Critical", alert: "Critical", critical: "Critical",
  error: "High", err: "High",
  warning: "Medium", warn: "Medium",
  notice: "Low",
  informational: "Info", info: "Info", debug: "Info",
};

function mitreFromTags(tags: unknown): string[] {
  const out = new Set<string>();
  const push = (s: string): void => { for (const m of s.matchAll(/\bt\d{4}(?:\.\d{3})?\b/gi)) out.add(m[0].toUpperCase()); };
  if (Array.isArray(tags)) for (const t of tags) push(str(t));
  else if (tags != null) push(str(tags));
  return [...out];
}

// ───────────────────────────── Falco alert ─────────────────────────────

function isFalcoAlert(rec: Row): boolean {
  return getCI(rec, "rule") != null && getCI(rec, "priority") != null &&
    (getCI(rec, "output") != null || getCI(rec, "output_fields") != null);
}

function addField(sink: Map<string, SiemIoc>, key: string, raw: unknown): void {
  const v = str(raw).trim();
  if (!v || v === "<NA>" || v === "(null)") return;
  const k = key.toLowerCase();
  if (/proc\.(?:name|aname)|^proc$/.test(k)) { addIoc(sink, "process", baseName(v)); return; }
  if (/proc\.(?:exepath|exe)$/.test(k) && v.includes("/")) { addIoc(sink, "file", v.slice(0, 300)); addIoc(sink, "process", baseName(v)); return; }
  if (/proc\.cmdline$/.test(k)) { const bn = baseName(v.split(/\s+/)[0] ?? ""); if (bn) addIoc(sink, "process", bn); return; }
  if (/(?:fd\.name|fd\.filename|fs\.path\.name|file)$/.test(k) && v.includes("/")) { addIoc(sink, "file", v.slice(0, 300)); return; }
  if (/(?:fd\.[sc]?ip|^.*\.ip|connection)/.test(k)) { for (const m of v.matchAll(IPV4_G)) { const ip = cleanIp(m[0]); if (ip) addIoc(sink, "ip", ip); } return; }
  if (/(?:fd\.[sc]?_?domain|domain|dns)/.test(k) && DOMAIN.test(v) && !IPV4.test(v)) { addIoc(sink, "domain", v.toLowerCase()); return; }
  if (/sha256|sha1|\bmd5\b/.test(k) && HEX_HASH.test(v)) addIoc(sink, "hash", v.toLowerCase());
}

function mapFalco(rec: Row, iocSink: Map<string, SiemIoc>): MappedEvent {
  const rule = str(getCI(rec, "rule")) || "Falco rule";
  const prio = str(getCI(rec, "priority")).trim().toLowerCase();
  const output = oneLine(str(getCI(rec, "output")));
  const host = str(getCI(rec, "hostname"));
  const severity = FALCO_SEVERITY[prio] ?? "Medium";
  const mitre = mitreFromTags(getCI(rec, "tags"));

  // Pull IOCs + a proc/file hint from output_fields, then scrape the rendered output for IPs.
  const fields = getCI(rec, "output_fields");
  let procName: string | undefined;
  let path: string | undefined;
  if (isObject(fields)) {
    for (const [k, v] of Object.entries(fields)) {
      addField(iocSink, k, v);
      const kl = k.toLowerCase();
      if (!procName && /proc\.name$/.test(kl)) procName = baseName(str(v));
      if (!path && /proc\.exepath$|^.*exe$/.test(kl) && str(v).includes("/")) path = str(v).slice(0, 300);
    }
  }
  for (const m of output.matchAll(IPV4_G)) { const ip = cleanIp(m[0]); if (ip) addIoc(iocSink, "ip", ip); }

  let description = `Falco: ${rule}`;
  if (output) description += ` — ${output}`;
  if (host) description += ` @ ${host}`;
  description = description.slice(0, 600);

  return {
    timestamp: falcoTime(getCI(rec, "time")),
    description,
    severity,
    mitre,
    aggKey: `falco|${rule}|${procName ?? ""}`.toLowerCase().slice(0, 400),
    sources: ["Falco"],
    ...(host ? { asset: host } : {}),
    ...(path ? { path } : {}),
    ...(procName ? { processName: procName } : {}),
  };
}

// Falco `time` is ISO with nanoseconds ("2024-06-01T00:00:00.123456789Z"); truncate to ms.
function falcoTime(v: unknown): string {
  const s = str(v).trim();
  if (!s) return "";
  return normalizeTime(s.replace(/(\.\d{3})\d+/, "$1"));
}

// ───────────────────────────── sysdig event ─────────────────────────────

function isSysdigEvent(rec: Row): boolean {
  return getCI(rec, "evt.type") != null || getCI(rec, "evt.num") != null || getCI(rec, "evt.rawtime") != null;
}

// sysdig `evt.datetime` ("2024-06-01 00:00:00.123456789") / `evt.rawtime` (ns epoch) → ISO ms.
function sysdigTime(rec: Row): string {
  const dt = str(getCI(rec, "evt.datetime")).trim();
  if (dt) return normalizeTime(dt.replace(/(\.\d{3})\d+/, "$1"));
  const raw = Number(getCI(rec, "evt.rawtime"));
  if (Number.isFinite(raw) && raw > 0) {
    const d = new Date(Math.floor(raw / 1e6)); // ns → ms
    return Number.isNaN(d.getTime()) ? "" : d.toISOString();
  }
  return normalizeTime(str(getCI(rec, "evt.time")));
}

function mapSysdigEvent(rec: Row, iocSink: Map<string, SiemIoc>): MappedEvent {
  const proc = str(getCI(rec, "proc.name")).trim();
  const etype = str(getCI(rec, "evt.type")).trim();
  const dir = str(getCI(rec, "evt.dir")).trim();
  const info = oneLine(str(getCI(rec, "evt.info") ?? getCI(rec, "evt.args")));
  const exe = str(getCI(rec, "proc.exepath") ?? getCI(rec, "proc.exe")).trim();
  const host = str(getCI(rec, "container.name") ?? getCI(rec, "evt.hostname"));
  const fdName = str(getCI(rec, "fd.name")).trim();

  if (proc) addIoc(iocSink, "process", baseName(proc));
  if (exe && exe.includes("/")) addIoc(iocSink, "file", exe.slice(0, 300));
  if (fdName && fdName.includes("/") && !fdName.startsWith("<")) addIoc(iocSink, "file", fdName.slice(0, 300));
  for (const m of `${info} ${fdName}`.matchAll(IPV4_G)) { const ip = cleanIp(m[0]); if (ip) addIoc(iocSink, "ip", ip); }

  let description = `sysdig: ${proc || "?"} ${dir} ${etype}`.trim();
  if (info) description += ` ${info}`;
  description = description.slice(0, 600);

  const procName = baseName(proc) || undefined;
  return {
    timestamp: sysdigTime(rec),
    description,
    severity: "Info",
    mitre: [],
    aggKey: `sysdig|${baseName(proc)}|${dir}|${etype}`.toLowerCase().slice(0, 400),
    sources: ["sysdig"],
    ...(exe && exe.includes("/") ? { path: exe } : {}),
    ...(procName ? { processName: procName } : {}),
  };
}

// True when a record is a sysdig/Falco record (used by the file-type sniffer).
export function looksLikeSysdig(rec: Row): boolean {
  return isFalcoAlert(rec) || isSysdigEvent(rec);
}

// ───────────────────────────── top-level parse ─────────────────────────────

export function parseSysdig(text: string, opts: SysdigImportOptions = {}): SysdigParseResult {
  const maxIocs = opts.maxIocs ?? 5000;
  const { records } = extractRecords(text);
  const total = records.length;
  if (total === 0) {
    return { events: [], iocs: [], total: 0, kept: 0, dropped: 0, groups: 0, alerts: 0, format: "empty", hostname: "" };
  }

  const iocSink = new Map<string, SiemIoc>();
  const hostTally = new Map<string, number>();
  const mapped: MappedEvent[] = [];
  let alerts = 0, sawFalco = false, sawSysdig = false;

  for (const rec of records) {
    if (!isObject(rec)) continue;
    if (isFalcoAlert(rec)) {
      sawFalco = true; alerts++;
      const m = mapFalco(rec, iocSink);
      mapped.push(m);
      if (m.asset) hostTally.set(m.asset, (hostTally.get(m.asset) ?? 0) + 1);
    } else if (isSysdigEvent(rec)) {
      sawSysdig = true;
      mapped.push(mapSysdigEvent(rec, iocSink));
    }
    // anything else is ignored (not a sysdig/Falco record)
  }

  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? 2000,
  });

  const represented = events.reduce((n, e) => n + (e.count ?? 1), 0);
  const hostname = [...hostTally.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] ?? "";
  const format = sawFalco && sawSysdig ? "mixed" : sawFalco ? "falco" : sawSysdig ? "sysdig" : "empty";

  return {
    events,
    iocs: [...iocSink.values()].slice(0, maxIocs),
    total,
    kept: events.length,
    dropped: Math.max(0, total - represented),
    groups,
    alerts,
    format,
    hostname,
  };
}
