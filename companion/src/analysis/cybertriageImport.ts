// Deterministic importer for Cyber Triage (Sleuth Kit Labs, formerly Basis Technology) timeline
// exports — the host-triage counterpart to the KAPE importer. No AI call.
//
// Cyber Triage collects host artifacts (MFT, processes, scheduled tasks, network, …) into ONE
// super-timeline and SCORES the notable items (Bad / Suspicious) with a human-readable reason.
// Per the Companion's post-detection principle we consume that VERDICT — we do not re-score the
// artifacts. The export is overwhelmingly raw filesystem telemetry (tens of thousands of "File
// Modified" rows, score=None), so to keep the timeline signal-rich the importer splits the feed:
//
//   • Scored rows (score is a "notable" verdict, or the CSV `threat_level` names Bad/Suspicious)
//     → forensic events; severity DERIVED from the verdict + a keyword bump on the reason text
//     (lsass dump / mimikatz / remote-access tooling …), reason leads the description, MITRE from
//     the reason, process-chain / path / host / args carried through. The richest signal.
//   • Unscored Process + Scheduled-Task rows → Info evidence events (a bounded process-execution
//     and persistence timeline) — discrete, security-relevant, and they aggregate well.
//   • Unscored File rows (the MFT super-timeline) → DROPPED by default as noise; `fileTelemetry`
//     opts the full file timeline back in (Info evidence, like KAPE's MFT artifact).
//   • Network rows (Active Connection / Port Opened) → IOCs only: the remote IP is harvested, the
//     port-only telemetry is not turned into events.
//
// Inputs accepted (the two timeline forms Cyber Triage emits — the Excel report is a formatted
// human deliverable, not ingested): JSONL / NDJSON (richest — carries hostName, process chain,
// args, the scoreDescription split), a JSON array, or the CSV timeline (lossy — no host, no
// process chain; `threat_level` carries "<verdict>. <reason>"). All events are tagged
// "Cyber Triage" for cross-source correlation.

import type { Severity } from "./stateTypes.js";
import { parseCsv } from "./csvImport.js";
import {
  extractRecords,
  aggregateEvents,
  addIoc,
  firstStr,
  baseName,
  oneLine,
  cleanIp,
  str,
  isObject,
  getCI,
  normalizeTime,
  type MappedEvent,
  type SiemEvent,
  type SiemIoc,
} from "./siemImport.js";

type Row = Record<string, unknown>;

export interface CybertriageImportOptions {
  aggregate?: boolean;
  minSeverity?: Severity;
  maxEvents?: number;
  maxIocs?: number;
  fileTelemetry?: boolean;   // include unscored File (MFT) rows as Info evidence (default: false)
}

export interface CybertriageParseResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  total: number;      // rows found
  kept: number;       // events emitted (after aggregation + cap)
  dropped: number;    // rows not represented (file telemetry / port noise / below floor / capped)
  groups: number;     // distinct event groups before the cap
  notable: number;    // scored (Bad/Suspicious) rows seen
  format: string;     // "jsonl" | "array" | "csv" | "single" | "empty"
  hostname: string;
}

type Verdict = "bad" | "suspicious" | "none";
type Kind = "process" | "file" | "task" | "network" | "other";

// ───────────────────────────── verdict + severity ─────────────────────────────

// JSONL `score` is an enum (Notable_Normal = Bad, LikelyNotable_Normal = Suspicious); the CSV
// `threat_level` is "<verdict>. <reason>" ("Bad. Bad list item detected"). Normalize either, and
// recover the reason text (JSONL carries it separately as `scoreDescription`).
function readVerdict(rec: Row): { verdict: Verdict; reason: string } {
  const scoreDesc = str(getCI(rec, "scoreDescription")).trim();
  const score = str(getCI(rec, "score")).trim();

  if (score) {
    const s = score.toLowerCase();
    if (s === "none" || s === "" || s === "good" || s === "normal") return { verdict: "none", reason: scoreDesc };
    if (/likely/.test(s) && /notable/.test(s)) return { verdict: "suspicious", reason: scoreDesc };
    if (/notable/.test(s)) return { verdict: "bad", reason: scoreDesc };
    // CSV threat_level lands here ("Bad. …" / "Suspicious. …" / "Good. …").
    const dot = score.indexOf(".");
    const head = (dot >= 0 ? score.slice(0, dot) : score).toLowerCase();
    const tail = dot >= 0 ? score.slice(dot + 1).trim() : "";
    if (head === "bad") return { verdict: "bad", reason: scoreDesc || tail };
    if (head === "suspicious") return { verdict: "suspicious", reason: scoreDesc || tail };
    return { verdict: "none", reason: scoreDesc || tail };
  }
  return { verdict: "none", reason: scoreDesc };
}

// Known credential-dumping / ransomware wording in the verdict reason or the item → Critical. Reads
// the tool's OWN reason text, so it stays "consume the verdict, don't re-detect".
const CRIT_KEYWORDS = /lsass|mimikatz|credential|dump(?:ing)?\s+lsass|password|ransom|lockbit|black\s*suit|blacksuit|cobalt\s*strike|secretsdump|dcsync/i;
// Offensive tooling / remote-access wording → at least High even when only flagged Suspicious.
const HIGH_KEYWORDS = /remote\s*access\s*software|\bras\b|anydesk|teamviewer|\bpsexec\b|\bbeacon\b|meterpreter|reverse\s*shell|yara\s*pattern|web\s*shell|webshell|impacket|icedid|trickbot|qakbot|emotet/i;

function severityFor(verdict: Verdict, reason: string, item: string): Severity {
  if (verdict === "none") return "Info";
  const text = `${reason} ${item}`;
  if (CRIT_KEYWORDS.test(text)) return "Critical";
  if (verdict === "bad") return "High";
  if (HIGH_KEYWORDS.test(text)) return "High";
  return "Medium"; // Suspicious
}

// High-precision MITRE from the verdict reason / item (+ the record kind) — only the few we can
// claim with confidence; synthesis fills the rest.
function mitreFor(reason: string, item: string, kind: Kind): string[] {
  const t = `${reason} ${item}`.toLowerCase();
  const out = new Set<string>();
  if (/lsass|mimikatz|credential|dump.*password|secretsdump/.test(t)) out.add("T1003.001");
  if (/remote\s*access\s*software|\bras\b|anydesk|teamviewer/.test(t)) out.add("T1219");
  if (kind === "task" || /scheduled\s*task/.test(t)) out.add("T1053.005");
  if (/uac-bypass|uac\s*bypass/.test(t)) out.add("T1548.002");
  if (/masquerad/.test(t)) out.add("T1036");
  return [...out];
}

// ───────────────────────────── time / kind ─────────────────────────────

// Prefer the unambiguous epoch (seconds) over the naive `event_timestamp` string; either is the
// artifact's own time (Cyber Triage already reads the source artifact's time, not collection time).
function ctTime(rec: Row): string {
  const ep = getCI(rec, "epoch_timestamp");
  const n = typeof ep === "number" ? ep : Number(str(ep).trim());
  if (Number.isFinite(n) && n > 0) {
    const d = new Date(n > 1e12 ? n : n * 1000);
    if (!Number.isNaN(d.getTime())) return d.toISOString();
  }
  return normalizeTime(firstStr(rec, ["event_timestamp", "datetime"]));
}

function classify(rec: Row): Kind {
  const ct = str(getCI(rec, "ctType")).toLowerCase();
  if (ct === "process") return "process";
  if (ct === "configuration item") return "task";
  if (ct === "file") return "file";

  const td = firstStr(rec, ["timestamp_desc", "timestamp_description"]).toLowerCase();
  if (td.startsWith("process")) return "process";
  if (td.startsWith("task") || /\btask\b/.test(str(getCI(rec, "type")).toLowerCase())) return "task";
  if (td.startsWith("file")) return "file";
  if (/connection|port/.test(td)) return "network";

  const it = firstStr(rec, ["item_type", "threat_type"]).toLowerCase();
  if (it.includes("process")) return "process";
  if (it.includes("task")) return "task";
  if (it.includes("file")) return "file";
  return "other";
}

// ───────────────────────────── IOC harvesting ─────────────────────────────

const TEXT_URL = /\bhttps?:\/\/[^\s"'<>)\]}]+/gi;
const TEXT_IPV4 = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const TEXT_HASH = /\b[a-f0-9]{64}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{32}\b/gi;

function harvestText(text: string, sink: Map<string, SiemIoc>): void {
  if (!text) return;
  for (const m of text.matchAll(TEXT_URL)) addIoc(sink, "url", m[0].replace(/[.,;:)\]]+$/, "").slice(0, 300));
  for (const m of text.matchAll(TEXT_IPV4)) {
    const ip = cleanIp(m[0]);
    if (ip && !ip.startsWith("127.")) addIoc(sink, "ip", ip);
  }
  for (const m of text.matchAll(TEXT_HASH)) addIoc(sink, "hash", m[0].toLowerCase());
}

function looksLikePath(p: string): boolean {
  return /[\\/]/.test(p) && !/^https?:/i.test(p);
}
function addProc(sink: Map<string, SiemIoc>, name: string): string | undefined {
  const bn = baseName(name.trim());
  if (bn && /\.\w{2,4}$/.test(bn)) { addIoc(sink, "process", bn); return bn; }
  return undefined;
}

// The task action command (its executable + args) — from the structured `actions[]` (JSONL) or the
// `message` (which Cyber Triage already renders as the action command line).
function taskAction(rec: Row): string {
  const actions = getCI(rec, "actions");
  if (Array.isArray(actions) && actions.length && isObject(actions[0])) {
    const a = actions[0] as Row;
    const cmd = `${str(getCI(a, "path"))} ${str(getCI(a, "args"))}`.trim();
    if (cmd) return oneLine(cmd);
  }
  return oneLine(firstStr(rec, ["message"]));
}

// ───────────────────────────── per-row mapping ─────────────────────────────

function mapRow(rec: Row, kind: Kind, opts: CybertriageImportOptions, sink: Map<string, SiemIoc>): MappedEvent | null {
  const host = firstStr(rec, ["hostName", "Host DNS Name", "Host Display Name"]);
  const { verdict, reason } = readVerdict(rec);
  const message = oneLine(firstStr(rec, ["message"]));

  // Network: telemetry → IOC only (Active Connection carries "To <ip>:<port>"); never an event.
  if (kind === "network") { harvestText(message, sink); return null; }

  // Unscored File rows are the MFT super-timeline — dropped unless the analyst opts in.
  if (kind === "file" && verdict === "none" && !opts.fileTelemetry) return null;

  const path = firstStr(rec, ["path", "Source Paths"]) || (kind === "file" ? message : "");
  const displayName = firstStr(rec, ["displayName", "fileName", "name"]);
  const parentRaw = firstStr(rec, ["parentProcess", "parentPath"]);
  const args = str(getCI(rec, "args")).trim();
  const taskName = firstStr(rec, ["name"]);

  // IOCs (scored items + the process/task evidence we keep; not the bulk file telemetry).
  if (verdict !== "none" || kind !== "file") {
    if (path && looksLikePath(path)) addIoc(sink, "file", path.slice(0, 300));
    harvestText(`${message} ${args}`, sink);
  }
  let processName: string | undefined;
  let parentName: string | undefined;
  if (kind === "process") {
    processName = addProc(sink, displayName || path || message.split(/\s+/)[0] || "");
    if (parentRaw) parentName = baseName(parentRaw);
  } else if (kind === "task") {
    processName = addProc(sink, taskAction(rec).split(/\s+/)[0] || "");
  } else if (kind === "file") {
    addProc(sink, displayName || baseName(path));
  }

  const severity = severityFor(verdict, reason, `${message} ${path} ${args}`);
  const mitre = verdict === "none" ? [] : mitreFor(reason, `${message} ${path} ${args}`, kind);
  const tag = verdict === "bad" ? " [Bad]" : verdict === "suspicious" ? " [Suspicious]" : "";
  const lead = `Cyber Triage${tag}`;

  let subject: string;
  let aggSubject: string;
  if (kind === "process") {
    const proc = processName || baseName(path) || "process";
    subject = `${proc}${args ? ` ${oneLine(args).slice(0, 160)}` : (message.includes(" ") ? ` ${message.split(/\s+/).slice(1).join(" ").slice(0, 160)}` : "")}`.trim();
    aggSubject = `${proc}|${parentName ?? ""}`;
  } else if (kind === "task") {
    const action = taskAction(rec).slice(0, 200);
    subject = `scheduled task${taskName ? ` "${taskName}"` : ""}${action ? ` → ${action}` : ""}`;
    aggSubject = `${taskName ?? ""}|${action}`;
  } else { // file
    subject = path || message;
    aggSubject = (path || message);
  }

  const headline = verdict === "none"
    ? `${lead}: ${firstStr(rec, ["timestamp_desc", "timestamp_description"]) || "event"} — ${subject}`
    : `${lead}: ${reason || "notable item"} — ${subject}`;
  let description = headline;
  if (parentName) description += ` (parent ${parentName})`;
  if (host && !description.toLowerCase().includes(host.toLowerCase())) description += ` @ ${host}`;
  description = description.slice(0, 600);

  const aggKey = `ct|${kind}|${verdict}|${reason.toLowerCase()}|${aggSubject.toLowerCase()}`
    .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/g, "<guid>")
    .replace(/\d+/g, "#")
    .slice(0, 400);

  return {
    timestamp: ctTime(rec),
    description,
    severity,
    mitre,
    aggKey,
    sources: ["Cyber Triage"],
    ...(path && looksLikePath(path) ? { path } : {}),
    ...(host ? { asset: host } : {}),
    ...(processName ? { processName } : {}),
    ...(parentName ? { parentName } : {}),
  };
}

// ───────────────────────────── row extraction ─────────────────────────────

const CT_HEADERS = ["event_timestamp", "epoch_timestamp", "timestamp_description"];

// JSON/JSONL via the shared extractor; else the CSV timeline (header-detected). CSV rows are
// returned as plain objects so the one mapper handles both forms.
function extractRows(text: string): { rows: Row[]; format: string } {
  const trimmed = text.trim();
  if (!trimmed) return { rows: [], format: "empty" };

  if (trimmed[0] === "{" || trimmed[0] === "[") {
    const { records, format } = extractRecords(trimmed);
    if (records.length) return { rows: records, format: format === "ndjson" ? "jsonl" : format };
  } else if (trimmed.split(/\r\n|\r|\n/, 1)[0]?.trim().startsWith("{")) {
    const { records, format } = extractRecords(trimmed);
    if (records.length) return { rows: records, format: format === "ndjson" ? "jsonl" : format };
  }

  // CSV timeline.
  const { headers, rows } = parseCsv(text);
  const hset = new Set(headers.map((h) => h.trim().toLowerCase()));
  if (!CT_HEADERS.every((h) => hset.has(h))) return { rows: [], format: "empty" };
  const objs: Row[] = rows.map((cols) => {
    const o: Row = {};
    headers.forEach((h, i) => { o[h.trim()] = cols[i] ?? ""; });
    // Fold the CSV's `threat_level` into `score` so readVerdict sees one field.
    if (o.threat_level != null) o.score = o.threat_level;
    return o;
  });
  return { rows: objs, format: "csv" };
}

// ───────────────────────────── top-level parse ─────────────────────────────

export function parseCybertriage(text: string, opts: CybertriageImportOptions = {}): CybertriageParseResult {
  const maxIocs = opts.maxIocs ?? 5000;
  const { rows, format } = extractRows(text);
  const total = rows.length;
  if (total === 0) {
    return { events: [], iocs: [], total: 0, kept: 0, dropped: 0, groups: 0, notable: 0, format: "empty", hostname: "" };
  }

  const sink = new Map<string, SiemIoc>();
  const hostTally = new Map<string, number>();
  const mapped: MappedEvent[] = [];
  let notable = 0;

  for (const rec of rows) {
    const host = firstStr(rec, ["hostName", "Host DNS Name", "Host Display Name"]);
    if (host) hostTally.set(host, (hostTally.get(host) ?? 0) + 1);
    if (readVerdict(rec).verdict !== "none") notable++;
    const m = mapRow(rec, classify(rec), opts, sink);
    if (m) mapped.push(m);
  }

  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? 2000,
  });

  const represented = events.reduce((n, e) => n + (e.count ?? 1), 0);
  const hostname = [...hostTally.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] ?? "";

  return {
    events,
    iocs: [...sink.values()].slice(0, maxIocs),
    total,
    kept: events.length,
    dropped: Math.max(0, total - represented),
    groups,
    notable,
    format,
    hostname,
  };
}
