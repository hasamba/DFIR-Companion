// Deterministic importer for THOR (Nextron) scanner results in JSON-Lines format
// (`thor --jsonfile`). Each line is one finding/event with stable fields: `time`,
// `hostname`, `level` (Alert|Warning|Notice|Info), `module`, `message`, `score`, plus
// finding-specific fields (process/file/hashes/rule reasons). We map findings straight
// to forensic events + IOCs WITHOUT an AI call — the schema is rich and stable.
//
// THOR emits a lot of scan-lifecycle/info chatter (the first ~hundred lines are module
// init/startup). By default we drop those: `level: "Info"` and the lifecycle modules
// below. Only scored findings (Alert/Warning/Notice from real scan modules) survive.

import type { Severity } from "./stateTypes.js";

// Modules that report scan lifecycle / app status, not host findings — dropped by default.
const LIFECYCLE_MODULES = new Set(["Init", "Startup", "Control", "ThorDB", "Report"]);

// THOR level → our severity.
const LEVEL_SEVERITY: Record<string, Severity> = {
  Alert: "Critical",
  Warning: "High",
  Notice: "Medium",
  Info: "Info",
};

// THOR level ordering (higher = more severe) for the minLevel floor.
export type ThorLevel = "Alert" | "Warning" | "Notice";
const LEVEL_RANK: Record<string, number> = { Alert: 3, Warning: 2, Notice: 1, Info: 0 };
const levelRank = (level: string): number => LEVEL_RANK[level] ?? 1;

export interface ThorImportOptions {
  // Drop `level: "Info"` rows (scan progress / informational). Default true.
  dropInfo?: boolean;
  // Drop lifecycle/app-status modules (Init, Startup, Control, ThorDB, Report). Default true.
  dropLifecycleModules?: boolean;
  // Minimum THOR level to import. "Notice" keeps Alert+Warning+Notice (default), "Warning"
  // drops Notice, "Alert" keeps only Alerts. Independent of dropInfo (Info is below Notice).
  minLevel?: ThorLevel;
  // Safety cap on emitted events (most-severe kept first). Default 2000.
  maxEvents?: number;
}

// A delta-shaped forensic event (matches deltaSchema.forensicEvents), produced deterministically.
export interface ThorEvent {
  id: string;            // assigned by the caller's idPrefix; left as a stable local key here
  timestamp: string;
  description: string;
  severity: Severity;
  mitreTechniques: string[];
  count?: number;        // when identical findings were collapsed
  endTimestamp?: string;
  sha256?: string;       // correlation keys — let the same artifact match across tools
  md5?: string;
  path?: string;
  sources?: string[];
  processName?: string;  // for parent→child chain validation (ProcessCheck rows)
  parentName?: string;
}

export interface ThorIoc {
  type: "ip" | "domain" | "hash" | "file" | "process" | "url" | "other";
  value: string;
}

export interface ThorParseResult {
  events: ThorEvent[];
  iocs: ThorIoc[];
  total: number;         // total JSON lines parsed
  kept: number;          // findings kept after filtering
  dropped: number;       // rows dropped (info / lifecycle / unparseable)
  hostname: string;      // best-effort scanned host
}

type Row = Record<string, unknown>;

function str(v: unknown): string {
  return typeof v === "string" ? v : v == null ? "" : String(v);
}
function firstStr(row: Row, keys: string[]): string {
  for (const k of keys) {
    const v = str(row[k]).trim();
    if (v) return v;
  }
  return "";
}

// The artifact's own incident time when available (process create, file mtime…),
// falling back to the THOR scan time. Never the current time.
function pickTimestamp(row: Row): string {
  return firstStr(row, ["created", "modified", "log_modified", "log_created", "time"]);
}

// Pull MITRE technique ids out of THOR tag/class fields (e.g. "ATTACK.T1059").
function pickTechniques(row: Row): string[] {
  const blob = [row.tags_1, row.tags_2, row.sigclass_1, row.sigclass_2, row.ref_1, row.ref_2]
    .map(str).join(" ");
  const ids = new Set<string>();
  for (const m of blob.matchAll(/\bT\d{4}(?:\.\d{3})?\b/gi)) ids.add(m[0].toUpperCase());
  return [...ids];
}

// Build a concise, self-describing event description from a THOR finding row.
function describe(row: Row): string {
  const level = str(row.level) || "Finding";
  const module = str(row.module) || "THOR";
  const message = str(row.message) || "THOR finding";
  const subject = firstStr(row, ["process_name", "image_file", "file", "filename", "path", "entry", "command"]);
  const owner = firstStr(row, ["owner", "user", "image_owner"]);
  const reasons = [str(row.reason_1), str(row.reason_2)].filter(Boolean).join("; ");
  const rule = firstStr(row, ["rulename_1", "matched_1", "ref_1"]);

  let d = `THOR ${level} [${module}]: ${message}`;
  if (subject) d += ` — ${subject.replace(/\r?\n/g, " ").trim()}`;
  if (owner) d += ` (owner: ${owner})`;
  const why = reasons || rule;
  if (why) d += ` | ${why.replace(/\r?\n/g, " ").trim()}`;
  return d.slice(0, 600);
}

const HASH_KEYS = ["sha256", "image_sha256", "archive_sha256", "sha1", "image_sha1", "md5", "image_md5",
  "sha256_1", "sha256_2", "md5_1", "sha1_1"];
const FILE_KEYS = ["file", "image_file", "filepath", "path", "image_path", "archive_file"];

function collectIocs(row: Row, sink: Map<string, ThorIoc>): void {
  const add = (type: ThorIoc["type"], value: string) => {
    const v = value.trim();
    if (v && !sink.has(`${type}:${v.toLowerCase()}`)) sink.set(`${type}:${v.toLowerCase()}`, { type, value: v });
  };
  for (const k of HASH_KEYS) { const v = str(row[k]).trim(); if (/^[a-f0-9]{32,64}$/i.test(v)) add("hash", v); }
  for (const k of FILE_KEYS) { const v = str(row[k]).trim(); if (v) add("file", v); }
  const proc = str(row.process_name).trim();
  if (proc) add("process", proc);
  for (const k of ["ip", "rip"]) { const v = str(row[k]).trim(); if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(v)) add("ip", v); }
}

const SEVERITY_RANK: Record<Severity, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };

// Parse a THOR JSON-Lines report into forensic events + IOCs, dropping scan noise.
export function parseThorReport(jsonText: string, opts: ThorImportOptions = {}): ThorParseResult {
  const dropInfo = opts.dropInfo ?? true;
  const dropLifecycle = opts.dropLifecycleModules ?? true;
  const maxEvents = opts.maxEvents ?? 2000;

  const lines = jsonText.split(/\r\n|\r|\n/).map((l) => l.trim()).filter(Boolean);
  let total = 0;
  let dropped = 0;
  let hostname = "";
  const iocSink = new Map<string, ThorIoc>();
  // Dedup identical findings (same module/message/subject/rule), accumulating a count.
  const bySig = new Map<string, ThorEvent>();
  const order: string[] = [];

  for (const line of lines) {
    let row: Row;
    try { row = JSON.parse(line) as Row; } catch { dropped++; continue; }
    total++;
    if (!hostname) hostname = str(row.hostname);

    const level = str(row.level);
    const module = str(row.module);
    if (dropInfo && level === "Info") { dropped++; continue; }
    if (opts.minLevel && levelRank(level) < LEVEL_RANK[opts.minLevel]) { dropped++; continue; }
    if (dropLifecycle && LIFECYCLE_MODULES.has(module)) { dropped++; continue; }

    const severity = LEVEL_SEVERITY[level] ?? "Medium";
    const timestamp = pickTimestamp(row);
    const description = describe(row);
    const sig = [module, str(row.message), firstStr(row, ["process_name", "image_file", "file", "entry"]),
      firstStr(row, ["rulename_1", "matched_1", "reason_1"])].join("|").toLowerCase();

    const sha256 = firstStr(row, ["sha256", "image_sha256", "archive_sha256", "sha256_1"]).toLowerCase() || undefined;
    const md5 = firstStr(row, ["md5", "image_md5", "archive_md5", "md5_1"]).toLowerCase() || undefined;
    const path = (firstStr(row, ["file", "image_file", "image_path", "filepath", "path"]) || undefined)?.trim();
    // ProcessCheck rows carry the process + parent (a path) — capture both as basenames
    // so parent→child chain validation (RockyRaccoon) can run on the event.
    const baseName = (s: string): string => s.trim().split(/[\\/]/).pop() || s.trim();
    const processName = firstStr(row, ["process_name", "image_name"]) ? baseName(firstStr(row, ["process_name", "image_name"])) : undefined;
    const parentName = firstStr(row, ["parent"]) ? baseName(firstStr(row, ["parent"])) : undefined;

    const existing = bySig.get(sig);
    if (existing) {
      existing.count = (existing.count ?? 1) + 1;
      if (timestamp && (!existing.endTimestamp || timestamp > existing.endTimestamp)) existing.endTimestamp = timestamp;
      if (timestamp && timestamp < existing.timestamp) existing.timestamp = timestamp;
    } else {
      bySig.set(sig, {
        id: "", timestamp, description, severity, mitreTechniques: pickTechniques(row),
        ...(sha256 && /^[a-f0-9]{64}$/.test(sha256) ? { sha256 } : {}),
        ...(md5 && /^[a-f0-9]{32}$/.test(md5) ? { md5 } : {}),
        ...(path ? { path } : {}),
        ...(processName ? { processName } : {}),
        ...(parentName ? { parentName } : {}),
        sources: ["THOR"],
      });
      order.push(sig);
    }
    collectIocs(row, iocSink);
  }

  // Most-severe first, then keep input order; cap for safety.
  let events = order.map((s) => bySig.get(s)!);
  events.sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]);
  const capped = events.slice(0, maxEvents);

  return {
    events: capped,
    iocs: [...iocSink.values()],
    total,
    kept: capped.length,
    dropped,
    hostname,
  };
}
