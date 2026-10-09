// Deterministic importer for THOR (Nextron) scanner results in JSON-Lines format
// (`thor --jsonfile`). Each line is one finding/event with stable fields: `time`,
// `hostname`, `level` (Alert|Warning|Notice|Info), `module`, `message`, `score`, plus
// finding-specific fields (process/file/hashes/rule reasons). We map findings straight
// to forensic events + IOCs WITHOUT an AI call — the schema is rich and stable.
//
// THOR emits a lot of scan-lifecycle/info chatter (the first ~hundred lines are module
// init/startup). By default we drop those: `level: "Info"` and the lifecycle modules
// below. Only scored findings (Alert/Warning/Notice from real scan modules) survive.

import { SEVERITY_RANK, type Severity } from "./stateTypes.js";
import { maxEventsDefault } from "./siemImport.js";
import { isDetectionToolLocation } from "./veloDetectionNoise.js";
import { createDecisionTally, type ImportDebugRecorder } from "./rowDecisionDebug.js";
import { contentMismatch } from "./thorRowMap.js";

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
  // Safety cap on emitted events. Default 2000 (overridable via DFIR_MAX_EVENTS).
  maxEvents?: number;
  debug?: ImportDebugRecorder; // this attempt's decision recorder (#1736)
}

// A delta-shaped forensic event (matches deltaSchema.forensicEvents), produced deterministically.
export interface ThorEvent {
  id: string; // assigned by the caller's idPrefix; left as a stable local key here
  timestamp: string;
  description: string;
  severity: Severity;
  mitreTechniques: string[];
  count?: number; // when identical findings were collapsed
  endTimestamp?: string;
  sha256?: string; // correlation keys — let the same artifact match across tools
  md5?: string;
  path?: string;
  asset?: string; // the scanned host this finding came from
  sources?: string[];
  processName?: string; // for parent→child chain validation (ProcessCheck rows)
  parentName?: string;
}

export interface ThorIoc {
  type: "ip" | "domain" | "hash" | "file" | "process" | "url" | "sid" | "other";
  value: string;
}

export interface ThorParseResult {
  events: ThorEvent[];
  iocs: ThorIoc[];
  total: number; // total JSON lines parsed
  kept: number; // findings kept after filtering
  dropped: number; // rows dropped (info / lifecycle / unparseable)
  hostname: string; // best-effort scanned host
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
//
// A file inside an archive has no `created` of its own, only the archive entry's `modified` — the
// time the file had where the archive was built. Mimikatz's 2013 build time came through that way and
// dated the hit nine years before the intrusion (#1603). `archive_created` is the containing
// archive's own creation time on the scanned host, so it outranks the member's inherited `modified`.
const TIME_KEYS = ["created", "archive_created", "modified", "log_modified", "log_created", "time"];
function pickTimestamp(row: Row): string {
  return firstStr(row, TIME_KEYS);
}
// The key pickTimestamp read (#1736), for the import debug record. Key names only.
function timestampKey(row: Row): string {
  return TIME_KEYS.find((k) => str(row[k]).trim()) ?? "";
}

// Pull MITRE technique ids out of THOR tag/class fields (e.g. "ATTACK.T1059").
function pickTechniques(row: Row): string[] {
  const blob = [row.tags_1, row.tags_2, row.sigclass_1, row.sigclass_2, row.ref_1, row.ref_2]
    .map(str)
    .join(" ");
  const ids = new Set<string>();
  for (const m of blob.matchAll(/\bT\d{4}(?:\.\d{3})?\b/gi)) ids.add(m[0].toUpperCase());
  return [...ids];
}

// Build a concise, self-describing event description from a THOR finding row.
function describe(row: Row): string {
  const level = str(row.level) || "Finding";
  const module = str(row.module) || "THOR";
  const message = str(row.message) || "THOR finding";
  const subject = firstStr(row, [
    "process_name",
    "image_file",
    "file",
    "filename",
    "path",
    "entry",
    "command",
  ]);
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

const HASH_KEYS = [
  "sha256",
  "image_sha256",
  "archive_sha256",
  "sha1",
  "image_sha1",
  "md5",
  "image_md5",
  "sha256_1",
  "sha256_2",
  "md5_1",
  "sha1_1",
];
const FILE_KEYS = ["file", "image_file", "filepath", "path", "image_path", "archive_file"];

function collectIocs(row: Row, sink: Map<string, ThorIoc>): void {
  const add = (type: ThorIoc["type"], value: string) => {
    const v = value.trim();
    if (v && !sink.has(`${type}:${v.toLowerCase()}`))
      sink.set(`${type}:${v.toLowerCase()}`, { type, value: v });
  };
  for (const k of HASH_KEYS) {
    const v = str(row[k]).trim();
    if (/^[a-f0-9]{32,64}$/i.test(v)) add("hash", v);
  }
  for (const k of FILE_KEYS) {
    const v = str(row[k]).trim();
    if (v) add("file", v);
  }
  const proc = str(row.process_name).trim();
  if (proc) add("process", proc);
  for (const k of ["ip", "rip"]) {
    const v = str(row[k]).trim();
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(v)) add("ip", v);
  }
}

// Parse a THOR JSON-Lines report into forensic events + IOCs, dropping scan noise.
export function parseThorReport(jsonText: string, opts: ThorImportOptions = {}): ThorParseResult {
  const dropInfo = opts.dropInfo ?? true;
  const dropLifecycle = opts.dropLifecycleModules ?? true;
  const maxEvents = opts.maxEvents ?? maxEventsDefault();

  const lines = jsonText
    .split(/\r\n|\r|\n/)
    .map((l) => l.trim())
    .filter(Boolean);
  let total = 0;
  let dropped = 0;
  let hostname = "";
  const iocSink = new Map<string, ThorIoc>();
  // Dedup identical findings (same module/message/subject/rule), accumulating a count.
  const bySig = new Map<string, ThorEvent>();
  const order: string[] = [];
  const tally = opts.debug ? createDecisionTally() : undefined;

  // A line holding a non-empty JSON array of findings (e.g. a /push body's `events` array, sent as
  // one line) is its findings, one per element; every other line is one value.
  const values: unknown[] = [];
  for (const line of lines) {
    try {
      const parsed: unknown = JSON.parse(line);
      if (Array.isArray(parsed) && parsed.length > 0) values.push(...parsed);
      else values.push(parsed);
    } catch {
      dropped++;
      tally?.skipped.add("unparseable_json");
    }
  }

  for (const parsed of values) {
    // #2062: a THOR finding is a JSON object. `null` used to throw and abort the whole file, and
    // arrays/scalars/`{}` became phantom "THOR finding" events — drop them like unparseable lines.
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      dropped++;
      tally?.skipped.add("not_an_object");
      continue;
    }
    if (Object.keys(parsed).length === 0) {
      dropped++;
      tally?.skipped.add("empty_row");
      continue;
    }
    const row = parsed as Row;
    total++;
    if (!hostname) hostname = str(row.hostname);

    const level = str(row.level);
    const module = str(row.module);
    if (dropInfo && level === "Info") {
      dropped++;
      tally?.skipped.add("info_level");
      continue;
    }
    if (opts.minLevel && levelRank(level) < LEVEL_RANK[opts.minLevel]) {
      dropped++;
      tally?.skipped.add("below_min_level");
      continue;
    }
    if (dropLifecycle && LIFECYCLE_MODULES.has(module)) {
      dropped++;
      tally?.skipped.add("lifecycle_module");
      continue;
    }

    let severity = LEVEL_SEVERITY[level] ?? "Medium";
    const timestamp = pickTimestamp(row);
    // Content vs name (#1966): graded before the self-scan demote below, so that demote still wins.
    const mismatch = contentMismatch(row, severity);
    if (mismatch) severity = mismatch.severity;
    const description = mismatch
      ? `${describe(row).slice(0, 599 - mismatch.note.length)} ${mismatch.note}`
      : describe(row);
    const sig = [
      module,
      str(row.message),
      firstStr(row, ["process_name", "image_file", "file", "entry"]),
      firstStr(row, ["rulename_1", "matched_1", "reason_1"]),
    ]
      .join("|")
      .toLowerCase();

    const sha256 =
      firstStr(row, ["sha256", "image_sha256", "archive_sha256", "sha256_1"]).toLowerCase() || undefined;
    const md5 = firstStr(row, ["md5", "image_md5", "archive_md5", "md5_1"]).toLowerCase() || undefined;
    const path = (
      firstStr(row, ["file", "image_file", "image_path", "filepath", "path"]) || undefined
    )?.trim();
    // ProcessCheck rows carry the process + parent (a path) — capture both as basenames
    // so parent→child chain validation (RockyRaccoon) can run on the event.
    const baseName = (s: string): string => s.trim().split(/[\\/]/).pop() || s.trim();
    const processName = firstStr(row, ["process_name", "image_name"])
      ? baseName(firstStr(row, ["process_name", "image_name"]))
      : undefined;
    const parentName = firstStr(row, ["parent"]) ? baseName(firstStr(row, ["parent"])) : undefined;

    // Self-scan protection. THOR scans the whole disk, so it flags the DFIR collector itself
    // (`Velociraptor.exe` → "Malicious process, YARA rule PSAttack_EXE"), the rule trees and
    // EVTX-ATTACK sample corpus the collector unpacked into its Tools dir, and a cached copy of the
    // simulation repo — all as Critical/High. None is the intrusion. Demote to Info when the FLAGGED
    // artifact's own path or process is a detection-tooling LOCATION (never a bare filename — see
    // isDetectionToolLocation). Reuses the same predicate the Velociraptor YARA path uses.
    const flaggedLoc =
      firstStr(row, ["process_name", "image_name", "image_path", "image_file", "file", "path"]) ||
      (path ?? "");
    if (severity !== "Info" && (isDetectionToolLocation(flaggedLoc) || isDetectionToolLocation(path ?? ""))) {
      severity = "Info";
      tally?.observed.add("detection_tool_location");
    }

    const host = str(row.hostname).trim() || hostname;
    if (tally) {
      const timeKey = timestampKey(row);
      if (timeKey) tally.fields.add("timestamp", timeKey);
      else tally.observed.add("empty_timestamp");
      if (str(row.hostname).trim()) tally.fields.add("host", "hostname");
      else tally.observed.add(host ? "host_from_earlier_row" : "missing_host");
    }

    const existing = bySig.get(sig);
    if (existing) {
      existing.count = (existing.count ?? 1) + 1;
      if (timestamp && (!existing.endTimestamp || timestamp > existing.endTimestamp))
        existing.endTimestamp = timestamp;
      if (timestamp && timestamp < existing.timestamp) existing.timestamp = timestamp;
      if (!existing.asset && host) existing.asset = host;
      tally?.omitted.add("aggregated");
    } else {
      bySig.set(sig, {
        id: "",
        timestamp,
        description,
        severity,
        mitreTechniques: pickTechniques(row),
        ...(sha256 && /^[a-f0-9]{64}$/.test(sha256) ? { sha256 } : {}),
        ...(md5 && /^[a-f0-9]{32}$/.test(md5) ? { md5 } : {}),
        ...(path ? { path } : {}),
        ...(host ? { asset: host } : {}),
        ...(processName ? { processName } : {}),
        ...(parentName ? { parentName } : {}),
        sources: ["THOR"],
      });
      order.push(sig);
    }
    collectIocs(row, iocSink);
  }

  // Most-severe first, then keep input order; cap for safety.
  const events = order.map((s) => bySig.get(s)!);
  events.sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]);
  const capped = events.slice(0, maxEvents);
  tally?.omitted.add("over_event_cap", events.length - capped.length);
  tally?.flush(opts.debug);

  return {
    events: capped,
    iocs: [...iocSink.values()],
    total,
    kept: capped.length,
    dropped,
    hostname,
  };
}
