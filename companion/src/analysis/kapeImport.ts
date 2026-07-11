// Deterministic importer for KAPE / Eric Zimmerman (EZ) Tools CSV output — the host-forensics
// counterpart to the EDR/network connectors. The seventh deterministic ingest path; no AI call.
//
// EZ tools each emit a CSV with the artifact's own columns and time field(s). A KAPE collection
// is a folder of these; the analyst uploads one CSV per import. This module DETECTS which tool
// produced the CSV from its header, then maps each row to a forensic event reading the
// artifact's OWN time (program last-run, file MAC time, deletion time…) and pulling file/hash/
// process IOCs. These are EVIDENCE rows (no maliciousness verdict), so severity is Info — their
// value is the super-timeline + cross-source correlation; synthesis + the high-severity backfill
// still escalate anything that lines up with a real detection.
//
// Supported artifacts (header-detected): Prefetch (PECmd), Amcache (AmcacheParser), AppCompatCache/
// ShimCache (AppCompatCacheParser), LNK (LECmd), JumpLists (JLECmd), UsnJrnl $J + $MFT (MFTECmd),
// SRUM network usage (SrumECmd), Recycle Bin (RBCmd), Shellbags (SBECmd).

import type { Severity } from "./stateTypes.js";
import { parseCsv } from "./csvImport.js";
import {
  aggregateEvents,
  addIoc,
  firstStr,
  baseName,
  oneLine,
  str,
  getCI,
  normalizeTime,
  type MappedEvent,
  type SiemEvent,
  type SiemIoc,
} from "./siemImport.js";

type Row = Record<string, unknown>;

export interface KapeImportOptions {
  aggregate?: boolean;
  minSeverity?: Severity;
  maxEvents?: number;
  maxIocs?: number;
}

export interface KapeParseResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  total: number;    // data rows in the CSV
  kept: number;     // events emitted (after aggregation + cap)
  dropped: number;  // rows not represented (no usable time/path / capped)
  groups: number;   // distinct event groups before the cap
  artifact: string; // detected EZ artifact ("Prefetch", "Amcache", …) or "unknown"
  format: string;   // = artifact, for parity with the other importers
}

// ───────────────────────────── helpers ─────────────────────────────

// EZ timestamps are UTC "yyyy-MM-dd HH:mm:ss(.fffffff)" (no zone). Truncate the 7-digit
// fraction to ms, drop the .NET min-date sentinel, then normalize (treats naive as UTC).
function ezTime(v: unknown): string {
  let t = str(v).trim();
  if (!t || t.startsWith("0001-01-01") || t.startsWith("1601-01-01")) return "";
  t = t.replace(/(\.\d{3})\d+/, "$1");
  return normalizeTime(t);
}

const HASH40 = /[a-f0-9]{40}/i;
function addHash(sink: Map<string, SiemIoc>, raw: string): void {
  const m = HASH40.exec(raw.trim()); // Amcache SHA1 sometimes carries a leading "0000" prefix
  if (m) addIoc(sink, "hash", m[0].toLowerCase());
  else { const h = raw.trim().toLowerCase(); if (/^[a-f0-9]{32}$|^[a-f0-9]{64}$/.test(h)) addIoc(sink, "hash", h); }
}
function addFile(sink: Map<string, SiemIoc>, p: string): void {
  const v = p.trim();
  if (v && v !== "-" && /[\\/]/.test(v)) addIoc(sink, "file", v.slice(0, 300));
}
function addProc(sink: Map<string, SiemIoc>, name: string): string | undefined {
  const bn = baseName(name.trim());
  if (bn && /\.\w{2,4}$/.test(bn)) { addIoc(sink, "process", bn); return bn; }
  return undefined;
}
function truthy(v: unknown): boolean {
  return /^(yes|true|1)$/i.test(str(v).trim());
}

// ───────────────────────────── artifact profiles ─────────────────────────────

interface Profile {
  name: string;
  match: (h: Set<string>) => boolean;
  map: (row: Row, sink: Map<string, SiemIoc>) => MappedEvent | null;
}

const has = (h: Set<string>, ...keys: string[]): boolean => keys.every((k) => h.has(k.toLowerCase()));

const PROFILES: Profile[] = [
  {
    name: "Prefetch",
    match: (h) => has(h, "ExecutableName", "RunCount") && (h.has("lastrun") || h.has("sourcefilename")),
    map: (row, sink) => {
      const exe = firstStr(row, ["ExecutableName"]);
      if (!exe) return null;
      const runCount = firstStr(row, ["RunCount"]);
      const proc = addProc(sink, exe);
      const time = ezTime(getCI(row, "LastRun")) || ezTime(getCI(row, "SourceModified"));
      return {
        timestamp: time,
        description: `Prefetch: ${exe} executed${runCount ? ` (run ${runCount}×)` : ""}`.slice(0, 600),
        severity: "Info", mitre: [], aggKey: `pf|${exe.toLowerCase()}`,
        sources: ["Prefetch"], ...(proc ? { processName: proc } : {}),
      };
    },
  },
  {
    name: "Amcache",
    match: (h) => has(h, "FullPath", "SHA1") || has(h, "FullPath", "FileKeyLastWriteTimestamp"),
    map: (row, sink) => {
      const path = firstStr(row, ["FullPath"]);
      if (!path) return null;
      const sha1 = firstStr(row, ["SHA1"]);
      if (sha1) addHash(sink, sha1);
      addFile(sink, path);
      const proc = addProc(sink, path);
      return {
        timestamp: ezTime(getCI(row, "FileKeyLastWriteTimestamp")),
        description: `Amcache: ${path}${sha1 ? ` (SHA1 ${sha1.replace(/^0+/, "").slice(0, 40)})` : ""}`.slice(0, 600),
        severity: "Info", mitre: [], aggKey: `amcache|${path.toLowerCase()}`,
        sources: ["Amcache"], path, ...(proc ? { processName: proc } : {}),
      };
    },
  },
  {
    name: "ShimCache",
    match: (h) => has(h, "Path", "LastModifiedTimeUTC") && (h.has("executed") || h.has("cacheentryposition")),
    map: (row, sink) => {
      const path = firstStr(row, ["Path"]);
      if (!path) return null;
      addFile(sink, path);
      const proc = addProc(sink, path);
      const executed = truthy(getCI(row, "Executed"));
      return {
        timestamp: ezTime(getCI(row, "LastModifiedTimeUTC")),
        description: `ShimCache: ${path}${executed ? " (Executed)" : ""}`.slice(0, 600),
        severity: "Info", mitre: [], aggKey: `shim|${path.toLowerCase()}`,
        sources: ["ShimCache"], path, ...(proc ? { processName: proc } : {}),
      };
    },
  },
  {
    name: "LNK",
    match: (h) => has(h, "TargetCreated", "Arguments") && (h.has("localpath") || h.has("relativepath")),
    map: (row, sink) => {
      const target = firstStr(row, ["LocalPath", "RelativePath"]);
      const src = firstStr(row, ["SourceFile"]);
      const args = firstStr(row, ["Arguments"]);
      if (!target && !src) return null;
      if (target) addFile(sink, target);
      return {
        timestamp: ezTime(getCI(row, "TargetModified")) || ezTime(getCI(row, "TargetCreated")) || ezTime(getCI(row, "SourceModified")),
        description: `LNK: ${baseName(src) || "shortcut"} → ${target || "?"}${args ? ` ${oneLine(args).slice(0, 120)}` : ""}`.slice(0, 600),
        severity: "Info", mitre: [], aggKey: `lnk|${(src || target).toLowerCase()}`,
        sources: ["LNK"], ...(target ? { path: target } : {}),
      };
    },
  },
  {
    name: "JumpLists",
    match: (h) => has(h, "AppId", "Path") && h.has("targetcreated"),
    map: (row, sink) => {
      const path = firstStr(row, ["Path"]);
      const app = firstStr(row, ["AppIdDescription", "AppId"]);
      if (!path) return null;
      addFile(sink, path);
      return {
        timestamp: ezTime(getCI(row, "TargetModified")) || ezTime(getCI(row, "TargetCreated")),
        description: `JumpList: ${app || "?"} → ${path}`.slice(0, 600),
        severity: "Info", mitre: [], aggKey: `jl|${app.toLowerCase()}|${path.toLowerCase()}`,
        sources: ["JumpLists"], path,
      };
    },
  },
  {
    name: "UsnJrnl",
    match: (h) => has(h, "UpdateReasons", "UpdateTimestamp"),
    map: (row, sink) => {
      const name = firstStr(row, ["Name"]);
      const reasons = firstStr(row, ["UpdateReasons"]);
      if (!name) return null;
      const proc = addProc(sink, name);
      return {
        timestamp: ezTime(getCI(row, "UpdateTimestamp")),
        description: `UsnJrnl: ${name} — ${reasons}`.slice(0, 600),
        severity: "Info", mitre: [], aggKey: `usn|${name.toLowerCase()}|${reasons.toLowerCase()}`,
        sources: ["UsnJrnl"], ...(proc ? { processName: proc } : {}),
      };
    },
  },
  {
    name: "MFT",
    match: (h) => has(h, "ParentPath", "FileName") && (h.has("created0x10") || h.has("lastmodified0x10")),
    map: (row, sink) => {
      if (truthy(getCI(row, "IsDirectory"))) return null; // files only — directories are noise
      const parent = firstStr(row, ["ParentPath"]);
      const fileName = firstStr(row, ["FileName"]);
      if (!fileName) return null;
      const path = (parent ? `${parent.replace(/[\\/]+$/, "")}\\` : "") + fileName;
      addFile(sink, path);
      const proc = addProc(sink, fileName);
      const size = firstStr(row, ["FileSize"]);
      return {
        timestamp: ezTime(getCI(row, "Created0x10")) || ezTime(getCI(row, "LastModified0x10")),
        description: `MFT: ${path}${size ? ` (${size} bytes)` : ""}`.slice(0, 600),
        severity: "Info", mitre: [], aggKey: `mft|${path.toLowerCase()}`,
        sources: ["MFT"], path, ...(proc ? { processName: proc } : {}),
      };
    },
  },
  {
    name: "SRUM",
    match: (h) => has(h, "BytesSent", "BytesReceived"),
    map: (row, sink) => {
      const exe = firstStr(row, ["ExeInfo", "AppId", "Application"]);
      if (!exe) return null;
      const proc = addProc(sink, exe);
      const sent = firstStr(row, ["BytesSent"]);
      const recv = firstStr(row, ["BytesReceived"]);
      return {
        timestamp: ezTime(getCI(row, "Timestamp")),
        description: `SRUM network: ${baseName(exe)} sent ${sent || "?"} / recv ${recv || "?"} bytes`.slice(0, 600),
        severity: "Info", mitre: [], aggKey: `srum|${exe.toLowerCase()}`,
        sources: ["SRUM"], ...(proc ? { processName: proc } : {}),
      };
    },
  },
  {
    name: "RecycleBin",
    match: (h) => has(h, "DeletedOn", "FileName") && h.has("filesize"),
    map: (row, sink) => {
      const file = firstStr(row, ["FileName"]);
      if (!file) return null;
      addFile(sink, file);
      return {
        timestamp: ezTime(getCI(row, "DeletedOn")),
        description: `RecycleBin: deleted ${file}`.slice(0, 600),
        severity: "Info", mitre: [], aggKey: `rb|${file.toLowerCase()}`,
        sources: ["RecycleBin"], path: file,
      };
    },
  },
  {
    name: "Shellbags",
    match: (h) => has(h, "AbsolutePath") && (h.has("lastinteracted") || h.has("firstinteracted")),
    map: (row, sink) => {
      const path = firstStr(row, ["AbsolutePath"]);
      if (!path) return null;
      addFile(sink, path);
      return {
        timestamp: ezTime(getCI(row, "LastInteracted")) || ezTime(getCI(row, "FirstInteracted")),
        description: `Shellbag: ${path}`.slice(0, 600),
        severity: "Info", mitre: [], aggKey: `sb|${path.toLowerCase()}`,
        sources: ["Shellbags"], path,
      };
    },
  },
];

function detectProfile(headers: string[]): Profile | null {
  const set = new Set(headers.map((h) => h.trim().toLowerCase()));
  for (const p of PROFILES) if (p.match(set)) return p;
  return null;
}

// ───────────────────────────── top-level parse ─────────────────────────────

export function parseKapeCsv(text: string, opts: KapeImportOptions = {}): KapeParseResult {
  const maxIocs = opts.maxIocs ?? 5000;
  const { headers, rows } = parseCsv(text);
  const profile = headers.length ? detectProfile(headers) : null;
  if (!profile) {
    return { events: [], iocs: [], total: rows.length, kept: 0, dropped: rows.length, groups: 0, artifact: "unknown", format: "unknown" };
  }

  const iocSink = new Map<string, SiemIoc>();
  const mapped: MappedEvent[] = [];
  for (const cols of rows) {
    const row: Row = {};
    headers.forEach((h, i) => { row[h.trim()] = cols[i] ?? ""; });
    const m = profile.map(row, iocSink);
    if (m) mapped.push(m);
  }

  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? (Number(process.env.DFIR_MAX_EVENTS) || 2000),
  });

  const represented = events.reduce((n, e) => n + (e.count ?? 1), 0);
  return {
    events,
    iocs: [...iocSink.values()].slice(0, maxIocs),
    total: rows.length,
    kept: events.length,
    dropped: Math.max(0, rows.length - represented),
    groups,
    artifact: profile.name,
    format: profile.name,
  };
}
