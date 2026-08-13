import type { Severity } from "./stateTypes.js";
import { parseCsv } from "./csvImport.js";
import {
  extractRecords,
  aggregateEvents,
  addIoc,
  oneLine,
  isObject,
  getCI,
  normalizeTime,
  type MappedEvent,
  type SiemEvent,
  type SiemIoc,
  maxEventsDefault,
} from "./siemImport.js";

// Deterministic importer for macOS host artifacts — the platform gap beside the Windows (KAPE/EVTX)
// and Linux (auditd/journald) paths. No AI call. Two shapes, auto-detected:
//
//   1. UNIFIED LOG — `log show --style json` / `log collect` exported to JSON. The closest macOS has
//      to an event log, though it is telemetry rather than a security log: process, subsystem,
//      category and a free-text message, with no verdict anywhere.
//   2. LSQUARANTINE — the download-provenance database (`~/Library/Preferences/
//      com.apple.LaunchServices.QuarantineEventsV2`), dumped to CSV. This is macOS's Mark-of-the-Web:
//      which app downloaded a file, from which URL, and from which referring page. On an initial-
//      access question it is often the single most useful macOS artifact there is.
//
// EVERY ROW IS Info, like kapeImport and hindsightImport. Neither artifact adjudicates anything: a
// quarantine record proves a file arrived from a URL, not that the file was malicious. Escalation is
// the job of correlation against a real detection, a hash lookup, or a sandbox verdict.

type Row = Record<string, unknown>;

export interface MacosImportOptions {
  aggregate?: boolean;
  minSeverity?: Severity;
  maxEvents?: number;
  maxIocs?: number;
}

export interface MacosParseResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  total: number;
  kept: number;
  dropped: number;
  groups: number;
  format: string; // "macos-unified-log" | "macos-quarantine" | "empty"
}

function text(value: unknown): string {
  return typeof value === "string" ? value : value == null ? "" : String(value);
}

function pick(rec: Row, keys: readonly string[]): string {
  for (const k of keys) {
    const v = getCI(rec, k);
    if (v != null && text(v).trim() !== "") return text(v).trim();
  }
  return "";
}

// `log show` writes "2026-05-02 10:00:00.123456+0000" — a space instead of the ISO 'T' and six
// fractional digits. normalizeTime handles ISO; this makes the unified-log form ISO first.
function normalizeUnifiedTime(raw: string): string {
  const iso = raw.trim().replace(" ", "T");
  return normalizeTime(iso);
}

function baseName(path: string): string {
  const parts = path.split(/[\\/]/);
  return parts[parts.length - 1] || path;
}

function hostOf(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
}

function mapUnifiedLog(rec: Row): MappedEvent | null {
  const timestamp = pick(rec, ["timestamp", "time"]);
  if (!timestamp) return null;

  const message = pick(rec, ["eventMessage", "message", "composedMessage"]);
  const proc = pick(rec, ["processImagePath", "process"]);
  const subsystem = pick(rec, ["subsystem"]);
  const category = pick(rec, ["category"]);
  const asset = pick(rec, ["machineName", "hostname", "host"]);
  const pid = pick(rec, ["processID", "pid"]);

  const procName = proc ? baseName(proc) : "";
  let description = `macOS log${procName ? ` ${procName}` : ""}`;
  if (pid) description += `[${pid}]`;
  if (subsystem || category) description += ` (${[subsystem, category].filter(Boolean).join(" / ")})`;
  if (message) description += `: ${oneLine(message).slice(0, 400)}`;
  description = description.slice(0, 600);

  return {
    timestamp: normalizeUnifiedTime(timestamp),
    description,
    severity: "Info", // telemetry, not a verdict — see the header
    mitre: [],
    aggKey: `macos-ulog|${subsystem}|${procName}`.toLowerCase().slice(0, 400),
    sources: ["macOS Unified Log"],
    ...(asset ? { asset } : {}),
    ...(proc ? { path: proc } : {}),
  };
}

function mapQuarantine(rec: Row, sink: Map<string, SiemIoc>): MappedEvent | null {
  const timestamp = pick(rec, ["LSQuarantineTimeStamp", "timestamp", "time"]);
  const dataUrl = pick(rec, ["LSQuarantineDataURLString", "data_url", "url"]);
  const originUrl = pick(rec, ["LSQuarantineOriginURLString", "origin_url", "referrer"]);
  if (!timestamp || (!dataUrl && !originUrl)) return null;

  const agent = pick(rec, ["LSQuarantineAgentName", "agent"]);
  const sender = pick(rec, ["LSQuarantineSenderName", "sender"]);

  // Both URLs matter and they are different facts: the data URL is where the file came from, the
  // origin URL is the page that led there — the lure, on a phishing question.
  for (const url of [dataUrl, originUrl]) {
    if (!url) continue;
    addIoc(sink, "url", url.slice(0, 500));
    const host = hostOf(url);
    if (host) addIoc(sink, "domain", host);
  }

  const file = dataUrl ? baseName(dataUrl.split("?")[0] ?? dataUrl) : "";
  let description = "macOS quarantine";
  if (agent) description += ` via ${agent}`;
  if (file) description += `: ${oneLine(file).slice(0, 160)}`;
  if (dataUrl) description += ` from ${oneLine(dataUrl).slice(0, 200)}`;
  if (originUrl && originUrl !== dataUrl) description += ` (referred by ${oneLine(originUrl).slice(0, 160)})`;
  if (sender) description += ` [sender: ${oneLine(sender).slice(0, 80)}]`;
  description = description.slice(0, 600);

  return {
    timestamp: normalizeTime(timestamp),
    description,
    severity: "Info", // provenance, not a verdict
    mitre: [],
    aggKey: `macos-quarantine|${agent}|${hostOf(dataUrl)}`.toLowerCase().slice(0, 400),
    sources: ["macOS Quarantine"],
  };
}

function looksLikeQuarantine(headers: readonly string[]): boolean {
  return headers.some((h) => /lsquarantine/i.test(h));
}

export function parseMacos(input: string, opts: MacosImportOptions = {}): MacosParseResult {
  const maxIocs = opts.maxIocs ?? 5000;
  const empty: MacosParseResult = {
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

  const iocSink = new Map<string, SiemIoc>();
  const mapped: MappedEvent[] = [];
  let total = 0;
  let format = "empty";

  if (trimmed[0] === "[" || trimmed[0] === "{") {
    const records = extractRecords(trimmed).records.filter(isObject) as Row[];
    total = records.length;
    for (const rec of records) {
      const event = mapUnifiedLog(rec);
      if (event) mapped.push(event);
    }
    format = "macos-unified-log";
  } else {
    const { headers, rows } = parseCsv(trimmed);
    if (!headers.length) return empty;
    const quarantine = looksLikeQuarantine(headers);
    const objects = rows.map((cols) => {
      const r: Row = {};
      headers.forEach((h, i) => {
        r[h.trim()] = cols[i] ?? "";
      });
      return r;
    });
    total = objects.length;
    for (const rec of objects) {
      const event = quarantine ? mapQuarantine(rec, iocSink) : mapUnifiedLog(rec);
      if (event) mapped.push(event);
    }
    format = quarantine ? "macos-quarantine" : "macos-unified-log";
  }

  if (total === 0) return empty;

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
    dropped: Math.max(0, mapped.length - represented),
    groups,
    format: mapped.length ? format : "empty",
  };
}
