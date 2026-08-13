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

// Deterministic importer for Hindsight (Ryan Benson) browser-artifact output — Chrome/Edge/Brave
// history, downloads, cookies, autofill and local storage, parsed from a browser profile. No AI call.
//
// EVERY ROW IS Info, ON PURPOSE. This is the same call kapeImport.ts makes: browser artifacts carry
// no maliciousness verdict, and the tool is a post-detection analysis layer, not a detection engine.
// A download of `setup.exe` is evidence that a file was fetched; whether it was malicious is decided
// by a hash lookup, a sandbox report or an EDR detection landing on the same artifact — which is
// exactly what cross-source correlation and the high-severity backfill are for. Grading downloads
// "Medium" here would invent a verdict the artifact cannot support, and would flood a case with
// false urgency on the browsing of every user who ever fetched an installer.
//
// The value is therefore twofold: the SUPER-TIMELINE (what the user was doing minute by minute,
// which is usually the only record of the initial-access click) and IOC extraction (the domains and
// URLs, which correlate against proxy logs, threat intel and the rest of the case).

type Row = Record<string, unknown>;

export interface HindsightImportOptions {
  aggregate?: boolean;
  minSeverity?: Severity;
  maxEvents?: number;
  maxIocs?: number;
}

export interface HindsightParseResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  total: number;
  kept: number;
  dropped: number;
  groups: number;
  format: string; // "hindsight-json" | "hindsight-csv" | "empty"
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

// The hostname, for the IOC list. Hindsight rows carry a full URL; a bare host is what correlates
// against proxy logs and threat intel, so both are recorded when they differ.
function hostOf(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
}

function mapRow(rec: Row, sink: Map<string, SiemIoc>): MappedEvent | null {
  const type = pick(rec, ["type", "row_type", "record_type"]).toLowerCase() || "url";
  const timestamp = pick(rec, ["timestamp", "date", "datetime", "visit_time", "time"]);
  const url = pick(rec, ["url", "target", "location"]);
  // A row with neither a time nor a URL cannot be placed on a timeline or correlated; it is a
  // cookie/preference row whose value is the profile dump, not the case.
  if (!timestamp || !url) return null;

  const title = pick(rec, ["title", "name"]);
  const interpretation = pick(rec, ["interpretation", "interpreted"]);
  const profile = pick(rec, ["profile", "profile folder", "profile_folder"]);
  const source = pick(rec, ["source", "browser"]);
  const value = pick(rec, ["value", "target_path", "full_path"]);

  const host = hostOf(url);
  if (host) addIoc(sink, "domain", host);
  if (url) addIoc(sink, "url", url.slice(0, 500));

  const verb = type === "download" ? "download" : type === "url" ? "visit" : type;
  let description = `Browser ${verb}: ${oneLine(url).slice(0, 200)}`;
  if (title) description += ` — ${oneLine(title).slice(0, 120)}`;
  if (value) description += ` → ${oneLine(value).slice(0, 160)}`;
  if (interpretation) description += ` [${oneLine(interpretation).slice(0, 160)}]`;
  const profileLabel = [source, profile].filter(Boolean).join(" ");
  if (profileLabel) description += ` (${profileLabel})`;
  description = description.slice(0, 600);

  return {
    timestamp: normalizeTime(timestamp),
    description,
    // Info, always — see the header. Escalation is correlation's job, not this parser's.
    severity: "Info",
    mitre: [],
    aggKey: `hindsight|${type}|${host}|${profileLabel}`.toLowerCase().slice(0, 400),
    sources: ["Hindsight"],
  };
}

// Hindsight writes XLSX by default, and JSONL/CSV on request. Only the text forms are handled here:
// an XLSX is a zip container, not text, and would need a spreadsheet reader to become rows.
function readRows(input: string): { rows: Row[]; format: string } {
  const trimmed = input.trim();
  if (!trimmed) return { rows: [], format: "empty" };

  if (trimmed[0] === "[" || trimmed[0] === "{") {
    const records = extractRecords(trimmed).records.filter(isObject) as Row[];
    return { rows: records, format: "hindsight-json" };
  }

  const { headers, rows } = parseCsv(trimmed);
  if (!headers.length) return { rows: [], format: "empty" };
  const mapped = rows.map((cols) => {
    const r: Row = {};
    headers.forEach((h, i) => {
      r[h.trim()] = cols[i] ?? "";
    });
    return r;
  });
  return { rows: mapped, format: "hindsight-csv" };
}

export function parseHindsight(input: string, opts: HindsightImportOptions = {}): HindsightParseResult {
  const maxIocs = opts.maxIocs ?? 5000;
  const { rows, format } = readRows(input);
  const total = rows.length;
  if (total === 0) {
    return { events: [], iocs: [], total: 0, kept: 0, dropped: 0, groups: 0, format: "empty" };
  }

  const iocSink = new Map<string, SiemIoc>();
  const mapped: MappedEvent[] = [];
  for (const rec of rows) {
    const event = mapRow(rec, iocSink);
    if (event) mapped.push(event);
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
    dropped: Math.max(0, mapped.length - represented),
    groups,
    format: mapped.length ? format : "empty",
  };
}
