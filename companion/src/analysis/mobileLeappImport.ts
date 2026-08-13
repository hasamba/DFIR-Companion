import type { Severity } from "./stateTypes.js";
import {
  aggregateEvents,
  addIoc,
  oneLine,
  normalizeTime,
  type MappedEvent,
  type SiemEvent,
  type SiemIoc,
  maxEventsDefault,
} from "./siemImport.js";

// Deterministic importer for iLEAPP / ALEAPP output — iOS and Android logical-extraction parsing.
// No AI call.
//
// SCOPE, STATED PLAINLY: LEAPP writes a REPORT TREE (HTML index, per-artifact HTML, and a
// "_TSV Exports" folder), and this importer takes the TSV files from that folder, one at a time.
// It does not walk the tree or read the HTML. That is a real limit and it is the honest one to
// ship: the TSVs carry the same rows the HTML renders, they are the only text-parseable form, and
// pretending to ingest a directory that the import route hands us as a single file's text would be
// a lie in the plumbing. Importing several artifacts means several imports, which is also how an
// analyst thinks about them ("bring in the call log, then the installed apps").
//
// EVERY COLUMN SET IS DIFFERENT. There are ~250 LEAPP artifacts and no shared schema beyond "one
// column holds a time". So this parser is deliberately generic: find the timestamp column, render
// the remaining columns as `Header: value` pairs, and name the artifact from the filename — which
// is exactly where LEAPP puts it ("Installed Apps.tsv", "Call History.tsv"). A per-artifact mapping
// table would be 250 entries that rot with every LEAPP release.
//
// Info severity throughout, like kapeImport / hindsightImport / macosImport: an extraction row is
// evidence, not a verdict.

export type LeappPlatform = "ios" | "android" | "unknown";

export interface LeappImportOptions {
  platform?: LeappPlatform;
  aggregate?: boolean;
  minSeverity?: Severity;
  maxEvents?: number;
  maxIocs?: number;
}

export interface LeappParseResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  total: number;
  kept: number;
  dropped: number;
  groups: number;
  format: string; // "leapp-tsv" | "empty"
}

// Column names LEAPP uses for the row's time, in preference order. Matched case-insensitively and
// as a whole cell, so a "Timestamp Source" column does not win over "Timestamp".
const TIME_COLUMNS = [
  "timestamp",
  "start time",
  "starttime",
  "date",
  "datetime",
  "date/time",
  "time",
  "created",
  "created date",
  "last modified",
  "end time",
];

const URL_RE = /\bhttps?:\/\/[^\s"'<>]+/gi;

function sourceLabel(platform: LeappPlatform): string {
  if (platform === "ios") return "iLEAPP";
  if (platform === "android") return "ALEAPP";
  return "LEAPP";
}

// "Installed Apps.tsv" → "Installed Apps". LEAPP names the file after the artifact, so the filename
// is the only place the artifact's identity appears in a bare TSV.
function artifactName(filename: string): string {
  const base = filename.split(/[\\/]/).pop() ?? filename;
  return base.replace(/\.(tsv|txt|csv)$/i, "").trim();
}

function hostOf(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
}

function pickTimeColumn(headers: readonly string[]): number {
  const lower = headers.map((h) => h.trim().toLowerCase());
  for (const wanted of TIME_COLUMNS) {
    const i = lower.indexOf(wanted);
    if (i >= 0) return i;
  }
  // Nothing named like a time — a "contains" pass catches "Timestamp (UTC)" and similar.
  return lower.findIndex((h) => /\btime\b|\bdate\b/.test(h));
}

export function parseLeappTsv(
  input: string,
  filename: string,
  opts: LeappImportOptions = {},
): LeappParseResult {
  const maxIocs = opts.maxIocs ?? 5000;
  const empty: LeappParseResult = {
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

  const lines = trimmed.split(/\r\n|\r|\n/).filter((l) => l.trim() !== "");
  if (lines.length < 2) return empty;

  // Tab-separated is LEAPP's export format; fall back to comma so a re-saved file still reads.
  const delimiter = (lines[0]?.includes("\t") ?? false) ? "\t" : ",";
  const headers = (lines[0] ?? "").split(delimiter).map((h) => h.trim());
  const timeIndex = pickTimeColumn(headers);
  const rows = lines.slice(1);
  const total = rows.length;
  if (timeIndex < 0) {
    // No time column means nothing can be placed on a timeline. Report the rows as read so the
    // import surfaces as zero-yield rather than silently succeeding.
    return { ...empty, total };
  }

  const label = sourceLabel(opts.platform ?? "unknown");
  const artifact = artifactName(filename);
  const iocSink = new Map<string, SiemIoc>();
  const mapped: MappedEvent[] = [];

  for (const line of rows) {
    const cells = line.split(delimiter);
    const rawTime = (cells[timeIndex] ?? "").trim();
    if (!rawTime) continue;

    const detail = headers
      .map((h, i) => {
        if (i === timeIndex) return "";
        const value = (cells[i] ?? "").trim();
        return value ? `${h}: ${value}` : "";
      })
      .filter(Boolean)
      .join(", ");

    for (const url of line.match(URL_RE) ?? []) {
      addIoc(iocSink, "url", url.slice(0, 500));
      const host = hostOf(url);
      if (host) addIoc(iocSink, "domain", host);
    }

    let description = `${label}${artifact ? ` ${artifact}` : ""}`;
    if (detail) description += `: ${oneLine(detail).slice(0, 400)}`;
    description = description.slice(0, 600);

    mapped.push({
      timestamp: normalizeTime(rawTime.replace(" ", "T")),
      description,
      severity: "Info", // extraction rows are evidence, not verdicts
      mitre: [],
      // The row's own content is part of the key. Keying on the artifact alone collapsed every row
      // of a file into one event — aggregation is meant to fold IDENTICAL rows, not a whole export.
      aggKey: `leapp|${artifact}|${detail}`.toLowerCase().slice(0, 400),
      sources: [label],
    });
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
    format: mapped.length ? "leapp-tsv" : "empty",
  };
}
