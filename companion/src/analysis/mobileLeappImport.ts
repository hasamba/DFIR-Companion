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
import { parseCsvRecords } from "./csvImport.js";
import { boundedAggKey, boundedText } from "./aggKey.js";

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
//
// A ROW WITH NO CLOCK IS STILL EVIDENCE (#932 item 12). Installed apps, permissions, accounts and
// settings tables carry no time column, and many per-row cells are empty even where one exists.
// The first version dropped every such row — the whole file when no column looked like a time —
// so the artifacts that answer "what was on this phone" never entered the case. Now a row with no
// usable time is imported UNDATED (`timestamp: ""`, the shape memoryImport / yaraImport /
// irisImport already emit); the pipeline renders "(undated)", the super-timeline sorts it after
// every dated row, and the parse result counts it in `undated`.
//
// WHICH CLOCK, PER ROW. A LEAPP table often has several time columns (Timestamp, Created, Last
// Modified) and a row's populated one is not the same for every row. Each row takes the FIRST
// populated recognised column in preference order and names it in the description —
// `[Last Modified: 2026-05-03 09:00:00]` — because "created" and "last modified" are different
// facts and the raw text must stay visible where the normaliser guessed. The unused clocks stay
// as `Header: value` prose. The clock's meaning is part of the aggregation key: two rows with the
// same value in different columns are two events.
//
// THE DESCRIPTION IS THE IDENTITY. Correlation's exact-duplicate pass, the import diff and the
// super-timeline content key all key on timestamp + description, so two long rows that share a
// prefix must stay distinct IN THE DESCRIPTION, not only in the aggregation key: the detail is
// bounded by boundedText (a digest tail replaces the last 17 chars when clipped), every prefix
// component is bounded at the source, and the outer 600-char slice is a defensive bound a test
// proves is never reached.

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
  /** Rows imported with no usable time cell (counted in `kept` too — they are events). */
  undated: number;
  format: string; // "leapp-tsv" | "empty"
}

// Bounds on the description's prefix components, so the digest tail of the bounded detail can
// never be pushed past the outer slice: label (≤ 6) + artifact + `[clock: raw]` + detail (400).
const ARTIFACT_MAX = 80;
const CLOCK_NAME_MAX = 40;
const CLOCK_RAW_MAX = 40;
const DESCRIPTION_MAX = 600;

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
  return base
    .replace(/\.(tsv|txt|csv)$/i, "")
    .trim()
    .slice(0, ARTIFACT_MAX);
}

function hostOf(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
}

// Every column that can carry the row's time, in preference order: the exact names first, then a
// "contains" pass that catches "Timestamp (UTC)" and similar. A row takes the first of these whose
// cell is populated.
function timeColumns(headers: readonly string[]): number[] {
  const lower = headers.map((h) => h.trim().toLowerCase());
  const out: number[] = [];
  for (const wanted of TIME_COLUMNS) {
    const i = lower.indexOf(wanted);
    if (i >= 0 && !out.includes(i)) out.push(i);
  }
  lower.forEach((h, i) => {
    if (!out.includes(i) && /\btime\b|\bdate\b/.test(h)) out.push(i);
  });
  return out;
}

interface RowClock {
  index: number;
  name: string;
  raw: string;
}

function rowClock(
  headers: readonly string[],
  cells: readonly string[],
  candidates: readonly number[],
): RowClock | null {
  for (const index of candidates) {
    const raw = (cells[index] ?? "").trim();
    if (raw) return { index, name: (headers[index] ?? "").trim().slice(0, CLOCK_NAME_MAX), raw };
  }
  return null;
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
    undated: 0,
    format: "empty",
  };

  const trimmed = input.trim();
  if (!trimmed) return empty;

  // Tab-separated is LEAPP's export format; fall back to comma so a re-saved file still reads.
  // Both go through the shared quote-aware parser (embedded delimiters and newlines survive).
  const firstLine = trimmed.split(/\r\n|\r|\n/, 1)[0] ?? "";
  const delimiter = firstLine.includes("\t") ? "\t" : ",";
  const records = [...parseCsvRecords(trimmed, delimiter)].filter((r) => r.some((c) => c.trim() !== ""));
  if (records.length < 2) return empty;

  const headers = (records[0] ?? []).map((h) => h.trim());
  const candidates = timeColumns(headers);
  const rows = records.slice(1);
  const total = rows.length;

  const label = sourceLabel(opts.platform ?? "unknown");
  const artifact = artifactName(filename);
  const iocSink = new Map<string, SiemIoc>();
  const mapped: MappedEvent[] = [];
  let undated = 0;

  for (const cells of rows) {
    const clock = rowClock(headers, cells, candidates);
    if (!clock) undated++;

    const detail = headers
      .map((h, i) => {
        if (i === clock?.index) return "";
        const value = (cells[i] ?? "").trim();
        return value ? `${h}: ${value}` : "";
      })
      .filter(Boolean)
      .join(", ");

    for (const url of cells.join("\t").match(URL_RE) ?? []) {
      addIoc(iocSink, "url", url.slice(0, 500));
      const host = hostOf(url);
      if (host) addIoc(iocSink, "domain", host);
    }

    // Prefix components are each bounded at the source (see the constants above), the detail by
    // boundedText, so the outer slice is a bound that is never reached — the digest tail survives.
    const clockTag = clock ? ` [${clock.name}: ${clock.raw.slice(0, CLOCK_RAW_MAX)}]` : "";
    const boundedDetail = detail ? boundedText(oneLine(detail)) : "";
    let description = `${label}${artifact ? ` ${artifact}` : ""}${clockTag}`;
    if (boundedDetail) description += `: ${boundedDetail}`;
    description = description.slice(0, DESCRIPTION_MAX);

    mapped.push({
      timestamp: clock ? normalizeTime(clock.raw.replace(" ", "T")) : "",
      description,
      severity: "Info", // extraction rows are evidence, not verdicts
      mitre: [],
      // The row's own content, its clock's NAME and its raw time are all part of the key. Keying
      // on the artifact alone collapsed every row of a file into one event; keying without the
      // time folded rows that differ only in when they happened and kept the first one's clock;
      // keying without the clock name folded "Created" into "Last Modified". Aggregation is meant
      // to fold IDENTICAL rows, and only those. Bounded fields first, the prose last, so the
      // attacker-shaped detail can never push a discriminator past the key's bound.
      aggKey: boundedAggKey(
        `leapp|${artifact}|${clock?.name ?? ""}|${clock?.raw ?? ""}|${boundedDetail}`.toLowerCase(),
      ),
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
    undated,
    format: mapped.length ? "leapp-tsv" : "empty",
  };
}
