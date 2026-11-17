// The pure half of running a CrowdStrike Next-Gen SIEM search (#2666): the per-search caps, the time
// window check, the default range, the outcome sentence and the event-name inference for `table()`
// output. Used by the search route (routes/crowdstrikeSiem*.ts) and by Watson's search card
// (analysis/ai/watson/crowdstrike/), which may not import integrations/.
//
// Pure: no I/O. `env` is passed in (process.env at the call site).

import { createHash } from "node:crypto";
import type { ScopeWindow } from "./scope.js";

type Env = Readonly<Record<string, string | undefined>>;

const DAY_MS = 86_400_000;
/** How far in the future a search may end (clock skew between the analyst and the server). */
const FUTURE_SLACK_MS = 5 * 60_000;

export interface SiemLimits {
  maxWindowDays: number;
  maxRows: number;
  timeoutMs: number;
  repository: string;
}

export const SIEM_DEFAULTS: Readonly<SiemLimits> = {
  maxWindowDays: 7,
  maxRows: 10_000,
  timeoutMs: 300_000,
  repository: "search-all",
};

function intIn(raw: string | undefined, min: number, max: number, fallback: number): number {
  const n = Number((raw ?? "").trim());
  return Number.isInteger(n) && n >= min && n <= max ? n : fallback;
}

/** The caps from DFIR_CROWDSTRIKE_SIEM_*; a missing or invalid value keeps its default. */
export function readSiemLimits(env: Env): SiemLimits {
  const repo = (env.DFIR_CROWDSTRIKE_SIEM_REPOSITORY ?? "").trim();
  return {
    maxWindowDays: intIn(env.DFIR_CROWDSTRIKE_SIEM_MAX_WINDOW_DAYS, 1, 3650, SIEM_DEFAULTS.maxWindowDays),
    maxRows: intIn(env.DFIR_CROWDSTRIKE_SIEM_MAX_ROWS, 1, 1_000_000, SIEM_DEFAULTS.maxRows),
    timeoutMs: intIn(env.DFIR_CROWDSTRIKE_SIEM_TIMEOUT_MS, 10_000, 3_600_000, SIEM_DEFAULTS.timeoutMs),
    repository: /^[\w.-]{1,128}$/.test(repo) ? repo : SIEM_DEFAULTS.repository,
  };
}

/** The search is on only when the SIEM API client's id AND secret are both set. */
export function siemConfigured(env: Env): boolean {
  return !!env.DFIR_CROWDSTRIKE_SIEM_CLIENT_ID?.trim() && !!env.DFIR_CROWDSTRIKE_SIEM_CLIENT_SECRET?.trim();
}

export type WindowCheck = { ok: true; startMs: number; endMs: number } | { ok: false; error: string };

const days = (ms: number): string => {
  const d = Math.ceil(ms / DAY_MS);
  return `${d} day${d === 1 ? "" : "s"}`;
};

/**
 * Whether one search may cover [start, end]. A wider window is refused before anything is sent, with
 * a sentence naming the limit — never clipped, so the analyst always knows what ran.
 */
export function checkSearchWindow(start: unknown, end: unknown, maxDays: number, now: number): WindowCheck {
  const startMs = typeof start === "string" ? Date.parse(start) : NaN;
  const endMs = typeof end === "string" ? Date.parse(end) : NaN;
  if (!Number.isFinite(startMs) || !Number.isFinite(endMs)) {
    return { ok: false, error: "The search needs a start and an end time (ISO 8601)." };
  }
  if (startMs >= endMs) return { ok: false, error: "The search start must be before its end." };
  if (endMs > now + FUTURE_SLACK_MS) return { ok: false, error: "The search end is in the future." };
  if (endMs - startMs > maxDays * DAY_MS) {
    return {
      ok: false,
      error:
        `The search covers ${days(endMs - startMs)}. The limit is ${days(maxDays * DAY_MS)} ` +
        `(DFIR_CROWDSTRIKE_SIEM_MAX_WINDOW_DAYS). Narrow the time range.`,
    };
  }
  return { ok: true, startMs, endMs };
}

/**
 * The range the Run dialog starts with: the case scope window, else the span of the case's
 * High/Critical forensic events padded by a day each side, else the last `maxDays` days. A window
 * wider than the limit keeps its END (the most recent activity) and moves its start forward.
 */
export function defaultSearchRange(
  scope: ScopeWindow,
  severeSpan: { start: string; end: string } | undefined,
  maxDays: number,
  now: number,
): { start: string; end: string } {
  const max = maxDays * DAY_MS;
  let startMs: number;
  let endMs: number;
  const s = Date.parse(scope.start ?? "");
  const e = Date.parse(scope.end ?? "");
  if (Number.isFinite(s) || Number.isFinite(e)) {
    endMs = Number.isFinite(e) ? e : now;
    startMs = Number.isFinite(s) ? s : endMs - max;
  } else if (severeSpan) {
    startMs = Date.parse(severeSpan.start) - DAY_MS;
    endMs = Date.parse(severeSpan.end) + DAY_MS;
  } else {
    startMs = now - max;
    endMs = now;
  }
  endMs = Math.min(endMs, now);
  if (!(startMs < endMs)) startMs = endMs - max;
  if (endMs - startMs > max) startMs = endMs - max;
  return { start: new Date(startMs).toISOString(), end: new Date(endMs).toISOString() };
}

export interface SiemSearchOutcome {
  title: string;
  /** Rows Falcon returned and the evidence file holds. */
  rows: number;
  /** Of those, the rows that were Falcon events (offered to the importer). */
  events: number;
  /** New forensic-timeline events after the settle. */
  added: number;
  /** The row cap, the timeout or an error cut the result short. */
  truncated: boolean;
  timedOut: boolean;
  timeoutMs?: number;
  /** A total Falcon reported for this result; only ever a real count of result rows. */
  total?: number;
  /** Why a search that read some rows stopped early (not the timeout). */
  error?: string;
  /** Why the search did not complete at all (nothing imported). */
  failed?: string;
}

const plural = (n: number, word: string): string => `${n} ${word}${n === 1 ? "" : "s"}`;

/** The outcome sentence for the activity log, the job and Watson's case event (huntEventText style). */
export function siemSearchText(o: SiemSearchOutcome): string {
  const name = `CrowdStrike NG-SIEM search ${o.title}`;
  if (o.failed) return `${name} did not complete: ${o.failed}`;
  if (o.rows === 0 && o.timedOut) return `${name} timed out before Falcon returned any rows`;
  if (o.rows === 0 && o.error) return `${name} did not complete: ${o.error}`;
  if (o.rows === 0 && !o.added) return `${name} found nothing`;
  const added = `added ${plural(o.added, "new event")}`;
  let text: string;
  if (o.timedOut) {
    const min = Math.round((o.timeoutMs ?? 0) / 60_000);
    text = `${name} timed out after ${plural(min, "minute")}. It imported the ${plural(o.rows, "row")} already read and ${added}`;
  } else if (o.error) {
    text = `${name} stopped early: ${o.error} It imported the ${plural(o.rows, "row")} already read and ${added}`;
  } else if (o.truncated) {
    const cut =
      o.total && o.total > o.rows
        ? `imported the first ${o.rows} of ${o.total} rows`
        : `imported the first ${plural(o.rows, "row")} (the row cap cut the rest)`;
    text = `${name} finished. It ${cut} and ${added}`;
  } else {
    text = `${name} finished. It found ${plural(o.rows, "row")} and ${added}`;
  }
  const other = o.rows - o.events;
  if (other > 0) {
    text += `. ${plural(other, "row")} ${other === 1 ? "was" : "were"} not Falcon events (for example groupBy totals); they are kept in the evidence file only`;
  }
  return text;
}

// Functions that keep one output row per matching event. Anything else (groupBy, count, stats,
// timeChart, join, …) makes rows that are not events, so no event name is inferred for them.
const PER_EVENT_FUNCTIONS: ReadonlySet<string> = new Set([
  "table",
  "select",
  "sort",
  "head",
  "tail",
  "rename",
  "drop",
  "in",
  "regex",
  "wildcard",
  "lower",
  "upper",
  "length",
  "format",
  "eval",
  "concat",
  "replace",
  "cidr",
  "test",
  "default",
]);

const stripComments = (q: string): string => q.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/\/\/[^\n]*/g, " ");
const stripStrings = (q: string): string => q.replace(/"(?:[^"\\]|\\.)*"/g, '""');

/**
 * The single event type a per-event query filters on, or "". `table([...])` output keeps only the
 * listed fields, so a row of `#event_simpleName=ProcessRollup2 | table([ComputerName, CommandLine])`
 * arrives without its event name; the importer needs it to read the row. Inferred only when the
 * query names exactly one type with `#event_simpleName=X` and uses no aggregate function.
 */
export function inferredEventName(query: string): string {
  const q = stripComments(query);
  if ((q.match(/#event_simpleName/g) ?? []).length !== 1) return "";
  const m = /#event_simpleName\s*=\s*"?([A-Za-z0-9_]+)"?(?=[\s|)]|$)/.exec(q);
  if (!m) return "";
  for (const call of stripStrings(q).matchAll(/([A-Za-z_][\w:]*)\s*\(/g)) {
    if (!PER_EVENT_FUNCTIONS.has(call[1].toLowerCase())) return "";
  }
  return m[1];
}

const normalizeQuery = (q: string): string => q.replace(/\s+/g, " ").trim();

/** The key one search is remembered by: the query (whitespace-normalised), repository and range. */
export function siemQueryFingerprint(query: string, repository: string, start: string, end: string): string {
  return createHash("sha256")
    .update(`${normalizeQuery(query)}\u0000${repository}\u0000${start}\u0000${end}`)
    .digest("hex")
    .slice(0, 32);
}
