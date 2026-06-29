import type { ForensicEvent, Finding, InvestigationState, Severity } from "./stateTypes.js";
import { byEventTime } from "./forensicSort.js";

// Log gap analysis (issue #83).
//
// A tampered audit log goes QUIET. An attacker who clears the Windows Event Log, stops auditd, or
// deletes log files leaves a hole in the forensic timeline — a stretch of time with no events at
// all. That silence is one of the clearest signatures of log tampering or a coverage blindspot, yet
// it's invisible in a strictly-chronological timeline (the analyst only sees the rows that ARE
// there, never the absence between them). This walks the scoped timeline and flags unusually long
// silent periods.
//
// Two flavours, weighted by how suspicious they are:
//   • COMPLETE silence — a window where the WHOLE environment went dark (no source logged anything).
//     The classic "logs cleared / collector stopped" signature → High. Detected on the full timeline.
//   • PARTIAL silence — one source (tool) went quiet while OTHER sources kept logging. A coverage
//     blindspot for that tool, less alarming than total darkness → Medium. Detected per-source.
//
// To avoid drowning the analyst in normal quiet periods (overnight, weekends, a naturally sparse
// timeline) a gap must clear TWO bars: a hard floor (`minGapMinutes`, default 30) AND either it
// overlaps configured active hours (`activeHours`) OR — when active hours aren't configured — it is
// much larger than the timeline's own typical cadence (the density heuristic: gap ≥ `densityFactor`
// × the median inter-event interval). So a 30-minute hole in a 5-second-cadence stream screams, but
// a 30-minute hole in a 25-minute-cadence stream is business as usual and stays silent.
//
// Pure, deterministic, NO AI call. Like attack phases and beacon candidates, this is DERIVED ON
// READ — never persisted to state, re-computed from the timeline each time it's requested.
//
// CRUCIAL FRAMING: a gap is a LEAD, not proof. An analyst may simply have collected logs for a
// limited window, or activity genuinely paused. The "all sources silent" case is the strong signal;
// confirm against the collection scope before concluding tampering.

export interface TimelineGap {
  id: string;                  // stable per-result id: "gap-1", "gap-2", … assigned worst-first
  startTimestamp: string;      // when activity stopped — the end of the last event before the silence
  endTimestamp: string;        // when activity resumed — the first event after the silence
  durationSeconds: number;     // length of the silence (seconds)
  durationLabel: string;       // human-readable duration, e.g. "2h 15m"
  severity: Severity;          // High when ALL sources went silent (complete), else Medium (partial)
  complete: boolean;           // true when the WHOLE environment went dark (no source logged at all)
  silentSources: string[];     // sources that produced no events during the window (sorted)
  activeSources: string[];     // sources that DID keep logging during the window (sorted; empty when complete)
  beforeEventId: string;       // forensic-event id bounding the start of the gap (last activity before)
  afterEventId: string;        // forensic-event id bounding the end of the gap (first activity after)
}

export interface GapOptions {
  // Hard floor: a silence shorter than this is never flagged. Default 30 minutes.
  minGapMinutes?: number;
  // Density heuristic (used when activeHours is not set): a gap must be ≥ this multiple of the
  // timeline's median inter-event interval to flag, so naturally-sparse timelines aren't noisy.
  // Default 4. Set to 0 to disable the density bar (the floor still applies).
  densityFactor?: number;
  // Optional configured working hours (UTC hour-of-day, 0..23). When set, a gap is flagged only if
  // it overlaps [start, end) on some day — so expected overnight/weekend quiet doesn't trip it. This
  // SUPERSEDES the density heuristic. `start === end` means "all day" (always overlaps). Off by default.
  activeHours?: { start: number; end: number } | null;
  // Cap on how many complete-silence gaps escalate to a FINDING (the panel/report still show all of
  // them). Guards against a super-timeline case (MFT/registry spanning years) flooding the findings
  // list. Default 5. The worst (longest) complete gaps are kept. Set 0 for no findings.
  maxFindings?: number;
  // Robustness against MIS-DATED stray events (issue: an importer that guesses the wrong YEAR for a
  // year-less timestamp — e.g. a Cisco ASA syslog line `May 14 12:00:48` parsed as 2023/2026 instead of
  // the real 2024 — would otherwise manufacture a giant "729d of silence" gap between the strays and the
  // real body). Before detection, the timeline's robust "core" time span is measured (the p2.5→p97.5
  // percentile range, so a handful of strays can't stretch it); any event lying more than
  // `outlierSpanFactor` × that core span outside the core is dropped FROM GAP ANALYSIS ONLY (it stays in
  // the timeline). This keys on MAGNITUDE, not count: a real collection gap is a small multiple of the
  // active span (an overnight/weekend lull, a few hours), while a wrong-year stray is hundreds-to-
  // thousands× it — so a substantial cluster (≥2.5% of events, hence inside the percentile core) and any
  // plausibly-real gap survive, but year-scale strays are removed. Default 5. Set 0 to disable.
  outlierSpanFactor?: number;
}

export const DEFAULT_GAP_MIN_MINUTES = 30;
export const DEFAULT_GAP_DENSITY_FACTOR = 4;
export const DEFAULT_GAP_MAX_FINDINGS = 5;
export const DEFAULT_GAP_OUTLIER_SPAN = 5;
// Outlier trimming only applies to a timeline with at least this many dated events (a tiny hand-built
// timeline has no meaningful percentiles). The core span is the p2.5→p97.5 range: a cluster larger than
// ~2.5% of events falls inside the core and is never treated as a stray.
const OUTLIER_MIN_EVENTS = 12;
const OUTLIER_CORE_LO_Q = 0.025;
const OUTLIER_CORE_HI_Q = 0.975;

// The shared "this is a lead, not a verdict" disclaimer — rendered on every surface (panel + report).
export const GAP_CAVEAT =
  "A coverage gap is a lead, not proof of tampering — an analyst may have collected logs for a limited window, or activity genuinely paused. A gap where EVERY source went silent is the classic signature of cleared logs or a stopped collector; confirm against the collection scope and host clocks before concluding.";

const SEV_RANK: Record<Severity, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
const MS_PER_HOUR = 3_600_000;

// Start time of an event in epoch ms (NaN when undated — filtered out before use).
function startMs(e: ForensicEvent): number {
  return Date.parse(e.timestamp);
}

// The end of an event's real-world span: the aggregated `endTimestamp` when present and valid, else
// its `timestamp`. So a long aggregated row (e.g. "20 logons over 3h") closes the gap at its END,
// not its first occurrence — otherwise the tail of an aggregated event reads as a false silence.
function endMs(e: ForensicEvent): number {
  const end = e.endTimestamp ? Date.parse(e.endTimestamp) : NaN;
  return Number.isNaN(end) ? Date.parse(e.timestamp) : end;
}

// An event's distinct named sources (the tools/imports that reported it). Events with no `sources`
// (e.g. screenshot extraction, manual entry) still bound gaps on the full timeline, but they don't
// belong to any named source's per-source stream.
function sourcesOf(e: ForensicEvent): string[] {
  return (e.sources ?? []).map((s) => s.trim()).filter((s) => s.length > 0);
}

// Median of a non-empty numeric list (copies + sorts; even length averages the two middle values).
function median(values: number[]): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = sorted.length >> 1;
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

// Linear-interpolated quantile of an ASCENDING numeric array (q in [0,1]). Empty ⇒ 0.
function quantileSorted(sorted: number[], q: number): number {
  if (sorted.length === 0) return 0;
  if (sorted.length === 1) return sorted[0];
  const pos = (sorted.length - 1) * q;
  const lo = Math.floor(pos);
  const hi = Math.ceil(pos);
  return lo === hi ? sorted[lo] : sorted[lo] + (sorted[hi] - sorted[lo]) * (pos - lo);
}

// Drop MIS-DATED temporal outliers from a time-ascending event list, for gap analysis only. The robust
// core span is the p2.5→p97.5 range (so strays can't inflate it); any event lying more than `factor` ×
// that span outside the core is removed — keying on MAGNITUDE so a real (small-multiple) gap survives
// while a year-scale stray is dropped. Below OUTLIER_MIN_EVENTS, with factor ≤ 0 / a degenerate (zero)
// core span, or if trimming would leave < 2 events, no trimming happens. Pure. See
// GapOptions.outlierSpanFactor for the rationale.
function dropTimeOutliers(dated: readonly ForensicEvent[], factor: number): readonly ForensicEvent[] {
  const n = dated.length;
  if (factor <= 0 || n < OUTLIER_MIN_EVENTS) return dated;
  const starts = dated.map(startMs); // already ascending (dated is time-sorted)
  const coreLo = quantileSorted(starts, OUTLIER_CORE_LO_Q);
  const coreHi = quantileSorted(starts, OUTLIER_CORE_HI_Q);
  const coreSpan = coreHi - coreLo;
  if (coreSpan <= 0) return dated; // core collapsed to an instant — no meaningful fence
  const lo = coreLo - factor * coreSpan;
  const hi = coreHi + factor * coreSpan;
  const kept = dated.filter((_, i) => starts[i] >= lo && starts[i] <= hi);
  if (kept.length === n || kept.length < 2) return dated;
  return kept;
}

// Render a duration (seconds) as a compact human label: "45m", "2h 15m", "1d 3h".
export function formatDuration(seconds: number): string {
  const s = Math.max(0, Math.round(seconds));
  const days = Math.floor(s / 86400);
  const hours = Math.floor((s % 86400) / 3600);
  const mins = Math.floor((s % 3600) / 60);
  if (days > 0) return hours > 0 ? `${days}d ${hours}h` : `${days}d`;
  if (hours > 0) return mins > 0 ? `${hours}h ${mins}m` : `${hours}h`;
  if (mins > 0) return `${mins}m`;
  return `${s}s`;
}

// Does the silence window [fromMs, toMs] overlap the configured active-hours band on any day? A gap
// spanning ≥ 24h always overlaps. For shorter gaps, walk hour-of-day (UTC) from the start hour to the
// end hour and test each against [start, end). `start === end` means the whole day is "active".
function overlapsActiveHours(fromMs: number, toMs: number, hours: { start: number; end: number }): boolean {
  if (toMs - fromMs >= 24 * MS_PER_HOUR) return true;
  const start = ((Math.trunc(hours.start) % 24) + 24) % 24;
  const end = ((Math.trunc(hours.end) % 24) + 24) % 24;
  if (start === end) return true; // degenerate band = all day
  const inBand = (h: number) =>
    start < end ? h >= start && h < end : h >= start || h < end; // wrap-around band (e.g. 22→06)
  const firstHour = Math.floor(fromMs / MS_PER_HOUR);
  const lastHour = Math.floor((toMs - 1) / MS_PER_HOUR); // -1: the resume instant itself isn't silent
  for (let h = firstHour; h <= lastHour; h++) {
    if (inBand(((h % 24) + 24) % 24)) return true;
  }
  return false;
}

// First index in the ascending array whose value is strictly greater than `x` (binary search).
function firstIndexGreater(arr: number[], x: number): number {
  let lo = 0;
  let hi = arr.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (arr[mid] > x) hi = mid;
    else lo = mid + 1;
  }
  return lo;
}

// Detect suspicious silent periods in a forensic timeline. Returns gaps worst-first (complete before
// partial, then longest, then earliest). An empty or fully-undated timeline yields no gaps.
export function detectTimelineGaps(events: readonly ForensicEvent[], opts: GapOptions = {}): TimelineGap[] {
  const minGapSeconds = Math.max(0, (opts.minGapMinutes ?? DEFAULT_GAP_MIN_MINUTES) * 60);
  const densityFactor = Math.max(0, opts.densityFactor ?? DEFAULT_GAP_DENSITY_FACTOR);
  const activeHours = opts.activeHours ?? null;

  const datedAll = events.filter((e) => !Number.isNaN(startMs(e))).sort(byEventTime);
  if (datedAll.length < 2) return [];

  // Drop mis-dated stray events (wrong-year timestamps) so they can't manufacture a giant false gap.
  const dated = dropTimeOutliers(datedAll, opts.outlierSpanFactor ?? DEFAULT_GAP_OUTLIER_SPAN);
  if (dated.length < 2) return [];

  const starts = dated.map(startMs);
  const allSources = [...new Set(dated.flatMap(sourcesOf))].sort();

  // Density baseline: the median inter-event interval (seconds) across the whole timeline.
  const intervals: number[] = [];
  for (let i = 1; i < dated.length; i++) intervals.push((starts[i] - starts[i - 1]) / 1000);
  const medianIntervalS = median(intervals);

  // A candidate window qualifies as a flagged gap when it clears the hard floor AND either overlaps
  // the configured active hours, or (no active hours) is much larger than the typical cadence.
  const qualifies = (fromMs: number, toMs: number): boolean => {
    const durationS = (toMs - fromMs) / 1000;
    if (durationS < minGapSeconds) return false;
    if (activeHours) return overlapsActiveHours(fromMs, toMs, activeHours);
    if (densityFactor > 0 && medianIntervalS > 0) return durationS >= densityFactor * medianIntervalS;
    return true;
  };

  // Coverage of the window (fromMs, toMs) by OTHER sources, used to classify a per-source silence:
  //   • `active`  — the distinct other sources that logged inside the window (sorted)
  //   • `any`     — did anything at all log inside the window? (false ⇒ total darkness ⇒ Pass A owns it)
  //   • [darkFrom,darkTo] — the LONGEST internal stretch with no events (including the window edges).
  // A genuine PARTIAL gap means the environment stayed continuously LIT while one source was quiet; if
  // the window hides a long internal blackout (a qualifying complete gap), that's Pass A territory, not
  // a partial coverage blindspot — so callers skip it. Binary search over the ascending `starts`.
  const windowCoverage = (fromMs: number, toMs: number, exclude: string) => {
    const lo = firstIndexGreater(starts, fromMs);
    const set = new Set<string>();
    const times: number[] = [];
    for (let i = lo; i < dated.length && starts[i] < toMs; i++) {
      times.push(starts[i]);
      for (const s of sourcesOf(dated[i])) if (s !== exclude) set.add(s);
    }
    let darkFrom = fromMs;
    let darkTo = fromMs;
    let maxDark = -1;
    let prev = fromMs;
    for (const t of times) {
      if (t - prev > maxDark) { maxDark = t - prev; darkFrom = prev; darkTo = t; }
      prev = t;
    }
    if (toMs - prev > maxDark) { maxDark = toMs - prev; darkFrom = prev; darkTo = toMs; }
    return { active: [...set].sort(), any: times.length > 0, darkFrom, darkTo };
  };

  const gaps: TimelineGap[] = [];

  // Pass A — COMPLETE silence on the full timeline. Walk chronologically, tracking the running END of
  // activity so a long aggregated event doesn't open a false gap. A qualifying window between the
  // running end and the next event's start is a stretch where NOTHING logged → all sources silent.
  let prevEndMs = endMs(dated[0]);
  let prevEndTs = dated[0].endTimestamp || dated[0].timestamp;
  let prevId = dated[0].id;
  for (let i = 1; i < dated.length; i++) {
    const e = dated[i];
    const sMs = starts[i];
    if (sMs > prevEndMs && qualifies(prevEndMs, sMs)) {
      const durationSeconds = Math.round((sMs - prevEndMs) / 1000);
      gaps.push({
        id: "",
        startTimestamp: prevEndTs,
        endTimestamp: e.timestamp,
        durationSeconds,
        durationLabel: formatDuration(durationSeconds),
        severity: "High",
        complete: true,
        silentSources: allSources,
        activeSources: [],
        beforeEventId: prevId,
        afterEventId: e.id,
      });
    }
    const eEnd = endMs(e);
    if (eEnd >= prevEndMs) { prevEndMs = eEnd; prevEndTs = e.endTimestamp || e.timestamp; prevId = e.id; }
  }

  // Pass B — PARTIAL silence per source. Only meaningful with ≥2 named sources (with one source every
  // gap is already "complete"). For each source, a qualifying window between two of ITS events where
  // SOME other source kept logging is a coverage blindspot for that tool (Medium). A window with no
  // activity at all is a complete gap already captured by Pass A, so it's skipped here.
  if (allSources.length >= 2) {
    for (const source of allSources) {
      const own = dated.filter((e) => sourcesOf(e).includes(source));
      for (let i = 1; i < own.length; i++) {
        const a = own[i - 1];
        const b = own[i];
        const fromMs = endMs(a);
        const bStart = startMs(b);
        if (!(bStart > fromMs) || !qualifies(fromMs, bStart)) continue;
        const { active, any, darkFrom, darkTo } = windowCoverage(fromMs, bStart, source);
        if (!any) continue; // total darkness — Pass A owns this window
        if (qualifies(darkFrom, darkTo)) continue; // window hides a complete-silence sub-gap → Pass A territory
        const durationSeconds = Math.round((bStart - fromMs) / 1000);
        gaps.push({
          id: "",
          startTimestamp: a.endTimestamp || a.timestamp,
          endTimestamp: b.timestamp,
          durationSeconds,
          durationLabel: formatDuration(durationSeconds),
          severity: "Medium",
          complete: false,
          silentSources: [source],
          activeSources: active,
          beforeEventId: a.id,
          afterEventId: b.id,
        });
      }
    }
  }

  // Worst-first: complete (High) above partial (Medium), then the longest silence, then the earliest
  // start, then by bounding event id for a deterministic, stable order.
  gaps.sort(
    (x, y) =>
      SEV_RANK[x.severity] - SEV_RANK[y.severity] ||
      y.durationSeconds - x.durationSeconds ||
      Date.parse(x.startTimestamp) - Date.parse(y.startTimestamp) ||
      x.beforeEventId.localeCompare(y.beforeEventId),
  );
  gaps.forEach((g, i) => { g.id = `gap-${i + 1}`; });
  return gaps;
}

// Thresholds resolved from the environment so the route, the report, and the synthesis backfill agree:
//   DFIR_GAP_MIN_MINUTES   (default 30) — hard floor; a silence shorter than this is never flagged
//   DFIR_GAP_DENSITY_FACTOR (default 4) — gap must be ≥ this × the timeline's median cadence to flag
//   DFIR_GAP_ACTIVE_HOURS   (unset)     — "START-END" UTC hours (e.g. "8-18"); when set, supersedes density
//   DFIR_GAP_MAX_FINDINGS  (default 5)  — cap on complete-silence gaps that escalate to a finding
//   DFIR_GAP_OUTLIER_SPAN  (default 5)  — drop mis-dated strays beyond this × the core time span; 0 disables
export function gapEnvOptions(): GapOptions {
  const minGapMinutes = Number(process.env.DFIR_GAP_MIN_MINUTES) || DEFAULT_GAP_MIN_MINUTES;
  const num = (raw: string | undefined, dflt: number): number =>
    raw !== undefined && raw.trim() !== "" && Number.isFinite(Number(raw)) ? Number(raw) : dflt;
  return {
    minGapMinutes,
    densityFactor: num(process.env.DFIR_GAP_DENSITY_FACTOR, DEFAULT_GAP_DENSITY_FACTOR),
    activeHours: parseActiveHours(process.env.DFIR_GAP_ACTIVE_HOURS),
    maxFindings: num(process.env.DFIR_GAP_MAX_FINDINGS, DEFAULT_GAP_MAX_FINDINGS),
    outlierSpanFactor: num(process.env.DFIR_GAP_OUTLIER_SPAN, DEFAULT_GAP_OUTLIER_SPAN),
  };
}

// Parse a "START-END" active-hours string (UTC hours, 0..23), e.g. "8-18" or "22-6" (wrap-around).
// Returns null when unset/blank/malformed so the density heuristic stays the default.
export function parseActiveHours(raw: string | undefined): { start: number; end: number } | null {
  if (!raw || !raw.trim()) return null;
  const m = raw.trim().match(/^(\d{1,2})\s*-\s*(\d{1,2})$/);
  if (!m) return null;
  const start = Number(m[1]);
  const end = Number(m[2]);
  if (!Number.isInteger(start) || !Number.isInteger(end) || start > 23 || end > 23) return null;
  return { start, end };
}

// Deterministic safety net (issue #83): a COMPLETE-silence gap — a window where every source went
// dark — is the classic signature of cleared logs / a stopped collector, so it earns a finding even
// though no single event is "high severity". Mirrors the high-severity backfill: pure (returns a new
// state, never mutates), and idempotent — the finding id is derived from the bounding event ids, so
// re-running synthesis over an unchanged timeline produces the same finding rather than duplicating.
//
// Only COMPLETE gaps generate findings; partial (single-tool) gaps surface in the panel/report as
// coverage notes but don't escalate. Confidence is deliberately moderate — a gap is a lead, not proof.
export function backfillSilenceGapFindings(
  state: InvestigationState,
  gaps: readonly TimelineGap[],
  timestamp: string,
  maxFindings: number = DEFAULT_GAP_MAX_FINDINGS,
): InvestigationState {
  const cap = Math.max(0, Math.floor(maxFindings));
  const existingIds = new Set(state.findings.map((f) => f.id));
  const newFindings: Finding[] = [];
  // `gaps` is sorted worst-first, so the complete gaps stream out longest-first — keep the worst `cap`.
  for (const gap of gaps) {
    if (!gap.complete) continue;
    if (newFindings.length >= cap) break;
    // Idempotency key derived from the bounding events — stable across synthesis runs over the same
    // gap (so re-synthesis refreshes rather than duplicates), and unique per distinct gap.
    const id = `f-gap-${gap.beforeEventId}-${gap.afterEventId}`;
    if (existingIds.has(id)) continue;
    existingIds.add(id);
    // The start time keeps the title unique per gap — two gaps of equal duration are distinct facts,
    // and the diff (by title) shouldn't collapse them or re-announce an unchanged one.
    const title = `Timeline coverage gap: ${gap.durationLabel} of complete silence from ${gap.startTimestamp}`;
    const sources = gap.silentSources.length ? gap.silentSources.join(", ") : "all sources";
    newFindings.push({
      id,
      severity: "High",
      confidence: 50,
      title,
      description:
        `No forensic activity was recorded from ${gap.startTimestamp} to ${gap.endTimestamp} ` +
        `(${gap.durationLabel}) — every source went silent (${sources}). A complete coverage gap is a ` +
        `classic indicator of log tampering (cleared Windows Event Logs, a stopped collector/auditd, or ` +
        `deleted log files) or a collection blindspot. ${GAP_CAVEAT}`,
      relatedIocs: [],
      mitreTechniques: ["T1070"], // Indicator Removal — missing/cleared logs
      sourceScreenshots: [],
      firstSeen: gap.startTimestamp || timestamp,
      lastUpdated: timestamp,
      status: "open",
    });
  }
  if (newFindings.length === 0) return state;
  return { ...state, findings: [...state.findings, ...newFindings] };
}
