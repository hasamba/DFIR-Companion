import type { ForensicEvent, Finding, InvestigationState } from "./stateTypes.js";
import { byEventTime } from "./forensicSort.js";
import {
  detectTimelineGaps,
  endMs,
  endTsStr,
  formatDuration,
  type GapOptions,
  type TimelineGap,
} from "./gapDetect.js";

// Activity-wave detection — the other reading of a long silence.
//
// gapDetect.ts flags a stretch where every source went quiet. That framing has one built-in
// assumption: the silence means data is MISSING. Often it does — cleared logs, a stopped collector,
// a collection window that started late. But when substantial activity sits on BOTH sides of the
// quiet stretch, the more likely reading is the opposite one: nothing is missing, and the host was
// touched twice, with a real dwell interval in between.
//
// That distinction matters more than it sounds. A staged intrusion — initial access, a long quiet
// period while the operator sells or sits on the access, then a return through the same unpatched
// door — produces exactly this shape, and the interval between the waves IS the finding. Reported
// as three separate "coverage gap" complaints, the same data says only that the collection is poor.
//
// So: split the timeline on the complete-silence gaps, keep the segments substantial enough to be
// real activity, and if two or more survive, report the cadence. The gaps between them are then
// re-labelled as wave boundaries rather than suspected tampering.
//
// Pure and deterministic, NO AI call — like gap detection itself, derived on read from the timeline.
//
// FRAMING, same as gaps: a wave pattern is a LEAD. Two bursts of activity with a quiet middle can
// also be one intrusion plus an unrelated later administrative session. The interval is a fact; what
// filled it is not.

export interface ActivityWave {
  index: number; // 1-based position in time order
  startTimestamp: string; // first event in the wave
  endTimestamp: string; // last event in the wave
  durationSeconds: number; // how long the wave itself lasted
  durationLabel: string; // human-readable wave duration
  eventCount: number; // events inside the wave
  firstEventId: string; // bounding event ids, for back-linking a finding to the timeline
  lastEventId: string;
}

export interface WaveInterval {
  fromWave: number; // 1-based index of the wave that ended
  toWave: number; // 1-based index of the wave that began
  durationSeconds: number; // the quiet interval between them
  durationLabel: string;
}

export interface WavePattern {
  waves: ActivityWave[]; // always ≥2 — a single wave is not a pattern
  intervals: WaveInterval[]; // waves.length - 1 entries, in time order
  longestIntervalSeconds: number; // the widest quiet stretch between two waves
  longestIntervalLabel: string;
  totalSpanSeconds: number; // first wave start → last wave end
  totalSpanLabel: string;
}

export interface WaveOptions {
  // A timeline segment must hold at least this many events to count as a wave, so one stray
  // mis-dated event can't masquerade as a second intrusion. Default 3.
  minWaveEvents?: number;
  // The quiet stretch between two waves must be at least this many hours. Below it, two bursts are
  // one working session with a coffee break, not two visits. Default 6.
  minWaveIntervalHours?: number;
}

export const DEFAULT_MIN_WAVE_EVENTS = 3;
export const DEFAULT_MIN_WAVE_INTERVAL_HOURS = 6;

// The shared "this is a lead, not a verdict" disclaimer, mirroring GAP_CAVEAT.
export const WAVE_CAVEAT =
  "A wave pattern is a lead, not proof of a staged intrusion — two bursts of activity around a quiet " +
  "interval can equally be one intrusion followed by unrelated administrative work, or a collection " +
  "that only covers part of the middle. The interval itself is a fact; what filled it is not. Confirm " +
  "against the collection scope, and check whether the later wave reuses access established by the earlier one.";

const MS_PER_HOUR = 3_600_000;

function startMs(e: ForensicEvent): number {
  return Date.parse(e.timestamp);
}

// Split the time-sorted events into segments on the boundaries of the COMPLETE-silence gaps. A
// partial gap (one tool quiet while others logged) is not a boundary — the environment stayed lit.
function segmentOnCompleteGaps(
  sorted: readonly ForensicEvent[],
  gaps: readonly TimelineGap[],
  minIntervalMs: number,
): ForensicEvent[][] {
  // Gap boundaries keyed by the event that RESUMES activity: that event opens a new segment.
  const resumesAt = new Set(
    gaps.filter((g) => g.complete && g.durationSeconds * 1000 >= minIntervalMs).map((g) => g.afterEventId),
  );
  const segments: ForensicEvent[][] = [];
  let current: ForensicEvent[] = [];
  for (const e of sorted) {
    if (current.length > 0 && resumesAt.has(e.id)) {
      segments.push(current);
      current = [];
    }
    current.push(e);
  }
  if (current.length > 0) segments.push(current);
  return segments;
}

// Detect a multi-wave activity pattern. Returns null when the timeline is one continuous stretch of
// activity, or when only one segment is substantial enough to count as a wave.
export function detectActivityWaves(
  events: readonly ForensicEvent[],
  gaps: readonly TimelineGap[],
  opts: WaveOptions = {},
): WavePattern | null {
  const minEvents = Math.max(1, Math.floor(opts.minWaveEvents ?? DEFAULT_MIN_WAVE_EVENTS));
  const minIntervalMs = Math.max(
    0,
    (opts.minWaveIntervalHours ?? DEFAULT_MIN_WAVE_INTERVAL_HOURS) * MS_PER_HOUR,
  );

  const sorted = events.filter((e) => !Number.isNaN(startMs(e))).sort(byEventTime);
  if (sorted.length < 2) return null;

  // Thin segments are trimmed from the ENDS only. That asymmetry is the whole point: a lone
  // mis-dated event sitting before or after everything else is a stray, but a lone event BETWEEN two
  // bursts is real activity, and discarding it would make the surviving bursts look adjacent —
  // producing an interval that asserts continuous silence across a period that demonstrably had an
  // event in it, and marking only one of the two real gaps as a boundary. Keeping interior segments
  // makes every interval a genuine complete-silence gap by construction, since the segmentation split
  // on exactly those gaps.
  const segments = segmentOnCompleteGaps(sorted, gaps, minIntervalMs);
  while (segments.length && segments[0].length < minEvents) segments.shift();
  while (segments.length && segments[segments.length - 1].length < minEvents) segments.pop();
  if (segments.length < 2) return null;
  // A pattern needs substantial activity on both sides of a silence. Two blips either side of a
  // quiet stretch are not two intrusions, however far apart they sit.
  if (segments.filter((seg) => seg.length >= minEvents).length < 2) return null;

  const waves: ActivityWave[] = segments.map((seg, i) => {
    const first = seg[0];
    // A wave ends where gapDetect says activity ended: the running MAXIMUM end time, so a long
    // aggregated row ("20 logons over 3h") closes the wave at its end rather than at the start of
    // whichever row happens to sort last. Using the last row's timestamp would report a dwell
    // interval that overlaps activity the aggregate covers, and link the wrong boundary event.
    let last = first;
    let lastEnd = endMs(first);
    for (const e of seg) {
      const t = endMs(e);
      if (t >= lastEnd) {
        lastEnd = t;
        last = e;
      }
    }
    const durationSeconds = Math.max(0, Math.round((lastEnd - startMs(first)) / 1000));
    return {
      index: i + 1,
      startTimestamp: first.timestamp,
      endTimestamp: endTsStr(last),
      durationSeconds,
      durationLabel: formatDuration(durationSeconds),
      eventCount: seg.length,
      firstEventId: first.id,
      lastEventId: last.id,
    };
  });

  const intervals: WaveInterval[] = [];
  for (let i = 1; i < waves.length; i++) {
    const durationSeconds = Math.max(
      0,
      Math.round((Date.parse(waves[i].startTimestamp) - Date.parse(waves[i - 1].endTimestamp)) / 1000),
    );
    intervals.push({
      fromWave: waves[i - 1].index,
      toWave: waves[i].index,
      durationSeconds,
      durationLabel: formatDuration(durationSeconds),
    });
  }

  // Trimming thin segments off the ends can leave two surviving waves separated by less than the
  // minimum, so re-check the real inter-wave intervals rather than trusting the gap-level filter.
  const longestIntervalSeconds = intervals.reduce((m, iv) => Math.max(m, iv.durationSeconds), 0);
  if (longestIntervalSeconds * 1000 < minIntervalMs) return null;

  const totalSpanSeconds = Math.max(
    0,
    Math.round(
      (Date.parse(waves[waves.length - 1].endTimestamp) - Date.parse(waves[0].startTimestamp)) / 1000,
    ),
  );

  return {
    waves,
    intervals,
    longestIntervalSeconds,
    longestIntervalLabel: formatDuration(longestIntervalSeconds),
    totalSpanSeconds,
    totalSpanLabel: formatDuration(totalSpanSeconds),
  };
}

// THE one entry point every gap consumer should use. Detection and wave-marking are a single step
// here on purpose: the classification is not synthesis's private opinion, it is a property of the
// timeline, and any surface that renders an unmarked gap contradicts the finding written about the
// same window. When only synthesis marked boundaries, a 15-day dwell interval appeared as a Medium
// "dwell interval" finding while the coverage panel and the Markdown report still called that exact
// window a High complete-silence log-tampering gap.
//
// Callers that need the pattern itself (to emit the cadence finding) take it from the second field;
// callers that only render gaps can ignore it and still get the right labels.
export function detectGapsWithWaves(
  events: readonly ForensicEvent[],
  gapOpts?: GapOptions,
  waveOpts?: WaveOptions,
): { gaps: TimelineGap[]; pattern: WavePattern | null } {
  const raw = detectTimelineGaps(events, gapOpts);
  const pattern = detectActivityWaves(events, raw, waveOpts ?? waveEnvOptions());
  return { gaps: markWaveBoundaries(raw, pattern), pattern };
}

// Thresholds resolved from the environment so synthesis, the report, and any route agree:
//   DFIR_WAVE_MIN_EVENTS         (default 3) — events a segment needs before it counts as a wave
//   DFIR_WAVE_MIN_INTERVAL_HOURS (default 6) — quiet hours between two waves before they are separate
export function waveEnvOptions(): WaveOptions {
  const num = (raw: string | undefined, dflt: number): number =>
    raw !== undefined && raw.trim() !== "" && Number.isFinite(Number(raw)) ? Number(raw) : dflt;
  return {
    minWaveEvents: num(process.env.DFIR_WAVE_MIN_EVENTS, DEFAULT_MIN_WAVE_EVENTS),
    minWaveIntervalHours: num(process.env.DFIR_WAVE_MIN_INTERVAL_HOURS, DEFAULT_MIN_WAVE_INTERVAL_HOURS),
  };
}

// Flag the gaps that separate two detected waves. Those silences are accounted for — activity
// resumes on the far side — so the surfaces that render them can say "interval between wave 1 and
// wave 2" instead of repeating the log-tampering framing. Pure: returns new gap objects.
export function markWaveBoundaries(gaps: readonly TimelineGap[], pattern: WavePattern | null): TimelineGap[] {
  if (!pattern) return [...gaps];
  // A gap is a boundary when it ends exactly where a wave begins — the same resume event that
  // segmentOnCompleteGaps split on. Matching by event id (not timestamp) keeps duplicate
  // timestamps from marking the wrong gap.
  const waveStartIds = new Set(pattern.waves.slice(1).map((w) => w.firstEventId));
  return gaps.map((g) =>
    g.complete && waveStartIds.has(g.afterEventId) ? { ...g, betweenWaves: true } : { ...g },
  );
}

// One finding for the whole pattern, not one per boundary. The cadence is a single fact about the
// intrusion: it was staged across N visits spanning X. Idempotent — the id is fixed, so re-running
// synthesis over an unchanged timeline refreshes rather than duplicates.
export function backfillActivityWaveFinding(
  state: InvestigationState,
  pattern: WavePattern | null,
  timestamp: string,
): InvestigationState {
  if (!pattern) return state;
  const id = "f-waves";
  if (state.findings.some((f) => f.id === id)) return state;

  const waveList = pattern.waves
    .map((w) => `wave ${w.index} (${w.eventCount} events, ${w.startTimestamp} → ${w.endTimestamp})`)
    .join("; ");
  const intervalList = pattern.intervals
    .map((iv) => `${iv.durationLabel} between wave ${iv.fromWave} and wave ${iv.toWave}`)
    .join(", ");

  const finding: Finding = {
    id,
    severity: "High",
    confidence: 55,
    title: `Activity occurred in ${pattern.waves.length} separate waves spanning ${pattern.totalSpanLabel}`,
    description:
      `The timeline is not one continuous session. Activity clusters into ${pattern.waves.length} waves — ` +
      `${waveList} — separated by ${intervalList}. Because substantial activity sits on BOTH sides of each ` +
      `quiet stretch, the silence is far more likely to be genuine dwell time between visits than missing ` +
      `data: total elapsed time from the first activity to the last is ${pattern.totalSpanLabel}, of which ` +
      `${pattern.longestIntervalLabel} is a single quiet interval. Establish whether the later wave reuses ` +
      `access, accounts, or an unpatched entry point established by the earlier one — a returning operator ` +
      `is a different containment problem from a single-session intrusion. ${WAVE_CAVEAT}`,
    relatedIocs: [],
    mitreTechniques: [],
    sourceScreenshots: [],
    firstSeen: pattern.waves[0].startTimestamp || timestamp,
    lastUpdated: timestamp,
    status: "open",
  };

  // Back-link to the bounding events of every wave so the dashboard's scope projection can drop the
  // finding when the analyst narrows the window past it, exactly as gap findings do.
  const linkIds = new Set(pattern.waves.flatMap((w) => [w.firstEventId, w.lastEventId]));
  return {
    ...state,
    findings: [...state.findings, finding],
    forensicTimeline: state.forensicTimeline.map((e) =>
      linkIds.has(e.id) && !e.relatedFindingIds.includes(id)
        ? { ...e, relatedFindingIds: [...e.relatedFindingIds, id] }
        : e,
    ),
  };
}
