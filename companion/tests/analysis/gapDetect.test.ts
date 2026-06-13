import { describe, it, expect } from "vitest";
import {
  detectTimelineGaps,
  backfillSilenceGapFindings,
  gapEnvOptions,
  parseActiveHours,
  formatDuration,
  DEFAULT_GAP_MIN_MINUTES,
  DEFAULT_GAP_DENSITY_FACTOR,
  DEFAULT_GAP_MAX_FINDINGS,
} from "../../src/analysis/gapDetect.js";
import { emptyState, type ForensicEvent, type Finding, type InvestigationState } from "../../src/analysis/stateTypes.js";

function ev(id: string, timestamp: string, extra: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp,
    description: extra.description ?? "",
    severity: extra.severity ?? "Info",
    mitreTechniques: extra.mitreTechniques ?? [],
    relatedFindingIds: extra.relatedFindingIds ?? [],
    sourceScreenshots: [],
    ...extra,
  };
}

// N events spaced `intervalS` seconds apart starting at `startISO`, tagged with `source`.
function series(prefix: string, source: string, startISO: string, intervalS: number, count: number): ForensicEvent[] {
  const out: ForensicEvent[] = [];
  let ms = Date.parse(startISO);
  for (let i = 0; i < count; i++) {
    out.push(ev(`${prefix}${i}`, new Date(ms).toISOString(), { sources: [source] }));
    ms += intervalS * 1000;
  }
  return out;
}

describe("detectTimelineGaps", () => {
  it("returns nothing for empty / single-event timelines", () => {
    expect(detectTimelineGaps([])).toEqual([]);
    expect(detectTimelineGaps([ev("e1", "2026-05-20T10:00:00Z")])).toEqual([]);
  });

  it("flags a complete-silence gap on a dense single-source timeline", () => {
    // 10 events one minute apart, then a 2-hour hole, then activity resumes — one source throughout.
    const before = series("a", "EventLog", "2026-05-20T08:00:00Z", 60, 10); // 08:00 → 08:09
    const after = series("b", "EventLog", "2026-05-20T10:09:00Z", 60, 5); // resumes at 10:09 (2h gap)
    const gaps = detectTimelineGaps([...before, ...after]);
    expect(gaps).toHaveLength(1);
    const g = gaps[0];
    expect(g.id).toBe("gap-1");
    expect(g.complete).toBe(true);
    expect(g.severity).toBe("High");
    expect(g.silentSources).toEqual(["EventLog"]);
    expect(g.activeSources).toEqual([]);
    expect(g.startTimestamp).toBe("2026-05-20T08:09:00.000Z");
    expect(g.endTimestamp).toBe("2026-05-20T10:09:00.000Z");
    expect(g.durationSeconds).toBe(2 * 3600);
    expect(g.durationLabel).toBe("2h");
    expect(g.beforeEventId).toBe("a9");
    expect(g.afterEventId).toBe("b0");
  });

  it("ignores gaps below the hard floor", () => {
    // Dense cadence (1 min) with a single 20-minute gap — under the 30-minute floor → not flagged.
    const before = series("a", "EventLog", "2026-05-20T08:00:00Z", 60, 10);
    const after = series("b", "EventLog", "2026-05-20T08:29:00Z", 60, 5); // 20-min gap from 08:09
    expect(detectTimelineGaps([...before, ...after])).toEqual([]);
  });

  it("density heuristic suppresses normal gaps in a naturally sparse timeline", () => {
    // Events every 40 minutes — a 45-minute gap is normal cadence. Floor (30m) alone would flag it,
    // but density (≥ 4 × median ≈ 160m) does not.
    const evs = [
      ev("s0", "2026-05-20T00:00:00Z", { sources: ["EventLog"] }),
      ev("s1", "2026-05-20T00:40:00Z", { sources: ["EventLog"] }),
      ev("s2", "2026-05-20T01:20:00Z", { sources: ["EventLog"] }),
      ev("s3", "2026-05-20T02:05:00Z", { sources: ["EventLog"] }), // 45-min gap
      ev("s4", "2026-05-20T02:45:00Z", { sources: ["EventLog"] }),
    ];
    expect(detectTimelineGaps(evs)).toEqual([]);
    // But a 4-hour hole in the same sparse stream clears the density bar → flagged.
    const withHole = [...evs, ev("s5", "2026-05-20T06:45:00Z", { sources: ["EventLog"] })];
    const gaps = detectTimelineGaps(withHole);
    expect(gaps).toHaveLength(1);
    expect(gaps[0].complete).toBe(true);
  });

  it("disabling the density factor falls back to the floor only", () => {
    const before = series("a", "EventLog", "2026-05-20T00:00:00Z", 2400, 4); // every 40 min
    const after = series("b", "EventLog", "2026-05-20T03:00:00Z", 2400, 2); // ~1h gap from last
    // With density off, the floor (30m) governs → the ~1h gap flags.
    const gaps = detectTimelineGaps([...before, ...after], { densityFactor: 0 });
    expect(gaps.length).toBeGreaterThanOrEqual(1);
    expect(gaps[0].complete).toBe(true);
  });

  it("classifies a single tool going quiet (others active) as a partial Medium gap", () => {
    // Velociraptor logs steadily all morning; THOR logs once at the start, then goes silent for 3h
    // while Velociraptor keeps going. THOR's silence is a coverage blindspot, not total darkness.
    const velo = series("v", "Velociraptor", "2026-05-20T08:00:00Z", 60, 200); // 08:00 → ~11:19
    const thorEarly = ev("t0", "2026-05-20T08:01:00Z", { sources: ["THOR"] });
    const thorLate = ev("t1", "2026-05-20T11:10:00Z", { sources: ["THOR"] }); // ~3h silence
    const gaps = detectTimelineGaps([...velo, thorEarly, thorLate]);
    const partial = gaps.filter((g) => !g.complete);
    expect(partial).toHaveLength(1);
    expect(partial[0].severity).toBe("Medium");
    expect(partial[0].silentSources).toEqual(["THOR"]);
    expect(partial[0].activeSources).toEqual(["Velociraptor"]);
    // No complete gap here — Velociraptor logged the whole time.
    expect(gaps.some((g) => g.complete)).toBe(false);
  });

  it("does not emit a partial gap when the window is total darkness (Pass A owns it)", () => {
    // Two sources both log early, then EVERYTHING goes dark for 3h. The silence is complete — it must
    // appear once as a High complete gap, never as per-source partial gaps.
    const a = [
      ev("a0", "2026-05-20T08:00:00Z", { sources: ["EventLog"] }),
      ev("a1", "2026-05-20T08:01:00Z", { sources: ["Sysmon"] }),
      ev("a2", "2026-05-20T08:02:00Z", { sources: ["EventLog"] }),
      ev("a3", "2026-05-20T08:03:00Z", { sources: ["Sysmon"] }),
    ];
    const resume = [
      ev("r0", "2026-05-20T11:03:00Z", { sources: ["EventLog"] }),
      ev("r1", "2026-05-20T11:04:00Z", { sources: ["Sysmon"] }),
    ];
    const gaps = detectTimelineGaps([...a, ...resume]);
    const complete = gaps.filter((g) => g.complete);
    expect(complete).toHaveLength(1);
    expect(complete[0].silentSources).toEqual(["EventLog", "Sysmon"]);
    expect(gaps.filter((g) => !g.complete)).toEqual([]);
  });

  it("sorts worst-first: complete (High) above partial (Medium), then longest", () => {
    const velo = series("v", "Velociraptor", "2026-05-20T08:00:00Z", 60, 400); // dense, ~6.6h coverage
    const thor = [
      ev("t0", "2026-05-20T08:01:00Z", { sources: ["THOR"] }),
      ev("t1", "2026-05-20T10:00:00Z", { sources: ["THOR"] }), // ~2h partial gap (velo active)
    ];
    // A complete blackout AFTER velo stops: last velo ~14:39, resume at 18:39 (4h, all silent).
    const resume = series("z", "Velociraptor", "2026-05-20T18:39:00Z", 60, 5);
    const gaps = detectTimelineGaps([...velo, ...thor, ...resume]);
    expect(gaps[0].complete).toBe(true); // High first
    expect(gaps[0].severity).toBe("High");
    expect(gaps.some((g) => !g.complete && g.silentSources[0] === "THOR")).toBe(true);
    // ids assigned worst-first
    expect(gaps[0].id).toBe("gap-1");
  });

  it("respects configured active hours (overnight silence suppressed)", () => {
    // Dense daytime cadence, then silence from 18:00 to 08:00 the next day (overnight, outside 08-18).
    const day = series("d", "EventLog", "2026-05-20T16:00:00Z", 120, 61); // 16:00 → 18:00
    const next = series("n", "EventLog", "2026-05-21T08:00:00Z", 120, 10); // resumes 08:00
    const all = [...day, ...next];
    // Active hours 08-18: the gap (18:00→08:00) is entirely outside working hours → not flagged.
    expect(detectTimelineGaps(all, { activeHours: { start: 8, end: 18 } })).toEqual([]);
    // Without active hours, the density heuristic flags the long overnight hole.
    expect(detectTimelineGaps(all).length).toBeGreaterThanOrEqual(1);
  });

  it("flags a gap that overlaps active hours", () => {
    // Silence from 09:00 to 11:00 — squarely inside 08-18 working hours.
    const before = series("a", "EventLog", "2026-05-20T08:00:00Z", 60, 60); // → 08:59
    const after = series("b", "EventLog", "2026-05-20T11:00:00Z", 60, 5); // 2h+ gap inside hours
    const gaps = detectTimelineGaps([...before, ...after], { activeHours: { start: 8, end: 18 } });
    expect(gaps).toHaveLength(1);
    expect(gaps[0].complete).toBe(true);
  });

  it("closes the gap at an aggregated event's end, not its start", () => {
    // An aggregated row spanning 08:00→11:00, then the next event at 11:10. Naively measuring from the
    // start (08:00) would invent a 3h+ gap; measuring from the END (11:00) sees only a 10-minute gap.
    const agg = ev("agg", "2026-05-20T08:00:00Z", {
      sources: ["EventLog"],
      endTimestamp: "2026-05-20T11:00:00Z",
      count: 50,
    });
    const next = ev("next", "2026-05-20T11:10:00Z", { sources: ["EventLog"] });
    expect(detectTimelineGaps([agg, next])).toEqual([]); // 10-min gap < 30-min floor
  });

  it("skips events with an unparseable timestamp", () => {
    const before = series("a", "EventLog", "2026-05-20T08:00:00Z", 60, 5);
    const bad = ev("bad", "not-a-date", { sources: ["EventLog"] });
    const after = series("b", "EventLog", "2026-05-20T10:30:00Z", 60, 5);
    const gaps = detectTimelineGaps([...before, bad, ...after]);
    expect(gaps).toHaveLength(1); // the undated event is ignored; the real 2h+ hole is still found
    expect(gaps[0].complete).toBe(true);
  });
});

describe("backfillSilenceGapFindings", () => {
  const baseState = (findings: Finding[] = []): InvestigationState => ({ ...emptyState("c1"), findings });

  it("creates a High finding for a complete-silence gap and ignores partial gaps", () => {
    const before = series("a", "EventLog", "2026-05-20T08:00:00Z", 60, 10);
    const after = series("b", "EventLog", "2026-05-20T10:09:00Z", 60, 5);
    const gaps = detectTimelineGaps([...before, ...after]);
    const next = backfillSilenceGapFindings(baseState(), gaps, "2026-05-20T12:00:00Z");
    expect(next.findings).toHaveLength(1);
    const f = next.findings[0];
    expect(f.severity).toBe("High");
    expect(f.confidence).toBe(50);
    expect(f.mitreTechniques).toEqual(["T1070"]);
    expect(f.title).toContain("complete silence");
    expect(f.id).toBe("f-gap-a9-b0");
  });

  it("is idempotent — re-running over the same gaps does not duplicate findings", () => {
    const before = series("a", "EventLog", "2026-05-20T08:00:00Z", 60, 10);
    const after = series("b", "EventLog", "2026-05-20T10:09:00Z", 60, 5);
    const gaps = detectTimelineGaps([...before, ...after]);
    const once = backfillSilenceGapFindings(baseState(), gaps, "2026-05-20T12:00:00Z");
    const twice = backfillSilenceGapFindings(once, gaps, "2026-05-20T12:05:00Z");
    expect(twice.findings).toHaveLength(1);
    expect(twice).toBe(once); // no new findings → same object returned
  });

  it("returns the state unchanged when there are no complete gaps", () => {
    const state = baseState();
    expect(backfillSilenceGapFindings(state, [], "2026-05-20T12:00:00Z")).toBe(state);
  });

  it("caps the number of complete-gap findings (worst-first) so a super-timeline case can't flood", () => {
    // Five separated complete-silence blackouts in one sparse timeline → five complete gaps.
    const blocks = ["08:00", "12:00", "16:00", "20:00", "23:30"].flatMap((_, b) => {
      const base = Date.parse(`2026-05-2${b}T08:00:00Z`); // each on its own day → big inter-block gaps
      return [0, 1, 2].map((i) => ev(`b${b}_${i}`, new Date(base + i * 60_000).toISOString(), { sources: ["EventLog"] }));
    });
    const gaps = detectTimelineGaps(blocks);
    expect(gaps.filter((g) => g.complete).length).toBeGreaterThanOrEqual(4);
    // Cap at 2 → only the two longest complete gaps escalate to findings.
    const next = backfillSilenceGapFindings(baseState(), gaps, "2026-05-29T00:00:00Z", 2);
    expect(next.findings).toHaveLength(2);
    // Cap 0 → no findings.
    expect(backfillSilenceGapFindings(baseState(), gaps, "2026-05-29T00:00:00Z", 0).findings).toHaveLength(0);
  });
});

describe("formatDuration", () => {
  it("renders compact human labels", () => {
    expect(formatDuration(45)).toBe("45s");
    expect(formatDuration(60)).toBe("1m");
    expect(formatDuration(45 * 60)).toBe("45m");
    expect(formatDuration(2 * 3600)).toBe("2h");
    expect(formatDuration(2 * 3600 + 15 * 60)).toBe("2h 15m");
    expect(formatDuration(86400 + 3 * 3600)).toBe("1d 3h");
  });
});

describe("parseActiveHours", () => {
  it("parses START-END strings and rejects malformed input", () => {
    expect(parseActiveHours("8-18")).toEqual({ start: 8, end: 18 });
    expect(parseActiveHours(" 22 - 6 ")).toEqual({ start: 22, end: 6 });
    expect(parseActiveHours(undefined)).toBeNull();
    expect(parseActiveHours("")).toBeNull();
    expect(parseActiveHours("nope")).toBeNull();
    expect(parseActiveHours("8-25")).toBeNull(); // hour out of range
  });
});

describe("gapEnvOptions", () => {
  it("defaults when env is unset", () => {
    delete process.env.DFIR_GAP_MIN_MINUTES;
    delete process.env.DFIR_GAP_DENSITY_FACTOR;
    delete process.env.DFIR_GAP_ACTIVE_HOURS;
    delete process.env.DFIR_GAP_MAX_FINDINGS;
    expect(gapEnvOptions()).toEqual({
      minGapMinutes: DEFAULT_GAP_MIN_MINUTES,
      densityFactor: DEFAULT_GAP_DENSITY_FACTOR,
      activeHours: null,
      maxFindings: DEFAULT_GAP_MAX_FINDINGS,
    });
  });

  it("reads overrides from the environment", () => {
    process.env.DFIR_GAP_MIN_MINUTES = "60";
    process.env.DFIR_GAP_DENSITY_FACTOR = "0";
    process.env.DFIR_GAP_ACTIVE_HOURS = "9-17";
    process.env.DFIR_GAP_MAX_FINDINGS = "3";
    expect(gapEnvOptions()).toEqual({ minGapMinutes: 60, densityFactor: 0, activeHours: { start: 9, end: 17 }, maxFindings: 3 });
    delete process.env.DFIR_GAP_MIN_MINUTES;
    delete process.env.DFIR_GAP_DENSITY_FACTOR;
    delete process.env.DFIR_GAP_ACTIVE_HOURS;
    delete process.env.DFIR_GAP_MAX_FINDINGS;
  });
});
