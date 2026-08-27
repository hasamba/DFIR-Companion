import { describe, it, expect } from "vitest";
import {
  detectActivityWaves,
  markWaveBoundaries,
  backfillActivityWaveFinding,
  detectGapsWithWaves,
  DEFAULT_MIN_WAVE_EVENTS,
  DEFAULT_MIN_WAVE_INTERVAL_HOURS,
} from "../../src/analysis/activityWaves.js";
import { detectTimelineGaps, backfillSilenceGapFindings } from "../../src/analysis/gapDetect.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

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

// `count` events one minute apart starting at `startISO`.
function burst(prefix: string, startISO: string, count: number): ForensicEvent[] {
  const out: ForensicEvent[] = [];
  let ms = Date.parse(startISO);
  for (let i = 0; i < count; i++) {
    out.push(ev(`${prefix}${i}`, new Date(ms).toISOString(), { sources: ["velo"] }));
    ms += 60_000;
  }
  return out;
}

// The INC-2026-003 shape: a wave 19 days back, a wave 1 day back, then the live collection run.
function twoWaveTimeline(): ForensicEvent[] {
  return [
    ...burst("w1-", "2026-08-07T14:30:00.000Z", 6),
    ...burst("w2-", "2026-08-25T17:30:00.000Z", 6),
    ...burst("w3-", "2026-08-26T13:45:00.000Z", 6),
  ];
}

describe("detectActivityWaves", () => {
  it("splits a timeline into waves on complete-silence gaps", () => {
    const events = twoWaveTimeline();
    const gaps = detectTimelineGaps(events);
    const pattern = detectActivityWaves(events, gaps);
    expect(pattern).not.toBeNull();
    expect(pattern!.waves).toHaveLength(3);
    expect(pattern!.waves[0].eventCount).toBe(6);
    expect(pattern!.waves[0].startTimestamp).toBe("2026-08-07T14:30:00.000Z");
    expect(pattern!.waves[2].endTimestamp).toBe("2026-08-26T13:50:00.000Z");
  });

  it("reports the interval between consecutive waves and the total span", () => {
    const events = twoWaveTimeline();
    const pattern = detectActivityWaves(events, detectTimelineGaps(events))!;
    expect(pattern.intervals).toHaveLength(2);
    // 2026-08-07T14:35 → 2026-08-25T17:30 is a little over 18 days.
    expect(pattern.intervals[0].durationLabel).toBe("18d 2h");
    expect(pattern.totalSpanLabel).toBe("18d 23h");
  });

  it("returns null for a single continuous burst of activity", () => {
    const events = burst("a-", "2026-08-26T13:00:00.000Z", 10);
    expect(detectActivityWaves(events, detectTimelineGaps(events))).toBeNull();
  });

  it("ignores a segment too small to be a wave", () => {
    // One stray event 19 days before a real burst is not a second wave.
    const events = [
      ev("stray", "2026-08-07T14:30:00.000Z", { sources: ["velo"] }),
      ...burst("b-", "2026-08-26T13:00:00.000Z", 8),
    ];
    expect(detectActivityWaves(events, detectTimelineGaps(events))).toBeNull();
  });

  it("ignores a quiet stretch shorter than the minimum wave interval", () => {
    // Two bursts an hour apart are one session, not two intrusions.
    const events = [
      ...burst("c-", "2026-08-26T09:00:00.000Z", 6),
      ...burst("d-", "2026-08-26T10:00:00.000Z", 6),
    ];
    expect(detectActivityWaves(events, detectTimelineGaps(events))).toBeNull();
  });

  it("respects minWaveEvents and minWaveIntervalHours overrides", () => {
    const events = [
      ...burst("c-", "2026-08-26T09:00:00.000Z", 6),
      ...burst("d-", "2026-08-26T10:00:00.000Z", 6),
    ];
    const pattern = detectActivityWaves(events, detectTimelineGaps(events), { minWaveIntervalHours: 0.5 });
    expect(pattern!.waves).toHaveLength(2);
    expect(DEFAULT_MIN_WAVE_EVENTS).toBeGreaterThan(1);
    expect(DEFAULT_MIN_WAVE_INTERVAL_HOURS).toBeGreaterThan(0);
  });
});

describe("markWaveBoundaries", () => {
  it("marks the gaps that separate two waves and leaves others alone", () => {
    const events = twoWaveTimeline();
    const gaps = detectTimelineGaps(events);
    const pattern = detectActivityWaves(events, gaps)!;
    const marked = markWaveBoundaries(gaps, pattern);
    const boundaries = marked.filter((g) => g.betweenWaves);
    expect(boundaries).toHaveLength(2);
    expect(marked.every((g) => g.complete)).toBe(true);
  });

  it("is a no-op when there is no wave pattern", () => {
    const events = burst("a-", "2026-08-26T13:00:00.000Z", 10);
    const gaps = detectTimelineGaps(events);
    expect(markWaveBoundaries(gaps, null)).toEqual(gaps);
  });
});

describe("backfillActivityWaveFinding", () => {
  it("emits one finding naming the wave count and the elapsed span", () => {
    const events = twoWaveTimeline();
    const pattern = detectActivityWaves(events, detectTimelineGaps(events))!;
    const next = backfillActivityWaveFinding(emptyState("INC-TEST"), pattern, "2026-08-26T20:00:00.000Z");
    expect(next.findings).toHaveLength(1);
    const f = next.findings[0];
    expect(f.id).toBe("f-waves");
    expect(f.title).toContain("3 separate waves");
    expect(f.description).toContain("18d 23h");
    expect(f.severity).toBe("High");
  });

  it("is idempotent — re-running does not duplicate the finding", () => {
    const events = twoWaveTimeline();
    const pattern = detectActivityWaves(events, detectTimelineGaps(events))!;
    const once = backfillActivityWaveFinding(emptyState("INC-TEST"), pattern, "2026-08-26T20:00:00.000Z");
    const twice = backfillActivityWaveFinding(once, pattern, "2026-08-26T21:00:00.000Z");
    expect(twice.findings).toHaveLength(1);
  });

  it("returns the state unchanged when there is no pattern", () => {
    const state = emptyState("INC-TEST");
    expect(backfillActivityWaveFinding(state, null, "2026-08-26T20:00:00.000Z")).toBe(state);
  });

  it("back-links the finding to the first and last event of every wave", () => {
    const events = twoWaveTimeline();
    const pattern = detectActivityWaves(events, detectTimelineGaps(events))!;
    const state = { ...emptyState("INC-TEST"), forensicTimeline: events };
    const next = backfillActivityWaveFinding(state, pattern, "2026-08-26T20:00:00.000Z");
    const linked = next.forensicTimeline.filter((e) => e.relatedFindingIds.includes("f-waves"));
    expect(linked).toHaveLength(6); // first + last of each of the 3 waves
  });
});

describe("gap findings for wave boundaries", () => {
  it("reframes a between-waves silence as a dwell interval, not suspected tampering", () => {
    const events = twoWaveTimeline();
    const gaps = detectTimelineGaps(events);
    const pattern = detectActivityWaves(events, gaps)!;
    const state = backfillSilenceGapFindings(
      { ...emptyState("INC-TEST"), forensicTimeline: events },
      markWaveBoundaries(gaps, pattern),
      "2026-08-26T20:00:00.000Z",
    );
    expect(state.findings).toHaveLength(2);
    for (const f of state.findings) {
      expect(f.title).toContain("Dwell interval");
      expect(f.title).not.toContain("coverage gap");
      expect(f.severity).toBe("Medium");
      expect(f.mitreTechniques).toEqual([]); // T1070 only fits the missing-data reading
    }
  });

  it("still reports an unaccounted-for silence as a coverage gap", () => {
    // A trailing burst too thin to be a wave leaves the silence unexplained.
    const events = [
      ...burst("w1-", "2026-08-07T14:30:00.000Z", 6),
      ev("lone", "2026-08-25T17:30:00.000Z", { sources: ["velo"] }),
    ];
    const gaps = detectTimelineGaps(events);
    const pattern = detectActivityWaves(events, gaps);
    expect(pattern).toBeNull();
    const state = backfillSilenceGapFindings(
      { ...emptyState("INC-TEST"), forensicTimeline: events },
      markWaveBoundaries(gaps, pattern),
      "2026-08-26T20:00:00.000Z",
    );
    expect(state.findings[0].title).toContain("coverage gap");
    expect(state.findings[0].severity).toBe("High");
    expect(state.findings[0].mitreTechniques).toEqual(["T1070"]);
  });
});

describe("interval fidelity", () => {
  // A thin segment BETWEEN two bursts is real activity. Discarding it and then measuring the
  // interval from burst-to-burst asserts a continuous silence over a period that had an event in
  // it — and leaves only one of the two real gaps marked as a boundary.
  it("does not claim a continuous dwell interval across an intervening event", () => {
    const events = [
      ...burst("a-", "2026-08-01T00:00:00.000Z", 6),
      ev("mid", "2026-08-10T00:00:00.000Z", { sources: ["velo"] }),
      ...burst("b-", "2026-08-20T00:00:00.000Z", 6),
    ];
    const gaps = detectTimelineGaps(events);
    const pattern = detectActivityWaves(events, gaps)!;
    expect(pattern).not.toBeNull();
    // No interval may span the intervening event.
    const midMs = Date.parse("2026-08-10T00:00:00.000Z");
    for (let i = 1; i < pattern.waves.length; i++) {
      const from = Date.parse(pattern.waves[i - 1].endTimestamp);
      const to = Date.parse(pattern.waves[i].startTimestamp);
      expect(from < midMs && midMs < to).toBe(false); // strictly inside is the bug; bounding is fine
    }
    // Both real silences are marked, not just one.
    expect(markWaveBoundaries(gaps, pattern).filter((g) => g.betweenWaves)).toHaveLength(2);
  });

  it("still drops a leading stray that is not real activity", () => {
    const events = [
      ev("stray", "2026-06-01T00:00:00.000Z", { sources: ["velo"] }),
      ...burst("a-", "2026-08-01T00:00:00.000Z", 6),
      ...burst("b-", "2026-08-20T00:00:00.000Z", 6),
    ];
    const pattern = detectActivityWaves(events, detectTimelineGaps(events))!;
    expect(pattern.waves).toHaveLength(2);
    expect(pattern.waves[0].startTimestamp).toBe("2026-08-01T00:00:00.000Z");
  });

  it("requires at least two SUBSTANTIAL waves, not two blips", () => {
    const events = [
      ev("x", "2026-08-01T00:00:00.000Z", { sources: ["velo"] }),
      ev("y", "2026-08-20T00:00:00.000Z", { sources: ["velo"] }),
    ];
    expect(detectActivityWaves(events, detectTimelineGaps(events))).toBeNull();
  });

  // gapDetect opens a gap from the running MAXIMUM end time so an aggregated row ("20 logons over
  // 3h") closes the gap at its end. A wave has to end at the same instant or it reports a dwell
  // interval that never happened.
  it("ends a wave at the aggregated end time, not the last row's start", () => {
    const events = [
      ...burst("a-", "2026-08-01T00:00:00.000Z", 4),
      ev("agg", "2026-08-01T00:04:00.000Z", {
        sources: ["velo"],
        endTimestamp: "2026-08-05T00:00:00.000Z",
      }),
      ...burst("b-", "2026-08-20T00:00:00.000Z", 6),
    ];
    const pattern = detectActivityWaves(events, detectTimelineGaps(events))!;
    expect(pattern.waves[0].endTimestamp).toBe("2026-08-05T00:00:00.000Z");
    expect(pattern.waves[0].lastEventId).toBe("agg");
    expect(pattern.intervals[0].durationLabel).toBe("15d");
  });
});

describe("detectGapsWithWaves", () => {
  // Every consumer has to see the SAME classification. When only synthesis marked wave boundaries,
  // the finding said "dwell interval, Medium" while the coverage panel and the Markdown report
  // still called the identical window a High complete-silence log-tampering gap.
  it("returns gaps already marked, plus the pattern", () => {
    const events = twoWaveTimeline();
    const { gaps, pattern } = detectGapsWithWaves(events);
    expect(pattern!.waves).toHaveLength(3);
    expect(gaps.filter((g) => g.betweenWaves)).toHaveLength(2);
  });

  it("agrees exactly with running the two steps by hand", () => {
    const events = twoWaveTimeline();
    const raw = detectTimelineGaps(events);
    const byHand = markWaveBoundaries(raw, detectActivityWaves(events, raw));
    expect(detectGapsWithWaves(events).gaps).toEqual(byHand);
  });

  it("marks nothing when there is no pattern", () => {
    const events = burst("a-", "2026-08-26T13:00:00.000Z", 10);
    const { gaps, pattern } = detectGapsWithWaves(events);
    expect(pattern).toBeNull();
    expect(gaps.every((g) => !g.betweenWaves)).toBe(true);
  });

  it("honours caller-supplied gap options", () => {
    const events = twoWaveTimeline();
    // A floor above every silence in the fixture leaves no gaps to split on.
    const { gaps, pattern } = detectGapsWithWaves(events, { minGapMinutes: 60 * 24 * 365 });
    expect(gaps).toHaveLength(0);
    expect(pattern).toBeNull();
  });
});
