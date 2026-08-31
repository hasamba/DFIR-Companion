import { describe, it, expect } from "vitest";
import { clampOutlierYears, pickImportYear, yearClampAdjustments } from "../../src/analysis/timeYearClamp.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

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

// A year-less source's event: the importer guessed the year, so the clamp may re-anchor it. Every
// fixture below that expects a rewrite must use this — a recorded year is never touched (#739).
function guessed(id: string, timestamp: string, extra: Partial<ForensicEvent> = {}): ForensicEvent {
  return ev(id, timestamp, { ...extra, yearInferred: true });
}

// N events on the same day, one minute apart, all in `year`.
function body(year: number, count: number): ForensicEvent[] {
  const out: ForensicEvent[] = [];
  for (let i = 0; i < count; i++) {
    const mm = String(i % 60).padStart(2, "0");
    out.push(guessed(`b${year}_${i}`, `${year}-05-14T12:${mm}:00Z`));
  }
  return out;
}

describe("clampOutlierYears", () => {
  it("re-anchors wrong-year strays onto the dominant year, preserving month/day/time", () => {
    const events = [
      guessed("old", "2023-05-14T12:01:13Z"),
      ...body(2024, 30),
      guessed("future", "2026-05-14T00:00:00Z"),
    ];
    const out = clampOutlierYears(events);
    expect(out.find((e) => e.id === "old")!.timestamp).toBe("2024-05-14T12:01:13.000Z");
    expect(out.find((e) => e.id === "future")!.timestamp).toBe("2024-05-14T00:00:00.000Z");
    // The body is untouched.
    expect(out.find((e) => e.id === "b2024_0")!.timestamp).toBe("2024-05-14T12:00:00Z");
  });

  it("is idempotent — a second pass changes nothing", () => {
    const events = [guessed("old", "2023-05-14T12:01:13Z"), ...body(2024, 30)];
    const once = clampOutlierYears(events);
    const twice = clampOutlierYears(once);
    expect(twice.map((e) => e.timestamp)).toEqual(once.map((e) => e.timestamp));
  });

  it("also re-anchors an aggregated row's endTimestamp", () => {
    const events = [
      guessed("agg", "2023-05-14T12:00:00Z", { endTimestamp: "2023-05-14T12:30:00Z", count: 5 }),
      ...body(2024, 30),
    ];
    const out = clampOutlierYears(events).find((e) => e.id === "agg")!;
    expect(out.timestamp).toBe("2024-05-14T12:00:00.000Z");
    expect(out.endTimestamp).toBe("2024-05-14T12:30:00.000Z");
  });

  it("leaves a genuine multi-year timeline untouched (no clear dominant year)", () => {
    const events = [...body(2023, 20), ...body(2024, 20)]; // 50/50 split
    const out = clampOutlierYears(events);
    expect(out.map((e) => e.timestamp)).toEqual(events.map((e) => e.timestamp));
  });

  it("does not clamp a tiny timeline (below the min-events guard)", () => {
    const events = [guessed("a", "2023-05-14T12:00:00Z"), ...body(2024, 5)];
    const out = clampOutlierYears(events);
    expect(out.find((e) => e.id === "a")!.timestamp).toBe("2023-05-14T12:00:00Z");
  });

  it("ignores undated events", () => {
    const events = [
      guessed("u", ""),
      guessed("bad", "not-a-date"),
      ...body(2024, 12),
      guessed("old", "2023-05-14T12:00:00Z"),
    ];
    const out = clampOutlierYears(events);
    expect(out.find((e) => e.id === "u")!.timestamp).toBe("");
    expect(out.find((e) => e.id === "bad")!.timestamp).toBe("not-a-date");
    expect(out.find((e) => e.id === "old")!.timestamp).toBe("2024-05-14T12:00:00.000Z");
  });

  // Regression for the "meridian espionage" ground-truth benchmark: a Cisco ASA / Snort log with
  // year-less BSD timestamps, imported while the machine's calendar year was 2026, defaulted its whole
  // batch to 2026. When that batch is itself a large enough share of the merged timeline, the wrong
  // year is no longer a small minority — so the ≥90% dominant-year guard never fires and the strays
  // survive uncorrected. This is NOT a bug in clampOutlierYears' math; it's the reason a post-hoc
  // minority-outlier correction can't be the only defense — see pickImportYear below.
  it("does NOT correct a large year-less-defaulted batch that is not a small minority", () => {
    const events = [...body(2024, 30), ...body(2026, 12)]; // 2026 is 29% of the dated timeline
    const out = clampOutlierYears(events);
    expect(out.map((e) => e.timestamp)).toEqual(events.map((e) => e.timestamp)); // untouched
  });

  // #739, case INC-2026-020. A Velociraptor hunt carried 197 events dated 2026 and 17 dated 2025 by
  // a lab VM whose clock was ~9 months out. The 17 were fully-qualified RFC 3339 stamps read out of
  // the artifact — real evidence — and the clamp rewrote every one of them to 2026, which then became
  // the case's "latest event" and pushed the actual attack out of the dashboard's scope window.
  it("never rewrites a RECORDED year, however small a minority it is", () => {
    const events = [
      ...body(2026, 197).map((e) => ({ ...e, yearInferred: undefined })), // structured importer
      ev("skewed", "2025-12-05T03:27:07.801Z", { asset: "WIN-UK1GV882OK6" }),
    ];
    const out = clampOutlierYears(events);
    expect(out.find((e) => e.id === "skewed")!.timestamp).toBe("2025-12-05T03:27:07.801Z");
    expect(out.find((e) => e.id === "skewed")!.yearClampedFrom).toBeUndefined();
  });

  it("still moves a guessed year that sits alongside recorded-year evidence", () => {
    // The vote is over the WHOLE dated timeline, so recorded events anchor the guessers even though
    // they can never be moved themselves.
    const events = [
      ...body(2024, 30).map((e) => ({ ...e, yearInferred: undefined })),
      guessed("syslogStray", "2026-05-14T09:00:00Z"),
    ];
    const out = clampOutlierYears(events);
    expect(out.find((e) => e.id === "syslogStray")!.timestamp).toBe("2024-05-14T09:00:00.000Z");
  });

  it("keeps the pre-clamp value, and a re-clamp never overwrites the first one", () => {
    const once = clampOutlierYears([guessed("old", "2023-05-14T12:01:13Z"), ...body(2024, 30)]);
    const clamped = once.find((e) => e.id === "old")!;
    expect(clamped.yearClampedFrom).toBe("2023-05-14T12:01:13Z");
    // A later merge whose timeline is dominated by a DIFFERENT year re-anchors again — the audit
    // trail must still point at what the source said, not at the previous adjustment.
    const again = clampOutlierYears([...once.filter((e) => e.id === "old"), ...body(2025, 30)]);
    expect(again.find((e) => e.id === "old")!.timestamp).toBe("2025-05-14T12:01:13.000Z");
    expect(again.find((e) => e.id === "old")!.yearClampedFrom).toBe("2023-05-14T12:01:13Z");
  });
});

describe("yearClampAdjustments", () => {
  it("aggregates the rewrites by year pair, most frequent first", () => {
    const out = clampOutlierYears([
      guessed("a", "2023-05-14T12:00:00Z"),
      guessed("b", "2023-05-14T13:00:00Z"),
      guessed("c", "2022-05-14T13:00:00Z"),
      ...body(2024, 30),
    ]);
    expect(yearClampAdjustments(out)).toEqual([
      { from: 2023, to: 2024, count: 2 },
      { from: 2022, to: 2024, count: 1 },
    ]);
  });

  it("reports nothing for a timeline the clamp never touched", () => {
    expect(yearClampAdjustments(body(2024, 30))).toEqual([]);
  });
});

describe("pickImportYear", () => {
  it("picks the case's already-established dominant year", () => {
    const existing = body(2024, 30);
    expect(pickImportYear(existing)).toBe(2024);
  });

  it("returns undefined when there isn't enough dated history to trust", () => {
    expect(pickImportYear([])).toBeUndefined();
    expect(pickImportYear(body(2024, 2))).toBeUndefined(); // below the default minEvents (3)
  });

  it("prevents the large-batch regression: pre-stamping the import lands it on the right year", () => {
    // Same shape as the clampOutlierYears regression above, but using pickImportYear the way
    // pipeline.ts's importCiscoAsa/importSnort/importSyslog now do: consult the CASE's existing dated
    // events BEFORE parsing the year-less batch, instead of defaulting to the current calendar year.
    const existing = body(2024, 30);
    const assumedYear = pickImportYear(existing) ?? new Date().getUTCFullYear();
    expect(assumedYear).toBe(2024);
    // The year-less batch, stamped with `assumedYear` at parse time (simulating snortImport.ts /
    // ciscoAsaImport.ts / syslogImport.ts), never lands as a 2026 outlier in the first place.
    const freshlyStamped = body(assumedYear, 12);
    const merged = [...existing, ...freshlyStamped];
    expect(merged.every((e) => new Date(e.timestamp).getUTCFullYear() === 2024)).toBe(true);
  });
});
