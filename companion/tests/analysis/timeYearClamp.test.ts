import { describe, it, expect } from "vitest";
import { clampOutlierYears, pickImportYear } from "../../src/analysis/timeYearClamp.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

function ev(id: string, timestamp: string, extra: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id, timestamp,
    description: extra.description ?? "",
    severity: extra.severity ?? "Info",
    mitreTechniques: extra.mitreTechniques ?? [],
    relatedFindingIds: extra.relatedFindingIds ?? [],
    sourceScreenshots: [],
    ...extra,
  };
}

// N events on the same day, one minute apart, all in `year`.
function body(year: number, count: number): ForensicEvent[] {
  const out: ForensicEvent[] = [];
  for (let i = 0; i < count; i++) {
    const mm = String(i % 60).padStart(2, "0");
    out.push(ev(`b${year}_${i}`, `${year}-05-14T12:${mm}:00Z`));
  }
  return out;
}

describe("clampOutlierYears", () => {
  it("re-anchors wrong-year strays onto the dominant year, preserving month/day/time", () => {
    const events = [
      ev("old", "2023-05-14T12:01:13Z"),
      ...body(2024, 30),
      ev("future", "2026-05-14T00:00:00Z"),
    ];
    const out = clampOutlierYears(events);
    expect(out.find((e) => e.id === "old")!.timestamp).toBe("2024-05-14T12:01:13.000Z");
    expect(out.find((e) => e.id === "future")!.timestamp).toBe("2024-05-14T00:00:00.000Z");
    // The body is untouched.
    expect(out.find((e) => e.id === "b2024_0")!.timestamp).toBe("2024-05-14T12:00:00Z");
  });

  it("is idempotent — a second pass changes nothing", () => {
    const events = [ev("old", "2023-05-14T12:01:13Z"), ...body(2024, 30)];
    const once = clampOutlierYears(events);
    const twice = clampOutlierYears(once);
    expect(twice.map((e) => e.timestamp)).toEqual(once.map((e) => e.timestamp));
  });

  it("also re-anchors an aggregated row's endTimestamp", () => {
    const events = [
      ev("agg", "2023-05-14T12:00:00Z", { endTimestamp: "2023-05-14T12:30:00Z", count: 5 }),
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
    const events = [ev("a", "2023-05-14T12:00:00Z"), ...body(2024, 5)];
    const out = clampOutlierYears(events);
    expect(out.find((e) => e.id === "a")!.timestamp).toBe("2023-05-14T12:00:00Z");
  });

  it("ignores undated events", () => {
    const events = [ev("u", ""), ev("bad", "not-a-date"), ...body(2024, 12), ev("old", "2023-05-14T12:00:00Z")];
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
