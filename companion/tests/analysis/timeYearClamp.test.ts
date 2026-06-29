import { describe, it, expect } from "vitest";
import { clampOutlierYears } from "../../src/analysis/timeYearClamp.js";
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
});
