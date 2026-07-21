import { describe, it, expect } from "vitest";
import { previewFloors, planBatches, DEFAULT_MAX_BATCHES } from "../../src/analysis/deepPass.js";
import type { ForensicEvent, Severity } from "../../src/analysis/stateTypes.js";

function ev(id: string, t: string, sev: Severity, desc = id, asset?: string): ForensicEvent {
  return {
    id, timestamp: t, description: desc, severity: sev,
    mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [],
    ...(asset ? { asset } : {}),
  };
}

// 40 Critical, 60 High, 100 Medium, 200 Low, 50 Info — all distinct descriptions so nothing groups.
function mixedCase(): ForensicEvent[] {
  const out: ForensicEvent[] = [];
  const add = (n: number, sev: Severity, prefix: string) => {
    for (let i = 0; i < n; i++) {
      out.push(ev(
        `${prefix}${i}`,
        `2026-05-20T${String(i % 24).padStart(2, "0")}:${String(i % 60).padStart(2, "0")}:00Z`,
        sev,
        `${prefix} distinct ${prefix}${i}`,
      ));
    }
  };
  add(40, "Critical", "crit"); add(60, "High", "high"); add(100, "Medium", "med");
  add(200, "Low", "low"); add(50, "Info", "info");
  return out;
}

describe("previewFloors", () => {
  it("reports cumulative volume per floor, never counting Info", () => {
    const rows = previewFloors(mixedCase(), { cap: 100 });
    const byFloor = Object.fromEntries(rows.map((r) => [r.floor, r]));

    expect(byFloor.Critical.events).toBe(40);
    expect(byFloor.High.events).toBe(100);      // Critical + High
    expect(byFloor.Medium.events).toBe(200);
    expect(byFloor.Low.events).toBe(400);       // everything except the 50 Info
    expect(rows.every((r) => r.events <= 400)).toBe(true);
  });

  it("computes batch counts from the rows that survive grouping", () => {
    const rows = previewFloors(mixedCase(), { cap: 100 });
    const low = rows.find((r) => r.floor === "Low")!;
    expect(low.rows).toBe(400);                 // nothing groups: all descriptions distinct
    expect(low.batches).toBe(4);                // ceil(400 / 100)
    const crit = rows.find((r) => r.floor === "Critical")!;
    expect(crit.batches).toBe(1);
  });

  it("estimates tokens from the rendered rows, not from a fixed guess", () => {
    // Select the High floor explicitly — index 0 is Critical, which holds none of these events.
    const at = (rows: ReturnType<typeof previewFloors>) => rows.find((r) => r.floor === "High")!;
    const short = at(previewFloors([ev("a", "2026-05-20T09:00:00Z", "High", "x")], { cap: 100 }));
    const long = at(previewFloors([ev("a", "2026-05-20T09:00:00Z", "High", "x".repeat(400))], { cap: 100 }));
    expect(short.estimatedInputTokens).toBeGreaterThan(0);
    expect(long.estimatedInputTokens).toBeGreaterThan(short.estimatedInputTokens);
  });

  it("returns a zero row for a floor with no events rather than omitting it", () => {
    const rows = previewFloors([ev("m", "2026-05-20T09:00:00Z", "Medium")], { cap: 100 });
    const crit = rows.find((r) => r.floor === "Critical")!;
    expect(crit.events).toBe(0);
    expect(crit.batches).toBe(0);
  });

  it("orders floors most-severe first", () => {
    expect(previewFloors(mixedCase(), { cap: 100 }).map((r) => r.floor))
      .toEqual(["Critical", "High", "Medium", "Low"]);
  });
});

describe("planBatches", () => {
  const rows = Array.from({ length: 250 }, (_, i) =>
    ev(`e${i}`, `2026-05-20T${String(i % 24).padStart(2, "0")}:00:00Z`, "High"));

  it("splits into chronological chunks of at most the cap", () => {
    const batches = planBatches(rows, 100);
    expect(batches).toHaveLength(3);
    expect(batches[0]).toHaveLength(100);
    expect(batches[2]).toHaveLength(50);
    // chronological across the whole plan
    const flat = batches.flat().map((e) => e.timestamp);
    expect(flat).toEqual([...flat].sort());
  });

  it("returns one batch when everything fits", () => {
    expect(planBatches(rows, 1000)).toHaveLength(1);
  });

  it("returns nothing for an empty input", () => {
    expect(planBatches([], 100)).toEqual([]);
  });

  it("never returns a zero-size batch even for a nonsense cap", () => {
    expect(planBatches(rows, 0).every((b) => b.length > 0)).toBe(true);
  });

  it("exposes a batch ceiling default", () => {
    expect(DEFAULT_MAX_BATCHES).toBeGreaterThan(0);
  });
});
