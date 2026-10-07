import { describe, it, expect } from "vitest";
import { aggregateEvents } from "../../src/analysis/eventAggregate.js";
import type { MappedEvent } from "../../src/analysis/siemImport.js";
import type { Severity } from "../../src/analysis/stateTypes.js";

function row(i: number, severity: Severity, timestamp: string): MappedEvent {
  return { timestamp, description: `row ${i}`, severity, mitre: [], aggKey: `k${i}` };
}

describe("aggregate cap tie-break (#1995)", () => {
  it("keeps the newest Info rows and puts undated rows last", () => {
    const rows = [
      row(1, "Info", "2026-01-01T00:00:00Z"),
      row(2, "Info", "2026-01-03T00:00:00Z"),
      row(3, "Info", ""),
      row(4, "Info", "2026-01-02T00:00:00Z"),
    ];
    const out = aggregateEvents(rows, { maxEvents: 2 });
    expect(out.groups).toBe(4);
    // The two newest survive, listed in the usual earliest-first order.
    expect(out.events.map((e) => e.description)).toEqual(["row 4", "row 2"]);
    // Under the cap nothing is cut, and the order is the usual one.
    const all = aggregateEvents(rows, { maxEvents: 10 });
    expect(all.events.map((e) => e.description)).toEqual(["row 3", "row 1", "row 4", "row 2"]);
  });

  it("keeps earliest-first for graded rows", () => {
    const rows = [
      row(1, "High", "2026-01-03T00:00:00Z"),
      row(2, "High", "2026-01-01T00:00:00Z"),
      row(3, "High", "2026-01-02T00:00:00Z"),
    ];
    const out = aggregateEvents(rows, { maxEvents: 2 });
    expect(out.events.map((e) => e.description)).toEqual(["row 2", "row 3"]);
  });
});
