import { describe, it, expect } from "vitest";
import { aggregateEvents } from "../../src/analysis/eventAggregate.js";
import type { MappedEvent } from "../../src/analysis/siemImport.js";

// #2502 — a group's first and last time must not depend on the order its rows arrive in. Entra and
// most cloud exports are newest-first: a group created from its NEWEST row lost that row's time as
// the end of the span when an older row joined (the end was seeded from the lowered start).

const at = (timestamp: string): MappedEvent => ({
  timestamp,
  description: "Entra sign-in: user@example.com from 192.0.2.10",
  severity: "Medium",
  mitre: [],
  aggKey: "entra-signin|user@example.com|192.0.2.10",
});

function span(times: string[]) {
  const { events } = aggregateEvents(times.map(at));
  expect(events).toHaveLength(1);
  return { start: events[0].timestamp, end: events[0].endTimestamp, count: events[0].count };
}

describe("aggregate time span is order-independent (#2502)", () => {
  const expected = { start: "2026-11-07T09:00:00Z", end: "2026-11-07T12:00:00Z", count: 3 };

  it("oldest-first", () => {
    expect(span(["2026-11-07T09:00:00Z", "2026-11-07T10:30:00Z", "2026-11-07T12:00:00Z"])).toEqual(expected);
  });

  it("newest-first", () => {
    expect(span(["2026-11-07T12:00:00Z", "2026-11-07T10:30:00Z", "2026-11-07T09:00:00Z"])).toEqual(expected);
  });

  it("shuffled", () => {
    expect(span(["2026-11-07T10:30:00Z", "2026-11-07T12:00:00Z", "2026-11-07T09:00:00Z"])).toEqual(expected);
    expect(span(["2026-11-07T12:00:00Z", "2026-11-07T09:00:00Z", "2026-11-07T10:30:00Z"])).toEqual(expected);
  });

  it("a newest-first pair keeps the newer time as the end", () => {
    expect(span(["2026-11-07T10:00:00Z", "2026-11-07T09:00:00Z"]).end).toBe("2026-11-07T10:00:00Z");
  });
});
