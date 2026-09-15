// #1084 (surfaced by #1077's design review): the shared `byTime` tie-break in each of
// awsComputeState.ts, azureComputeState.ts and gcpComputeState.ts compared equal-timestamp
// entries by their locator STRING, so "record:10" sorted before "record:2" (lexical '1' < '2').
// Fixed to compare the locator's own trailing integer instead.
import { describe, expect, it } from "vitest";
import { byTime as awsByTime } from "../../src/analysis/awsComputeState.js";
import { byTime as azureByTime } from "../../src/analysis/azureComputeState.js";
import { byTime as gcpByTime } from "../../src/analysis/gcpComputeState.js";

const cases: [string, (a: unknown, b: unknown) => number][] = [
  ["awsComputeState", awsByTime as (a: unknown, b: unknown) => number],
  ["azureComputeState", azureByTime as (a: unknown, b: unknown) => number],
  ["gcpComputeState", gcpByTime as (a: unknown, b: unknown) => number],
];

describe.each(cases)("%s byTime", (_name, byTime) => {
  it("orders two same-timestamp entries by scan position, never by locator-string comparison", () => {
    const earlier = { time: 1000, locator: "record:2" };
    const later = { time: 1000, locator: "record:10" };
    // record:2 occurred first in the upload; it must sort before record:10 at the same timestamp.
    expect(byTime(earlier, later)).toBeLessThan(0);
    expect(byTime(later, earlier)).toBeGreaterThan(0);
  });

  it("still orders by time first when timestamps differ", () => {
    const first = { time: 1000, locator: "record:99" };
    const second = { time: 2000, locator: "record:1" };
    expect(byTime(first, second)).toBeLessThan(0);
    expect(byTime(second, first)).toBeGreaterThan(0);
  });

  it("falls back to the locator string when it does not end in a digit run", () => {
    const a = { time: 1000, locator: "alpha" };
    const b = { time: 1000, locator: "beta" };
    expect(byTime(a, b)).toBeLessThan(0);
  });

  it("is a stable zero for two identical entries", () => {
    const a = { time: 1000, locator: "record:5" };
    const b = { time: 1000, locator: "record:5" };
    expect(byTime(a, b)).toBe(0);
  });
});
