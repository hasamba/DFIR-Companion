import { describe, expect, it } from "vitest";
import { createHuntEventBudget } from "../../src/composition/huntEventBudget.js";
import type { ForensicEvent, Severity } from "../../src/analysis/stateTypes.js";

const ev = (severity: Severity, i = 0): ForensicEvent => ({
  id: `e${severity}${i}`,
  timestamp: "2026-01-01T00:00:00Z",
  description: "x",
  severity,
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
});
const many = (severity: Severity, n: number): ForensicEvent[] =>
  Array.from({ length: n }, (_, i) => ev(severity, i));

describe("hunt-wide event budget", () => {
  it("gives every artifact its own per-import cap and no floor while the budget lasts", () => {
    const b = createHuntEventBudget(100);
    expect(b.nextImport()).toEqual({ maxEvents: 100 });
    expect(b.exhausted).toBe(false);
  });

  it("does not charge rows the forensic gate will demote (Info under the default Low gate)", () => {
    const b = createHuntEventBudget(100);
    b.charge(many("Info", 5000), "Low");
    expect(b.exhausted).toBe(false);
    expect(b.nextImport()).toEqual({ maxEvents: 100 });
  });

  it("charges by the case's gate: Low rows do not count when the gate is Medium", () => {
    const b = createHuntEventBudget(10);
    b.charge(many("Low", 50), "Medium");
    expect(b.exhausted).toBe(false);
    b.charge(many("Medium", 10), "Medium");
    expect(b.exhausted).toBe(true);
  });

  it("once spent, still imports artifacts but only Medium and above", () => {
    const b = createHuntEventBudget(10);
    b.charge(many("Low", 10), "Low");
    expect(b.exhausted).toBe(true);
    expect(b.nextImport()).toEqual({ maxEvents: 10, minSeverity: "Medium" });
  });
});
