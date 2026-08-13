import { describe, it, expect } from "vitest";
import { COLLECTION_STEPS } from "../../src/analysis/collectionPlan.js";
import {
  TACTIC_CLEARANCE_EVIDENCE,
  sourceClassesFor,
  evaluateEligibility,
} from "../../src/analysis/hostScopeEligibility.js";
import type { HostEvidence } from "../../src/analysis/hostScopeAggregate.js";

function evidence(over: Partial<HostEvidence> = {}): HostEvidence {
  return {
    collected: true,
    sources: new Set(["Microsoft Defender"]),
    firstSeen: "2026-05-01T00:00:00Z",
    lastSeen: "2026-05-11T00:00:00Z",
    eventCount: 12,
    maxSeverity: "Info",
    findingIds: new Set(),
    referencedBy: new Set(),
    ...over,
  };
}

const WINDOW = { start: "2026-05-01T00:00:00Z", end: "2026-05-11T00:00:00Z" };

describe("TACTIC_CLEARANCE_EVIDENCE vocabulary", () => {
  it("names only real collection step ids", () => {
    const ids = new Set(COLLECTION_STEPS.map((s) => s.id));
    for (const steps of Object.values(TACTIC_CLEARANCE_EVIDENCE)) {
      for (const step of steps ?? []) expect(ids).toContain(step);
    }
  });
});

describe("sourceClassesFor", () => {
  it("maps a tool name to its collection step id", () => {
    expect(sourceClassesFor(["Microsoft Defender"])).toContain("edr");
  });

  it("ignores a tool no step claims", () => {
    expect(sourceClassesFor(["Some Unknown Tool"]).size).toBe(0);
  });
});

describe("evaluateEligibility", () => {
  it("is eligible when every criterion is met", () => {
    const result = evaluateEligibility({
      evidence: evidence(),
      window: WINDOW,
      caseTactics: ["Credential Access"],
    });
    expect(result.eligible).toBe(true);
  });

  it("fails source breadth when the host has no host-level source", () => {
    const result = evaluateEligibility({
      evidence: evidence({ sources: new Set(["Suricata"]) }),
      window: WINDOW,
      caseTactics: [],
    });
    expect(result.criteria.find((c) => c.id === "source-breadth")!.met).toBe(false);
    expect(result.eligible).toBe(false);
  });

  it("fails window coverage and reports the real span", () => {
    const result = evaluateEligibility({
      evidence: evidence({ lastSeen: "2026-05-04T00:00:00Z" }),
      window: WINDOW,
      caseTactics: [],
    });
    const criterion = result.criteria.find((c) => c.id === "window-coverage")!;
    expect(criterion.met).toBe(false);
    expect(criterion.detail).toContain("2026-05-04");
  });

  it("fails technique coverage and names the missing evidence class", () => {
    const result = evaluateEligibility({
      evidence: evidence({ sources: new Set(["Microsoft Defender"]) }),
      window: WINDOW,
      caseTactics: ["Exfiltration"],
    });
    const criterion = result.criteria.find((c) => c.id === "technique-coverage")!;
    expect(criterion.met).toBe(false);
    expect(criterion.detail).toContain("Exfiltration");
  });

  it("fails on open signal when the host carries a finding", () => {
    const result = evaluateEligibility({
      evidence: evidence({ findingIds: new Set(["f1"]) }),
      window: WINDOW,
      caseTactics: [],
    });
    expect(result.criteria.find((c) => c.id === "no-open-signal")!.met).toBe(false);
  });

  it("fails on open signal when the host has a High event", () => {
    const result = evaluateEligibility({
      evidence: evidence({ maxSeverity: "High" }),
      window: WINDOW,
      caseTactics: [],
    });
    expect(result.criteria.find((c) => c.id === "no-open-signal")!.met).toBe(false);
  });
});
