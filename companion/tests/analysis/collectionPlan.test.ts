import { describe, it, expect } from "vitest";
import {
  COLLECTION_STEPS,
  getCollectionStep,
  buildCollectionPlan,
} from "../../src/analysis/collectionPlan.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

function ev(sources: string[]): ForensicEvent {
  return {
    id: `e${sources.join("-")}`,
    timestamp: "2026-01-01T00:00:00Z",
    description: "",
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    sources,
  };
}

describe("collection step vocabulary", () => {
  it("defines every step with a label and a satisfiedBy list", () => {
    expect(COLLECTION_STEPS.length).toBeGreaterThan(0);
    for (const s of COLLECTION_STEPS) {
      expect(s.id).toMatch(/^[a-z0-9-]+$/);
      expect(s.label.length).toBeGreaterThan(0);
      expect(Array.isArray(s.satisfiedBy)).toBe(true);
    }
    expect(new Set(COLLECTION_STEPS.map((s) => s.id)).size).toBe(COLLECTION_STEPS.length);
  });

  it("resolves a step by id", () => {
    expect(getCollectionStep("edr")?.label).toBe("EDR telemetry");
    expect(getCollectionStep("nope")).toBeUndefined();
  });

  // "CSV import" / "Log import" mean "we could not tell what this was" — they must satisfy nothing.
  it("never lets an unidentified import satisfy a step", () => {
    const all = COLLECTION_STEPS.flatMap((s) => s.satisfiedBy);
    expect(all).not.toContain("CSV import");
    expect(all).not.toContain("Log import");
  });
});

describe("buildCollectionPlan", () => {
  it("marks a step collected when the timeline holds a matching source", () => {
    const plan = buildCollectionPlan(["edr", "network"], [ev(["EDR (ECAR)"])], {});
    expect(plan.steps.find((s) => s.id === "edr")!.state).toBe("collected");
    expect(plan.steps.find((s) => s.id === "network")!.state).toBe("outstanding");
    expect(plan.collected).toBe(1);
    expect(plan.total).toBe(2);
  });

  it("ticks a step from ANY of its satisfying sources, not just the first", () => {
    for (const label of ["Chainsaw", "Hayabusa", "EVTX", "Sysmon", "Windows Event Log"]) {
      const plan = buildCollectionPlan(["windows-event-logs"], [ev([label])], {});
      expect(plan.steps[0].state, `${label} should satisfy windows-event-logs`).toBe("collected");
    }
  });

  it("preserves the declared order and names the next outstanding step", () => {
    const plan = buildCollectionPlan(["edr", "network", "siem"], [ev(["EDR (ECAR)"])], {});
    expect(plan.steps.map((s) => s.id)).toEqual(["edr", "network", "siem"]);
    expect(plan.nextStepId).toBe("network");
  });

  it("reports no next step once everything is collected", () => {
    const plan = buildCollectionPlan(["edr"], [ev(["EDR (ECAR)"])], {});
    expect(plan.nextStepId).toBe("");
  });

  // A step nothing can import is real work, but the tool must not nag about it.
  it("marks a step with no satisfying sources as external and never as next", () => {
    const plan = buildCollectionPlan(["physical-access", "network"], [], {});
    expect(plan.steps.find((s) => s.id === "physical-access")!.state).toBe("external");
    expect(plan.nextStepId).toBe("network");
  });

  it("excludes external steps from the collected/total counts", () => {
    const plan = buildCollectionPlan(["physical-access", "edr"], [ev(["EDR (ECAR)"])], {});
    expect(plan.total).toBe(1);
    expect(plan.collected).toBe(1);
  });

  it("lets an override beat the derived state in both directions", () => {
    const collected = buildCollectionPlan(["network"], [], {
      network: { state: "collected", reason: "pcap on the SAN" },
    });
    expect(collected.steps[0].state).toBe("override-collected");
    expect(collected.steps[0].reason).toBe("pcap on the SAN");
    expect(collected.collected).toBe(1);

    const na = buildCollectionPlan(["edr"], [ev(["EDR (ECAR)"])], {
      edr: { state: "na", reason: "no EDR here" },
    });
    expect(na.steps[0].state).toBe("override-na");
    expect(na.collected).toBe(0);
    expect(na.total).toBe(0); // n/a leaves the denominator, like an external step
  });

  it("never proposes an overridden step as next", () => {
    const plan = buildCollectionPlan(["network", "siem"], [], { network: { state: "na", reason: "" } });
    expect(plan.nextStepId).toBe("siem");
  });

  it("ignores an unknown step id rather than rendering a blank row", () => {
    const plan = buildCollectionPlan(["edr", "not-a-step"], [], {});
    expect(plan.steps.map((s) => s.id)).toEqual(["edr"]);
  });

  it("is pure — does not mutate its inputs", () => {
    const events = [ev(["EDR (ECAR)"])];
    const overrides = { edr: { state: "na" as const, reason: "x" } };
    const snapshot = JSON.stringify({ events, overrides });
    buildCollectionPlan(["edr"], events, overrides);
    expect(JSON.stringify({ events, overrides })).toBe(snapshot);
  });
});
