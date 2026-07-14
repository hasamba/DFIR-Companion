import { describe, it, expect } from "vitest";
import { compileRuleset } from "../../src/analysis/taggerRules.js";
import { runTagger, raiseSeverity, applyToForensicEvent } from "../../src/analysis/tagger.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

function ev(p: Partial<ForensicEvent> & { id: string }): ForensicEvent {
  return {
    timestamp: "2026-06-01T00:00:00Z",
    description: "d",
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...p,
  };
}

const RULESET = compileRuleset({
  svc: {
    any: [{ field: "message", contains: "7045" }],
    tags: ["win-service", "persistence"],
    mitre: ["T1543"],
    severity: "Medium",
    view: "Service Installs",
  },
  cred: {
    any: [{ field: "message", contains: "lsass" }],
    tags: ["cred-access"],
    mitre: ["T1003"],
    severity: "High",
  },
});

describe("runTagger", () => {
  it("counts matches per rule and lists matched event ids", () => {
    const r = runTagger(
      [
        ev({ id: "e1", message: "service 7045" }),
        ev({ id: "e2", message: "dump lsass" }),
        ev({ id: "e3", message: "nothing here" }),
      ],
      RULESET,
    );
    const svc = r.perRule.find((x) => x.id === "svc")!;
    expect(svc.matched).toBe(1);
    expect(svc.eventIds).toEqual(["e1"]);
    expect(svc.view).toBe("Service Installs");
    expect(r.totalMatched).toBe(2);
  });

  it("aggregates tags/mitre and takes the HIGHEST severity when an event matches several rules", () => {
    const r = runTagger([ev({ id: "e1", message: "7045 and lsass together" })], RULESET);
    const pe = r.perEvent.find((x) => x.eventId === "e1")!;
    expect(pe.tags.sort()).toEqual(["cred-access", "persistence", "win-service"]);
    expect(pe.mitre.sort()).toEqual(["T1003", "T1543"]);
    expect(pe.severity).toBe("High"); // High beats Medium
    expect(pe.ruleIds.sort()).toEqual(["cred", "svc"]);
  });

  it("emits perEvent only for events with at least one match", () => {
    const r = runTagger([ev({ id: "e3", message: "benign" })], RULESET);
    expect(r.perEvent).toHaveLength(0);
    expect(r.perRule.every((x) => x.matched === 0)).toBe(true);
  });
});

describe("raiseSeverity — raise only", () => {
  it("raises to the more severe of the two, never lowers", () => {
    expect(raiseSeverity("Low", "High")).toBe("High");
    expect(raiseSeverity("Critical", "Low")).toBe("Critical");
    expect(raiseSeverity("Info", undefined)).toBe("Info");
    expect(raiseSeverity("Medium", "Medium")).toBe("Medium");
  });
});

describe("applyToForensicEvent", () => {
  it("raises severity and unions MITRE without mutating the input", () => {
    const original = ev({ id: "e1", severity: "Low", mitreTechniques: ["T1059"] });
    const result = { eventId: "e1", tags: ["t"], mitre: ["T1543", "T1059"], severity: "High" as const, ruleIds: ["svc"] };
    const next = applyToForensicEvent(original, result);
    expect(next).not.toBe(original);
    expect(original.severity).toBe("Low"); // input untouched
    expect(next.severity).toBe("High");
    expect(next.mitreTechniques.sort()).toEqual(["T1059", "T1543"]);
  });

  it("is idempotent — applying the same result twice changes nothing further", () => {
    const original = ev({ id: "e1", severity: "Low", mitreTechniques: [] });
    const result = { eventId: "e1", tags: ["t"], mitre: ["T1543"], severity: "High" as const, ruleIds: ["svc"] };
    const once = applyToForensicEvent(original, result);
    const twice = applyToForensicEvent(once, result);
    expect(twice).toEqual(once);
  });

  it("never lowers an already-higher severity", () => {
    const original = ev({ id: "e1", severity: "Critical" });
    const result = { eventId: "e1", tags: [], mitre: [], severity: "Low" as const, ruleIds: ["x"] };
    expect(applyToForensicEvent(original, result).severity).toBe("Critical");
  });
});
