import { describe, it, expect } from "vitest";
import { buildAttackPhases, DEFAULT_GAP_SECONDS } from "../../src/analysis/burstDetect.js";
import type { ForensicEvent, Severity } from "../../src/analysis/stateTypes.js";

function ev(id: string, timestamp: string, extra: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp,
    description: extra.description ?? "",
    severity: extra.severity ?? "Info",
    mitreTechniques: extra.mitreTechniques ?? [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...extra,
  };
}

describe("buildAttackPhases", () => {
  it("returns no phases for an empty or fully-undated timeline", () => {
    expect(buildAttackPhases([])).toEqual([]);
    expect(buildAttackPhases([ev("e1", ""), ev("e2", "not-a-date")])).toEqual([]);
  });

  it("groups a dense burst into one phase and a later burst into another", () => {
    const events: ForensicEvent[] = [
      ev("e1", "2026-05-20T14:01:00Z"),
      ev("e2", "2026-05-20T14:02:00Z"),
      ev("e3", "2026-05-20T14:03:00Z"),
      // > 5 min gap → new phase
      ev("e4", "2026-05-20T15:10:00Z"),
      ev("e5", "2026-05-20T15:11:00Z"),
    ];
    const phases = buildAttackPhases(events);
    expect(phases).toHaveLength(2);
    expect(phases[0].id).toBe("phase-1");
    expect(phases[0].eventIds).toEqual(["e1", "e2", "e3"]);
    expect(phases[0].startTimestamp).toBe("2026-05-20T14:01:00Z");
    expect(phases[0].endTimestamp).toBe("2026-05-20T14:03:00Z");
    expect(phases[0].eventCount).toBe(3);
    expect(phases[1].id).toBe("phase-2");
    expect(phases[1].eventIds).toEqual(["e4", "e5"]);
  });

  it("sorts unordered input chronologically before clustering", () => {
    const phases = buildAttackPhases([
      ev("e3", "2026-05-20T14:03:00Z"),
      ev("e1", "2026-05-20T14:01:00Z"),
      ev("e2", "2026-05-20T14:02:00Z"),
    ]);
    expect(phases).toHaveLength(1);
    expect(phases[0].eventIds).toEqual(["e1", "e2", "e3"]);
  });

  it("labels a phase with its dominant ATT&CK tactic and unions techniques", () => {
    const phases = buildAttackPhases([
      ev("e1", "2026-05-20T14:01:00Z", { mitreTechniques: ["T1566"], description: "phishing email" }),
      ev("e2", "2026-05-20T14:02:00Z", { mitreTechniques: ["T1566.001"] }),
      ev("e3", "2026-05-20T14:02:30Z", { mitreTechniques: ["T1059"], description: "powershell" }),
    ]);
    expect(phases).toHaveLength(1);
    expect(phases[0].label).toBe("Initial Access");           // 2× Initial Access beats 1× Execution
    expect(phases[0].inferredTechniques).toEqual(["T1059", "T1566", "T1566.001"]);
  });

  it("falls back to 'Activity burst' when no tactic can be inferred", () => {
    const phases = buildAttackPhases([
      ev("e1", "2026-05-20T14:01:00Z", { description: "benign file read" }),
    ]);
    expect(phases[0].label).toBe("Activity burst");
  });

  it("records the worst severity in a burst", () => {
    const sevs: Severity[] = ["Low", "Critical", "Medium"];
    const phases = buildAttackPhases(
      sevs.map((s, i) => ev(`e${i}`, `2026-05-20T14:0${i}:00Z`, { severity: s })),
    );
    expect(phases[0].maxSeverity).toBe("Critical");
  });

  it("honors a custom gapSeconds threshold", () => {
    const events = [
      ev("e1", "2026-05-20T14:00:00Z"),
      ev("e2", "2026-05-20T14:00:30Z"),   // 30s apart
    ];
    expect(buildAttackPhases(events, { gapSeconds: 10 })).toHaveLength(2); // 30s > 10s → split
    expect(buildAttackPhases(events, { gapSeconds: 60 })).toHaveLength(1); // 30s ≤ 60s → one phase
  });

  it("sums aggregated counts and spans aggregated end times", () => {
    const phases = buildAttackPhases([
      ev("e1", "2026-05-20T14:00:00Z", { count: 20, endTimestamp: "2026-05-20T14:04:00Z" }),
      // starts 1 min after e1's END (14:04) → within the default 5-min gap, same phase
      ev("e2", "2026-05-20T14:05:00Z"),
    ]);
    expect(phases).toHaveLength(1);
    expect(phases[0].eventCount).toBe(21);                    // 20 (aggregated) + 1
    expect(phases[0].endTimestamp).toBe("2026-05-20T14:05:00Z");
  });

  it("defaults the gap threshold to 5 minutes", () => {
    expect(DEFAULT_GAP_SECONDS).toBe(300);
  });
});
