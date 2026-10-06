// #1974 — ATT&CK Reconnaissance (TA0043). A T1595.002 row (tagged by the #1964 web-scanner rules)
// used to resolve to no tactic, so it fell into "Uncategorized" and out of every kill-chain view.
import { describe, expect, it } from "vitest";
import { tacticForTechniques } from "../../src/analysis/mitreTactics.js";
import { buildSwimlaneData } from "../../src/analysis/swimlane.js";
import { buildAttackPhases } from "../../src/analysis/burstDetect.js";
import { deriveCockpitStory, STORY_STAGE_ORDER } from "../../src/analysis/cockpitStory.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

function ev(id: string, timestamp: string, extra: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp,
    description: extra.description ?? "",
    severity: extra.severity ?? "High",
    mitreTechniques: extra.mitreTechniques ?? [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...extra,
  };
}

// Every base technique ATT&CK v19 files under TA0043 (data/attack-matrix.json).
const RECON_BASES = [
  "T1589",
  "T1590",
  "T1591",
  "T1592",
  "T1593",
  "T1594",
  "T1595",
  "T1596",
  "T1597",
  "T1598",
  "T1681",
  "T1682",
];

describe("Reconnaissance tactic (#1974)", () => {
  it("maps T1595.002 and every TA0043 technique to Reconnaissance", () => {
    expect(tacticForTechniques(["T1595.002"])).toBe("Reconnaissance");
    for (const id of RECON_BASES) expect(tacticForTechniques([id]), id).toBe("Reconnaissance");
  });

  it("ranks Reconnaissance last when a row carries another tactic too (worst stage wins)", () => {
    expect(tacticForTechniques(["T1595.002", "T1190"])).toBe("Initial Access");
    expect(tacticForTechniques(["T1595.002", "T1059"])).toBe("Execution");
  });

  it("puts a Reconnaissance lane first in the swimlane tactic view", () => {
    const r = buildSwimlaneData(
      [
        ev("exploit", "2026-05-01T10:05:00Z", { mitreTechniques: ["T1190"] }),
        ev("scan", "2026-05-01T10:00:00Z", { mitreTechniques: ["T1595.002"] }),
      ],
      "tactic",
    );
    expect(r.lanes.map((l) => l.label)).toEqual(["Reconnaissance", "Initial Access"]);
  });

  it("breaks a phase tie toward Reconnaissance, the earliest kill-chain stage", () => {
    const phases = buildAttackPhases([
      ev("exploit", "2026-05-20T14:02:00Z", { mitreTechniques: ["T1190"] }),
      ev("scan", "2026-05-20T14:01:00Z", { mitreTechniques: ["T1595.002"] }),
    ]);
    expect(phases[0].label).toBe("Reconnaissance");
  });

  it("opens the story with a Reconnaissance stage but never reports it missing", () => {
    expect(STORY_STAGE_ORDER[0]).toBe("Reconnaissance");
    const withRecon = deriveCockpitStory({
      ...emptyState("case-1974"),
      forensicTimeline: [
        ev("exploit", "2026-05-01T10:05:00Z", { mitreTechniques: ["T1190"] }),
        ev("scan", "2026-05-01T10:00:00Z", { mitreTechniques: ["T1595.002"] }),
      ],
    });
    expect(withRecon.stages.map((s) => s.tactic)).toEqual(["Reconnaissance", "Initial Access"]);
    const without = deriveCockpitStory({
      ...emptyState("case-1974"),
      forensicTimeline: [ev("exploit", "2026-05-01T10:05:00Z", { mitreTechniques: ["T1190"] })],
    });
    expect(without.missingStages).not.toContain("Reconnaissance");
    expect(deriveCockpitStory(emptyState("case-1974")).missingStages).not.toContain("Reconnaissance");
  });
});
