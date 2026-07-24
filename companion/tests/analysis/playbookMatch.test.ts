import { describe, it, expect } from "vitest";
import {
  observedTechniqueSequence,
  matchPlaybook,
  rankPlaybooks,
  buildPlaybookMatchResult,
  BASE_MATCH_WEIGHT,
  type Playbook,
  type KnownPlaybooksDataset,
} from "../../src/analysis/playbookMatch.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

const ev = (id: string, timestamp: string, techniques: string[]): ForensicEvent => ({
  id,
  timestamp,
  description: id,
  severity: "High",
  mitreTechniques: techniques,
  relatedFindingIds: [],
  sourceScreenshots: [],
});

const conti: Playbook = {
  name: "Conti",
  description: "",
  steps: [
    { technique: "T1566.001", name: "Spearphish" },
    { technique: "T1059.001", name: "PowerShell" },
    { technique: "T1003.001", name: "LSASS dump" },
    { technique: "T1021.002", name: "Lateral SMB" },
    { technique: "T1486", name: "Encryption" },
  ],
};

const dataset = (playbooks: Playbook[]): KnownPlaybooksDataset => ({
  source: "test",
  generated: "2026-07-24",
  playbooks,
});

describe("observedTechniqueSequence", () => {
  it("orders techniques chronologically by event timestamp", () => {
    const seq = observedTechniqueSequence([
      ev("e2", "2026-01-02T00:00:00Z", ["T1003.001"]),
      ev("e1", "2026-01-01T00:00:00Z", ["T1566.001", "T1059.001"]),
    ]);
    expect(seq).toEqual(["T1566.001", "T1059.001", "T1003.001"]);
  });

  it("drops non-technique ids and collapses adjacent duplicates", () => {
    const seq = observedTechniqueSequence([
      ev("e1", "2026-01-01T00:00:00Z", ["nonsense", "T1059.001"]),
      ev("e2", "2026-01-01T00:00:01Z", ["T1059.001", "T1486"]),
    ]);
    expect(seq).toEqual(["T1059.001", "T1486"]);
  });

  it("returns an empty sequence when no events carry techniques", () => {
    expect(observedTechniqueSequence([ev("e1", "2026-01-01", [])])).toEqual([]);
  });
});

describe("matchPlaybook", () => {
  it("scores a full in-order chain at 100 and marks all steps matched/exact", () => {
    const observed = ["T1566.001", "T1059.001", "T1003.001", "T1021.002", "T1486"];
    const m = matchPlaybook(conti, observed);
    expect(m.score).toBe(100);
    expect(m.matchedCount).toBe(5);
    expect(m.exactCount).toBe(5);
    expect(m.missingCount).toBe(0);
    expect(m.steps.every((s) => s.status === "matched" && s.matchKind === "exact")).toBe(true);
  });

  it("allows unrelated techniques between playbook steps (subsequence match)", () => {
    const observed = ["T1566.001", "T1190", "T1059.001", "T1105", "T1003.001", "T1078", "T1021.002", "T1486"];
    const m = matchPlaybook(conti, observed);
    expect(m.matchedCount).toBe(5);
    expect(m.missingCount).toBe(0);
    expect(m.score).toBe(100);
  });

  it("marks unseen steps missing and computes a partial score", () => {
    const observed = ["T1566.001", "T1059.001"];
    const m = matchPlaybook(conti, observed);
    expect(m.matchedCount).toBe(2);
    expect(m.missingCount).toBe(3);
    expect(m.score).toBe(40);
    const statuses = m.steps.map((s) => s.status);
    expect(statuses).toEqual(["matched", "matched", "missing", "missing", "missing"]);
  });

  it("marks a step out-of-order when its technique appears only before the cursor", () => {
    const observed = ["T1003.001", "T1566.001", "T1059.001"]; // LSASS dump before the chain reaches it
    const m = matchPlaybook(conti, observed);
    const lsass = m.steps.find((s) => s.step.technique === "T1003.001");
    expect(lsass?.status).toBe("out-of-order");
    expect(m.matchedCount).toBe(2);
    expect(m.missingCount).toBe(3);
  });

  it("awards partial credit for a base-technique match and ranks it below an exact one", () => {
    // Playbook wants T1059.001 (PowerShell); case observed T1059.003 (cmd) — same base.
    const observed = ["T1566.001", "T1059.003", "T1003.001", "T1021.002", "T1486"];
    const m = matchPlaybook(conti, observed);
    expect(m.matchedCount).toBe(5);
    expect(m.exactCount).toBe(4);
    const ps = m.steps.find((s) => s.step.technique === "T1059.001");
    expect(ps?.status).toBe("matched");
    expect(ps?.matchKind).toBe("base");
    expect(m.score).toBe(Math.round(((4 + BASE_MATCH_WEIGHT) / 5) * 100));
  });
});

describe("rankPlaybooks", () => {
  const lockbit: Playbook = {
    name: "LockBit",
    description: "",
    steps: [
      { technique: "T1190", name: "Exploit App" },
      { technique: "T1105", name: "Tool Transfer" },
      { technique: "T1071.001", name: "C2" },
      { technique: "T1486", name: "Encryption" },
    ],
  };

  it("returns top-N playbooks ranked by score, dropping zero-overlap ones", () => {
    const observed = ["T1566.001", "T1059.001", "T1003.001", "T1021.002", "T1486"];
    const ranked = rankPlaybooks([conti, lockbit], observed, { topN: 3 });
    expect(ranked[0].name).toBe("Conti");
    expect(ranked.length).toBe(2);
    expect(ranked[1].score).toBeLessThan(ranked[0].score);
  });

  it("caps results at topN", () => {
    const observed = ["T1486"];
    const many = Array.from({ length: 5 }, (_, i) => ({
      name: `P${i}`,
      description: "",
      steps: [{ technique: "T1486", name: "Encryption" }],
    }));
    expect(rankPlaybooks(many, observed, { topN: 2 })).toHaveLength(2);
  });

  it("returns nothing for an empty observed sequence", () => {
    expect(rankPlaybooks([conti, lockbit], [])).toEqual([]);
  });

  it("ranks an exact-heavy playbook above a base-heavy one at equal matched counts", () => {
    const exactPlaybook: Playbook = {
      name: "Exact",
      description: "",
      steps: [
        { technique: "T1059.001", name: "PowerShell" },
        { technique: "T1486", name: "Encryption" },
      ],
    };
    const basePlaybook: Playbook = {
      name: "Base",
      description: "",
      steps: [
        { technique: "T1059.003", name: "Cmd" },
        { technique: "T1486", name: "Encryption" },
      ],
    };
    const observed = ["T1059.001", "T1486"];
    const ranked = rankPlaybooks([basePlaybook, exactPlaybook], observed);
    expect(ranked[0].name).toBe("Exact");
    expect(ranked[0].exactCount).toBe(2);
    expect(ranked[1].exactCount).toBe(1);
  });
});

describe("buildPlaybookMatchResult", () => {
  it("derives the observed sequence from forensic events and returns matches + provenance", () => {
    const events = [
      ev("e1", "2026-01-01T00:00:00Z", ["T1566.001"]),
      ev("e2", "2026-01-01T00:01:00Z", ["T1059.001"]),
      ev("e3", "2026-01-01T00:02:00Z", ["T1003.001"]),
      ev("e4", "2026-01-01T00:03:00Z", ["T1021.002"]),
      ev("e5", "2026-01-01T00:04:00Z", ["T1486"]),
    ];
    const result = buildPlaybookMatchResult(events, dataset([conti]), { topN: 3 });
    expect(result.observed).toEqual(["T1566.001", "T1059.001", "T1003.001", "T1021.002", "T1486"]);
    expect(result.matches).toHaveLength(1);
    expect(result.matches[0].name).toBe("Conti");
    expect(result.matches[0].score).toBe(100);
    expect(result.source).toBe("test");
    expect(result.generated).toBe("2026-07-24");
  });

  it("respects topN", () => {
    const events = [ev("e1", "2026-01-01T00:00:00Z", ["T1486"])];
    const playbooks = Array.from({ length: 5 }, (_, i) => ({
      name: `P${i}`,
      description: "",
      steps: [{ technique: "T1486", name: "Encryption" }],
    }));
    const result = buildPlaybookMatchResult(events, dataset(playbooks), { topN: 2 });
    expect(result.matches).toHaveLength(2);
  });
});
