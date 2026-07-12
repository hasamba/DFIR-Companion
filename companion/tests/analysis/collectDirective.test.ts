import { describe, it, expect } from "vitest";
import { collectSummary, collectTargetKey, isActionableCollect } from "../../src/analysis/collectDirective.js";
import { derivePlaybookTasks } from "../../src/analysis/playbook.js";
import { emptyState } from "../../src/analysis/stateTypes.js";

describe("collectSummary", () => {
  it("renders host + logSource + artifact + expected", () => {
    expect(collectSummary({ host: "ALCLIENT07", logSource: "Security.evtx 4624", artifact: "Windows.EventLogs.Evtx", expectedOutcome: "the pivot logon" }))
      .toBe("collect Security.evtx 4624 (Windows.EventLogs.Evtx) from ALCLIENT07 — expected: the pivot logon");
  });
  it("omits the artifact suffix when it equals the logSource", () => {
    expect(collectSummary({ host: "H", logSource: "$MFT", artifact: "$MFT" })).toBe("collect $MFT from H");
  });
  it("returns '' for an empty directive", () => {
    expect(collectSummary(undefined)).toBe("");
    expect(collectSummary({})).toBe("");
  });
});

describe("collectTargetKey", () => {
  it("is host|source, case-insensitive", () => {
    expect(collectTargetKey({ host: "HOST7", logSource: "Security.evtx" })).toBe("host7|security.evtx");
    expect(collectTargetKey({ host: "host7", artifact: "Security.evtx" })).toBe("host7|security.evtx");
  });
  it("distinguishes different sources on the same host", () => {
    expect(collectTargetKey({ host: "H", logSource: "Security.evtx" }))
      .not.toBe(collectTargetKey({ host: "H", logSource: "Sysmon" }));
  });
  it("returns '' without a host (not deployable / matchable)", () => {
    expect(collectTargetKey({ logSource: "Security.evtx" })).toBe("");
  });
});

describe("isActionableCollect", () => {
  it("requires a non-empty host", () => {
    expect(isActionableCollect({ host: "H" })).toBe(true);
    expect(isActionableCollect({ logSource: "x" })).toBe(false);
    expect(isActionableCollect({ host: "  " })).toBe(false);
    expect(isActionableCollect(undefined)).toBe(false);
  });
});

describe("derivePlaybookTasks — collection directives (#8)", () => {
  it("seeds a collection task from an unknown question carrying an actionable collect target", () => {
    const s = emptyState("c1");
    s.keyQuestions = [
      { id: "q_lateral_movement", question: "Was there lateral movement?", status: "unknown", answer: "", pointer: "",
        collect: { host: "DC01", logSource: "Security.evtx 4624 type-3", expectedOutcome: "a type-3 logon" } },
      { id: "q_answered", question: "Which hosts?", status: "answered", answer: "DC01", pointer: "",
        collect: { host: "DC01", logSource: "x" } },
    ];
    const seeds = derivePlaybookTasks(s);
    const qSeed = seeds.find((t) => t.sourceKey === "question:q_lateral_movement");
    expect(qSeed).toBeDefined();
    expect(qSeed!.source).toBe("question");
    expect(qSeed!.title).toContain("Collect to answer");
    expect(qSeed!.description).toContain("DC01");
    // an ANSWERED question does not seed a collection task
    expect(seeds.find((t) => t.sourceKey === "question:q_answered")).toBeUndefined();
  });

  it("uses a next-step's structured relatedFindingIds instead of prose-scraping the pointer", () => {
    const s = emptyState("c1");
    s.findings = [{ id: "f9", severity: "Critical", title: "Malware", description: "", relatedIocs: [], sourceScreenshots: [], mitreTechniques: [], firstSeen: "", lastUpdated: "", status: "open" }];
    s.nextSteps = [
      { id: "n1", priority: "high", action: "Pull logs", rationale: "confirm", pointer: "no finding id in this prose", relatedFindingIds: ["f9"],
        collect: { host: "HOST7", logSource: "Security.evtx" } },
    ];
    const seeds = derivePlaybookTasks(s);
    // f9 is Critical → covered → the next step folds into f9's task rather than creating its own
    expect(seeds.find((t) => t.sourceKey === "next_step:n1")).toBeUndefined();
    const findingTask = seeds.find((t) => t.sourceKey === "finding:f9");
    expect(findingTask).toBeDefined();
    expect(findingTask!.description).toContain("HOST7");
  });
});
