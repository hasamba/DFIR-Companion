import { describe, it, expect } from "vitest";
import { compareAnalysisRuns } from "../../src/analysis/analysisRunCompare.js";
import type { AnalysisRunManifest } from "../../src/analysis/analysisRunTypes.js";

function run(id: string, claims: AnalysisRunManifest["output"]["claims"]): AnalysisRunManifest {
  return {
    id,
    caseId: "c1",
    schemaVersion: 1,
    sequence: id === "r1" ? 1 : 2,
    kind: "synthesis",
    status: "completed",
    parentRunId: null,
    startedAt: "2026-07-31T10:00:00.000Z",
    finishedAt: "2026-07-31T10:00:01.000Z",
    durationMs: 1000,
    versions: { application: "0.33.0" },
    input: { artifacts: [], eventIds: [], entityIds: [] },
    execution: { retries: 0, warnings: [] },
    output: { entityIds: claims.map((claim) => claim.id), hashes: [], claims },
    previousManifestHash: null,
    manifestHash: "hash",
  };
}

describe("compareAnalysisRuns", () => {
  it("shows added, removed and changed claims with evidence links", () => {
    const before = run("r1", [
      { id: "f1", hash: "old", evidenceEventIds: ["e1"] },
      { id: "f2", hash: "same", evidenceEventIds: ["e2"] },
    ]);
    const after = run("r2", [
      { id: "f1", hash: "new", evidenceEventIds: ["e1", "e3"] },
      { id: "f3", hash: "added", evidenceEventIds: ["e4"] },
    ]);

    expect(compareAnalysisRuns(before, after)).toEqual({
      fromRunId: "r1",
      toRunId: "r2",
      added: [{ id: "f3", evidenceEventIds: ["e4"] }],
      removed: [{ id: "f2", evidenceEventIds: ["e2"] }],
      changed: [
        {
          id: "f1",
          beforeEvidenceEventIds: ["e1"],
          afterEvidenceEventIds: ["e1", "e3"],
        },
      ],
    });
  });
});
