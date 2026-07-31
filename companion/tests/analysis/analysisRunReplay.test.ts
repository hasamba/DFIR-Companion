import { describe, it, expect } from "vitest";
import { checkReplayAvailability } from "../../src/analysis/analysisRunReplay.js";
import type { AnalysisRunManifest } from "../../src/analysis/analysisRunTypes.js";

const RUN: AnalysisRunManifest = {
  id: "r1",
  caseId: "c1",
  schemaVersion: 1,
  sequence: 1,
  kind: "synthesis",
  status: "completed",
  parentRunId: null,
  startedAt: "2026-07-31T10:00:00.000Z",
  finishedAt: "2026-07-31T10:00:01.000Z",
  durationMs: 1000,
  versions: {
    application: "0.33.0",
    importer: "thor/v1",
    rules: "rules-a",
  },
  input: {
    artifacts: [{ path: "imports/0001_thor.json", sha256: "a".repeat(64) }],
    eventIds: ["e1"],
    entityIds: [],
  },
  configuration: {
    provider: "openai",
    model: "gpt-test",
    promptHash: "prompt-a",
    templateHash: "template-a",
  },
  execution: { retries: 0, warnings: [] },
  output: { entityIds: ["f1"], hashes: [], claims: [] },
  previousManifestHash: null,
  manifestHash: "hash",
};

describe("checkReplayAvailability", () => {
  it("allows a replay only when every pinned dependency is available", () => {
    expect(
      checkReplayAvailability(RUN, {
        artifacts: { "imports/0001_thor.json": "a".repeat(64) },
        providerModels: [{ provider: "openai", model: "gpt-test" }],
        promptHashes: ["prompt-a"],
        templateHashes: ["template-a"],
        ruleHashes: ["rules-a"],
        importerVersions: ["thor/v1"],
        eventIds: ["e1"],
      }),
    ).toEqual({ ready: true, blockers: [] });
  });

  it("names unavailable or changed models, prompts, rules and source evidence before starting", () => {
    const result = checkReplayAvailability(RUN, {
      artifacts: { "imports/0001_thor.json": "b".repeat(64) },
      providerModels: [],
      promptHashes: [],
      templateHashes: [],
      ruleHashes: [],
      importerVersions: [],
      eventIds: [],
    });

    expect(result.ready).toBe(false);
    expect(result.blockers).toEqual([
      "source artifact changed: imports/0001_thor.json",
      "source event unavailable: e1",
      "provider/model unavailable: openai/gpt-test",
      "prompt version unavailable: prompt-a",
      "template version unavailable: template-a",
      "rules version unavailable: rules-a",
      "importer version unavailable: thor/v1",
    ]);
  });
});
