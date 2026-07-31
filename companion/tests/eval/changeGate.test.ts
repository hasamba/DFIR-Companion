import { describe, expect, it } from "vitest";
import { assessNoRegressionGate, evaluationSourceHash, type NoRegressionAttestation } from "./changeGate.js";

const PIPELINE = `
export const SYSTEM_PROMPT = ["system"].join("\\n");
export const CSV_SYSTEM_PROMPT = ["csv"].join("\\n");
export const LOG_SYSTEM_PROMPT = ["log"].join("\\n");
export const SYNTHESIS_PROMPT = ["synth"].join("\\n");
export const unrelated = "ignored";
`;
const ENV = `
DFIR_VISION_PROVIDER=claude-code
DFIR_VISION_MODEL=haiku
DFIR_AI_SYNTH_PROVIDER=claude-code
DFIR_AI_SYNTH_MODEL=sonnet
# DFIR_AI_SYNTH_MODEL=commented-example
`;

function attestation(sourceHash: string): NoRegressionAttestation {
  return {
    schemaVersion: 1,
    sourceHash,
    status: "passed",
    reportPath: "eval-report.json",
    reportSha256: "a".repeat(64),
    baselineKey: "provider/model/prompt",
    evaluatedAt: "2026-07-31T00:00:00.000Z",
  };
}

describe("default prompt/model no-regression gate (#378)", () => {
  it("ignores unrelated source edits but detects prompt and active-model changes", () => {
    const base = evaluationSourceHash(PIPELINE, ENV);
    expect(evaluationSourceHash(PIPELINE.replace("ignored", "still-ignored"), ENV)).toBe(base);
    expect(evaluationSourceHash(PIPELINE.replace('"synth"', '"changed"'), ENV)).not.toBe(base);
    expect(evaluationSourceHash(PIPELINE, ENV.replace("sonnet", "new-model"))).not.toBe(base);
    expect(evaluationSourceHash(PIPELINE, ENV.replace("commented-example", "other-comment"))).toBe(base);
  });

  it("requires a passing attestation tied to the current source hash when defaults change", () => {
    const base = evaluationSourceHash(PIPELINE, ENV);
    const current = evaluationSourceHash(PIPELINE.replace('"synth"', '"changed"'), ENV);
    expect(assessNoRegressionGate(base, current, undefined).status).toBe("missing");
    expect(assessNoRegressionGate(base, current, attestation(base)).status).toBe("stale");
    expect(assessNoRegressionGate(base, current, attestation(current)).status).toBe("passed");
  });

  it("passes without an attestation when the evaluated defaults did not change", () => {
    const hash = evaluationSourceHash(PIPELINE, ENV);
    expect(assessNoRegressionGate(hash, hash, undefined).status).toBe("not-required");
  });
});
