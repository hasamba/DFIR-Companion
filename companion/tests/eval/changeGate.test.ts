import { describe, expect, it } from "vitest";
import {
  assessNoRegressionGate,
  evaluationSourceHash,
  noRegressionAttestationSchema,
  visionInputsChanged,
  type NoRegressionAttestation,
} from "./changeGate.js";

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
    schemaVersion: 2,
    sourceHash,
    runs: 3,
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

describe("no-regression attestation v2 (#1579)", () => {
  const hash = "b".repeat(64);

  it("parses a schemaVersion 2 attestation with a run count", () => {
    expect(noRegressionAttestationSchema.parse(attestation(hash)).runs).toBe(3);
  });

  it("rejects a schemaVersion 1 attestation", () => {
    expect(() => noRegressionAttestationSchema.parse({ ...attestation(hash), schemaVersion: 1 })).toThrow();
  });

  it("requires runs, as a positive integer", () => {
    const withoutRuns: Partial<NoRegressionAttestation> = { ...attestation(hash) };
    delete withoutRuns.runs;
    expect(() => noRegressionAttestationSchema.parse(withoutRuns)).toThrow();
    expect(() => noRegressionAttestationSchema.parse({ ...attestation(hash), runs: 0 })).toThrow();
    expect(() => noRegressionAttestationSchema.parse({ ...attestation(hash), runs: 2.5 })).toThrow();
  });
});

describe("vision-path change detection (#1579 item 2)", () => {
  it("is true when only SYSTEM_PROMPT differs", () => {
    expect(visionInputsChanged(PIPELINE, ENV, PIPELINE.replace('"system"', '"changed"'), ENV)).toBe(true);
  });

  it("is true when only a DFIR_VISION_MODEL default line differs", () => {
    expect(visionInputsChanged(PIPELINE, ENV, PIPELINE, ENV.replace("=haiku", "=opus"))).toBe(true);
  });

  it("is true when only a DFIR_VISION_PROVIDER default line differs", () => {
    expect(
      visionInputsChanged(
        PIPELINE,
        ENV,
        PIPELINE,
        ENV.replace("VISION_PROVIDER=claude-code", "VISION_PROVIDER=openai"),
      ),
    ).toBe(true);
  });

  it("is false when only SYNTHESIS_PROMPT differs", () => {
    expect(visionInputsChanged(PIPELINE, ENV, PIPELINE.replace('"synth"', '"changed"'), ENV)).toBe(false);
  });

  it("is false when only DFIR_AI_SYNTH_MODEL differs", () => {
    expect(visionInputsChanged(PIPELINE, ENV, PIPELINE, ENV.replace("=sonnet", "=opus"))).toBe(false);
  });

  it("ignores a commented-out vision line", () => {
    const env = `${ENV}# DFIR_VISION_MODEL=example\n`;
    expect(visionInputsChanged(PIPELINE, env, PIPELINE, env.replace("=example", "=other"))).toBe(false);
  });
});
