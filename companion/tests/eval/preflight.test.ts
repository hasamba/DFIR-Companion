import { describe, expect, it } from "vitest";
import { MIN_ATTESTED_RUNS } from "./baseline.js";
import type { EvalCliOptions } from "./cli.js";
import { attestationPreflight } from "./preflight.js";

const ATTESTED: EvalCliOptions = {
  mode: "all",
  real: true,
  runs: MIN_ATTESTED_RUNS,
  requireProvider: true,
  requireBaseline: true,
  outputPath: "report.json",
  baselinePath: "baseline.json",
  attestationPath: "attestation.json",
};

describe("attestationPreflight (#1579)", () => {
  it("allows any run that does not ask for an attestation", () => {
    expect(
      attestationPreflight({
        mode: "all",
        real: false,
        runs: 1,
        requireProvider: false,
        requireBaseline: false,
      }),
    ).toBeUndefined();
  });

  it("allows a fully specified attested run", () => {
    expect(attestationPreflight(ATTESTED)).toBeUndefined();
    expect(attestationPreflight({ ...ATTESTED, runs: 10 })).toBeUndefined();
  });

  it.each([
    ["a mock run", { real: false }, /--real/],
    ["too few runs", { runs: MIN_ATTESTED_RUNS - 1 }, new RegExp(`--runs ${MIN_ATTESTED_RUNS}`)],
    ["one section only", { mode: "synthesis" as const }, /mode "all"/],
    ["no report output", { outputPath: undefined }, /--output/],
    ["no baseline", { baselinePath: undefined }, /--baseline/],
    ["an optional baseline", { requireBaseline: false }, /--require-baseline/],
  ])("refuses %s", (_label, change, message) => {
    const result = attestationPreflight({ ...ATTESTED, ...change });
    expect(result).toMatch(/^--attestation /);
    expect(result).toMatch(message);
  });

  it("names every missing requirement at once", () => {
    const result = attestationPreflight({
      mode: "all",
      real: true,
      runs: 1,
      requireProvider: false,
      requireBaseline: false,
      attestationPath: "x.json",
    });
    expect(result).toMatch(/--runs 3/);
    expect(result).toMatch(/--output/);
    expect(result).toMatch(/--baseline/);
    expect(result).toMatch(/--require-baseline/);
  });
});
