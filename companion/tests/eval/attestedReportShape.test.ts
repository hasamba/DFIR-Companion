import { describe, expect, it } from "vitest";
import { verifyAttestedReportShape, type AttestedReportShape, type AttestedRow } from "./changeGate.js";

const EXPECTED = { cases: 4, extraction: 2, screenshot: 1 };

/** Every fixture once in every run, as run.ts writes them: run 1 keeps the id, run k ≥ 2 adds #runk. */
function runRows(perRun: number, runs: number): AttestedRow[] {
  const out: AttestedRow[] = [];
  for (let run = 1; run <= runs; run++)
    for (let i = 0; i < perRun; i++) out.push({ id: run === 1 ? `f${i}` : `f${i}#run${run}`, runIndex: run });
  return out;
}

function report(overrides: Partial<AttestedReportShape> = {}): AttestedReportShape {
  return {
    real: true,
    mode: "all",
    runs: 3,
    identity: { provider: "openrouter" },
    expected: EXPECTED,
    cases: runRows(EXPECTED.cases, 3),
    extraction: runRows(EXPECTED.extraction, 3),
    screenshot: runRows(EXPECTED.screenshot, 3),
    ...overrides,
  };
}

const ATTESTATION = { runs: 3 };
const NO_VISION = { visionChanged: false };
const VISION = { visionChanged: true };

describe("attested report shape (#1579)", () => {
  it("accepts a complete 3-run real 'all' report", () => {
    expect(verifyAttestedReportShape(report(), ATTESTATION, NO_VISION)).toEqual([]);
    expect(verifyAttestedReportShape(report(), ATTESTATION, VISION)).toEqual([]);
  });

  it("accepts a report with no screenshot rows when the vision path did not change", () => {
    const noSet = report({ screenshot: [], expected: { ...EXPECTED, screenshot: 0 } });
    expect(verifyAttestedReportShape(noSet, ATTESTATION, NO_VISION)).toEqual([]);
  });

  it("rejects a partial screenshot set — every screenshot the report ran must be there for every run", () => {
    const partial = report({ screenshot: runRows(EXPECTED.screenshot, 3).slice(0, -1) });
    expect(verifyAttestedReportShape(partial, ATTESTATION, NO_VISION).join("\n")).toMatch(/screenshot rows/);
  });

  it("rejects a mock report", () => {
    expect(verifyAttestedReportShape(report({ real: false }), ATTESTATION, NO_VISION).join("\n")).toMatch(
      /real/,
    );
  });

  it("rejects a report with no real flag", () => {
    expect(verifyAttestedReportShape(report({ real: undefined }), ATTESTATION, NO_VISION)).not.toEqual([]);
  });

  it("rejects a partial-mode report", () => {
    expect(
      verifyAttestedReportShape(report({ mode: "synthesis" }), ATTESTATION, NO_VISION).join("\n"),
    ).toMatch(/mode/);
  });

  it("rejects a single-run report", () => {
    const single = report({
      runs: 1,
      cases: runRows(EXPECTED.cases, 1),
      extraction: runRows(EXPECTED.extraction, 1),
      screenshot: runRows(EXPECTED.screenshot, 1),
    });
    expect(verifyAttestedReportShape(single, { runs: 1 }, NO_VISION).join("\n")).toMatch(/at least 3 runs/);
  });

  it("rejects a report whose run count differs from its attestation", () => {
    expect(verifyAttestedReportShape(report(), { runs: 2 }, NO_VISION).join("\n")).toMatch(/attestation/);
  });

  it("rejects a report with no expected counts", () => {
    expect(
      verifyAttestedReportShape(report({ expected: undefined }), ATTESTATION, NO_VISION).join("\n"),
    ).toMatch(/expected/);
  });

  it("rejects a report missing case rows", () => {
    const short = report({ cases: runRows(EXPECTED.cases, 3).slice(0, -1) });
    expect(verifyAttestedReportShape(short, ATTESTATION, NO_VISION).join("\n")).toMatch(/case rows/);
  });

  it("rejects a report missing extraction rows", () => {
    const short = report({ extraction: runRows(EXPECTED.extraction, 2) });
    expect(verifyAttestedReportShape(short, ATTESTATION, NO_VISION).join("\n")).toMatch(/extraction rows/);
  });

  it("rejects a vision change attested without screenshot rows", () => {
    const noSet = report({ screenshot: [], expected: { ...EXPECTED, screenshot: 0 } });
    const errors = verifyAttestedReportShape(noSet, ATTESTATION, VISION);
    expect(errors.join("\n")).toMatch(/#1579 item 2/);
  });

  // #1579 review: a total row count cannot tell a complete set from an uneven one.
  it("rejects a mock report relabelled as real", () => {
    const relabelled = report({ identity: { provider: "mock" } });
    expect(verifyAttestedReportShape(relabelled, ATTESTATION, NO_VISION).join("\n")).toMatch(/mock provider/);
  });

  it("rejects uneven runs that add up to the right total (2, 1, 3)", () => {
    const [a, b] = [{ id: "f0" }, { id: "f1" }];
    const uneven = report({
      expected: { ...EXPECTED, screenshot: 2 },
      screenshot: [
        { ...a, runIndex: 1 },
        { ...b, runIndex: 1 },
        { id: "f0#run2", runIndex: 2 },
        { id: "f0#run3", runIndex: 3 },
        { id: "f1#run3", runIndex: 3 },
        { id: "f1#run3", runIndex: 3 },
      ],
    });
    const errors = verifyAttestedReportShape(uneven, ATTESTATION, NO_VISION).join("\n");
    expect(errors).toMatch(/"f1" is missing from run 2/);
    expect(errors).toMatch(/"f1" appears twice in run 3/);
  });
});
