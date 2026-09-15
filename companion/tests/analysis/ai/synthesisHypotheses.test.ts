import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../../src/storage/caseStore.js";
import { HypothesisStore } from "../../../src/analysis/hypothesisStore.js";
import { EvidenceAttestationStore } from "../../../src/analysis/evidenceAttestationStore.js";
import { autoGenerateHypotheses } from "../../../src/analysis/ai/synthesisHypotheses.js";
import type { SynthesisContext } from "../../../src/analysis/ai/synthesis.js";
import type { InvestigationState } from "../../../src/analysis/stateTypes.js";

// Thin-wiring test for #1111: autoGenerateHypotheses must load the case's own ACTIVE attestations
// and pass them into gateRefutedSeeds. The gate's own coverage/disclosure logic is exhaustively
// covered in refutationGate.test.ts — this only pins that the plumbing between the two is correct.

let cases: CaseStore;

function ctxWith(evidenceAttestationStore?: EvidenceAttestationStore): SynthesisContext {
  return {
    opts: {
      hypothesisStore: new HypothesisStore(cases),
      ...(evidenceAttestationStore ? { evidenceAttestationStore } : {}),
    },
  } as unknown as SynthesisContext;
}

const STATE: InvestigationState = {
  forensicTimeline: [],
  iocs: [],
} as unknown as InvestigationState;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-synth-hyp-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
});

function rawHypothesis(title: string) {
  return {
    title,
    description: "",
    expectedOutcome: "",
    status: "refuted" as const,
    relatedTechniques: [],
    relatedEventIds: [],
    relatedIocIds: [],
    contradictingEventIds: [],
    discriminator: "",
  };
}

describe("autoGenerateHypotheses — evidence attestation wiring (#1111)", () => {
  it("an active attestation lets a refutation the collection alone cannot support still stand", async () => {
    const attestationStore = new EvidenceAttestationStore(cases);
    await attestationStore.attest("c1", {
      evidenceClass: "execution",
      confirmedBy: "a.analyst@example.invalid",
      confirmedAt: "2026-08-13T09:41:00Z",
      reason: "Reviewed the full Prefetch and Sysmon export against the incident window",
    });
    const ctx = ctxWith(attestationStore);
    await autoGenerateHypotheses(ctx, "c1", [rawHypothesis("The payload never ran on the host")], STATE, []);
    const stored = await new HypothesisStore(cases).load("c1");
    expect(stored[0].status).toBe("refuted");
    expect(stored[0].description).toContain("analyst-attested coverage");
  });

  it("without an evidenceAttestationStore wired, behaves exactly as before (backward compatible)", async () => {
    const ctx = ctxWith(undefined);
    await autoGenerateHypotheses(ctx, "c1", [rawHypothesis("The payload never ran on the host")], STATE, []);
    const stored = await new HypothesisStore(cases).load("c1");
    expect(stored[0].status).toBe("unknown");
  });
});
