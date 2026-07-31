import { describe, expect, it } from "vitest";
import { passesCaseQuality, scoreCaseQuality, type CaseGolden, type QualityOutput } from "./qualityScorer.js";

const GOLDEN: CaseGolden = {
  claims: [
    {
      id: "credential-access",
      requiredTerms: ["credential dump"],
      evidenceEventIds: ["e1", "e2"],
      confidence: { min: 70, max: 95 },
    },
  ],
  iocs: [{ type: "hash", value: "a".repeat(64) }],
  forbiddenConclusions: [{ id: "invented-actor", terms: ["nightfall"] }],
  uncertainties: [
    {
      id: "initial-access-gap",
      topicTerms: ["initial access"],
      allowedStatuses: ["unknown", "inferred"],
    },
  ],
  nextSteps: [{ id: "collect-auth", requiredTerms: ["security.evtx", "dc01"] }],
  expectAbstention: false,
};

const OUTPUT: QualityOutput = {
  evidenceEventIds: ["e1", "e2"],
  claims: [
    {
      id: "f1",
      title: "Credential dump",
      description: "Credential dump was observed.",
      evidenceEventIds: ["e2", "e1"],
      confidence: 85,
      confidenceReason: "Two exact events corroborate the activity.",
    },
  ],
  iocs: [{ id: "i1", type: "hash", value: "a".repeat(64) }],
  uncertainties: [
    {
      topic: "Initial access",
      status: "unknown",
      basis: "",
      gap: "The delivery artifact has not been collected.",
    },
  ],
  nextSteps: [
    {
      action: "Collect Security.evtx from DC01",
      rationale: "Confirm the source logon.",
      pointer: "DC01 Security.evtx",
    },
  ],
};

describe("scoreCaseQuality (#378 production quality gates)", () => {
  it("passes claims only when their exact evidence-id set and required terms match", () => {
    expect(passesCaseQuality(scoreCaseQuality(GOLDEN, OUTPUT))).toBe(true);

    const wrongEvidence: QualityOutput = {
      ...OUTPUT,
      claims: [{ ...OUTPUT.claims[0], evidenceEventIds: ["e1"] }],
    };
    const score = scoreCaseQuality(GOLDEN, wrongEvidence);
    expect(score.claims.missed).toEqual(["credential-access"]);
    expect(score.claims.falseConclusions).toEqual(["f1"]);
    expect(passesCaseQuality(score)).toBe(false);
  });

  it("flags dangling evidence references, forbidden conclusions, and poor calibration", () => {
    const unsafe: QualityOutput = {
      ...OUTPUT,
      claims: [
        {
          ...OUTPUT.claims[0],
          description: "NIGHTFALL performed the credential dump.",
          evidenceEventIds: ["e1", "e2", "invented-event"],
          confidence: 100,
          confidenceReason: "",
        },
      ],
    };
    const score = scoreCaseQuality(GOLDEN, unsafe);
    expect(score.danglingEvidenceRefs).toEqual([{ claimId: "f1", evidenceEventIds: ["invented-event"] }]);
    expect(score.forbiddenConclusions).toEqual(["invented-actor"]);
    expect(score.confidenceIssues).toContain("f1: confidence outside 70-95");
    expect(score.confidenceIssues).toContain("f1: confidence has no reason");
    expect(passesCaseQuality(score)).toBe(false);
  });

  it("scores IOC recall, uncertainty handling, and useful next steps", () => {
    const incomplete: QualityOutput = {
      ...OUTPUT,
      iocs: [],
      uncertainties: [],
      nextSteps: [],
    };
    const score = scoreCaseQuality(GOLDEN, incomplete);
    expect(score.iocs.recall).toBe(0);
    expect(score.uncertainties.missed).toEqual(["initial-access-gap"]);
    expect(score.nextSteps.missed).toEqual(["collect-auth"]);
    expect(passesCaseQuality(score)).toBe(false);
  });

  it("rewards abstention on a clean case and fails a manufactured finding", () => {
    const cleanGolden: CaseGolden = {
      claims: [],
      iocs: [],
      forbiddenConclusions: [],
      uncertainties: [],
      nextSteps: [],
      expectAbstention: true,
    };
    expect(passesCaseQuality(scoreCaseQuality(cleanGolden, { ...OUTPUT, claims: [], iocs: [] }))).toBe(true);
    expect(passesCaseQuality(scoreCaseQuality(cleanGolden, OUTPUT))).toBe(false);
  });
});
