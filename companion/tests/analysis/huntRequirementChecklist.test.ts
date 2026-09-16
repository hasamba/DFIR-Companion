import { describe, it, expect } from "vitest";
import { buildHuntChecklist } from "../../src/analysis/huntRequirementChecklist.js";
import type { HuntRequirement } from "../../src/analysis/huntRequirementStore.js";
import type { Hypothesis } from "../../src/analysis/hypothesis.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { AttestedEvidenceClass, EvidenceClass } from "../../src/analysis/refutationGate.js";
import { buildHostAliasIndex } from "../../src/analysis/hostAlias.js";

function ev(id: string, sources: string[], artifactName?: string, asset?: string): ForensicEvent {
  return {
    id,
    timestamp: "2026-08-26T13:00:00.000Z",
    description: "",
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    sources,
    ...(artifactName ? { artifactName } : {}),
    ...(asset ? { asset } : {}),
  };
}

function req(over: Partial<HuntRequirement> = {}): HuntRequirement {
  return {
    id: "req-1",
    decision: "recommend containment vs. monitor",
    audience: "IR lead",
    deadline: "2026-09-20T00:00:00Z",
    subjectScope: { kind: "hosts", hosts: ["ws-01"] },
    expectedObservableEvidence: "the binary executed and wrote files to disk",
    createdBy: "a.analyst@example.invalid",
    createdAt: "2026-09-16T00:00:00Z",
    ...over,
  };
}

function h(partial: Partial<Hypothesis> & { id: string; title: string }): Hypothesis {
  return {
    description: "",
    expectedOutcome: "",
    status: "open",
    relatedTechniques: [],
    relatedEventIds: [],
    relatedIocIds: [],
    contradictingEventIds: [],
    discriminator: "",
    exhausted: false,
    exhaustedReason: "",
    assignee: "",
    notes: "",
    source: "synthesis",
    analystTouched: false,
    needsReview: false,
    reviewReason: "",
    alternativeIds: [],
    excludedEvidence: [],
    createdAt: "2026-01-01T00:00:00Z",
    updatedAt: "2026-01-01T00:00:00Z",
    statusHistory: [],
    ...partial,
  };
}

const EMPTY_ALIAS = buildHostAliasIndex([], {});
const NOW = "2026-09-16T12:00:00Z";

describe("buildHuntChecklist", () => {
  it("reports required evidence classes from the requirement's own expected evidence text", () => {
    const out = buildHuntChecklist({
      requirement: req({ expectedObservableEvidence: "the binary executed and connected outbound" }),
      events: [],
      hypotheses: [],
      attested: new Map(),
      aliasIndex: EMPTY_ALIAS,
      now: NOW,
    });
    expect(out.requiredClasses.sort()).toEqual(["execution", "network"]);
  });

  it("reports an unsupported-evidence-source case when no known class matches", () => {
    const out = buildHuntChecklist({
      requirement: req({ expectedObservableEvidence: "the operator was authorized to do this" }),
      events: [],
      hypotheses: [],
      attested: new Map(),
      aliasIndex: EMPTY_ALIAS,
      now: NOW,
    });
    expect(out.requiredClasses).toEqual([]);
    expect(out.unsupportedEvidenceSource).toBe(true);
  });

  it("marks a class collected on the requirement's own scoped host as available, not a gap", () => {
    const out = buildHuntChecklist({
      requirement: req({ subjectScope: { kind: "hosts", hosts: ["ws-01"] } }),
      events: [ev("e1", ["sysmon"], undefined, "ws-01")],
      hypotheses: [],
      attested: new Map(),
      aliasIndex: EMPTY_ALIAS,
      now: NOW,
    });
    expect(out.gaps.map((g) => g.evidenceClass)).not.toContain("execution");
  });

  it("gaps a class collected only on a DIFFERENT host than the requirement's own scope", () => {
    const out = buildHuntChecklist({
      requirement: req({ subjectScope: { kind: "hosts", hosts: ["ws-02"] } }),
      events: [ev("e1", ["sysmon"], undefined, "ws-01")],
      hypotheses: [],
      attested: new Map(),
      aliasIndex: EMPTY_ALIAS,
      now: NOW,
    });
    expect(out.gaps.map((g) => g.evidenceClass)).toContain("execution");
  });

  it("folds in an existing attestation as available coverage, disclosed distinctly", () => {
    const attested = new Map<EvidenceClass, AttestedEvidenceClass>([
      [
        "execution",
        { confirmedBy: "a.analyst@example.invalid", confirmedAt: "2026-09-01T00:00:00Z", reason: "reviewed" },
      ],
    ]);
    const out = buildHuntChecklist({
      requirement: req({ subjectScope: { kind: "hosts", hosts: ["ws-01"] } }),
      events: [],
      hypotheses: [],
      attested,
      aliasIndex: EMPTY_ALIAS,
      now: NOW,
    });
    expect(out.gaps.map((g) => g.evidenceClass)).not.toContain("execution");
    expect(out.attestedOnly).toContain("execution");
  });

  it("costs a gapped class 'low' when a source for it exists elsewhere in the case, 'high' when it doesn't", () => {
    const out = buildHuntChecklist({
      requirement: req({
        subjectScope: { kind: "hosts", hosts: ["ws-02"] },
        expectedObservableEvidence: "the binary executed and connected outbound",
      }),
      events: [ev("e1", ["sysmon"], undefined, "ws-01")], // execution exists case-wide, just not on ws-02
      hypotheses: [],
      attested: new Map(),
      aliasIndex: EMPTY_ALIAS,
      now: NOW,
    });
    const execGap = out.gaps.find((g) => g.evidenceClass === "execution")!;
    const netGap = out.gaps.find((g) => g.evidenceClass === "network")!;
    expect(execGap.cost).toBe("low");
    expect(netGap.cost).toBe("high");
  });

  it("emits no cost label at all when the requirement's own scope is unknown", () => {
    const out = buildHuntChecklist({
      requirement: req({ subjectScope: { kind: "unknown" } }),
      events: [],
      hypotheses: [],
      attested: new Map(),
      aliasIndex: EMPTY_ALIAS,
      now: NOW,
    });
    for (const gap of out.gaps) expect(gap.cost).toBeUndefined();
    expect(out.scopeUnresolved).toBe(true);
  });

  it("suggests a matching open hypothesis's own discriminator, verbatim", () => {
    const out = buildHuntChecklist({
      requirement: req({ subjectScope: { kind: "hosts", hosts: ["ws-01"] } }),
      events: [],
      hypotheses: [
        h({
          id: "hyp-1",
          title: "malware executed on ws-01",
          expectedOutcome: "the binary executed and wrote files to disk",
          status: "open",
          subjectScope: { kind: "hosts", hosts: ["ws-01"] },
          discriminator: "Prefetch entry for the dropped binary on ws-01",
        }),
      ],
      attested: new Map(),
      aliasIndex: EMPTY_ALIAS,
      now: NOW,
    });
    expect(out.discriminator).toBe("Prefetch entry for the dropped binary on ws-01");
  });

  it("never matches via relatedTechniques (ATT&CK ids can't match evidence-class keywords)", () => {
    const out = buildHuntChecklist({
      requirement: req({ subjectScope: { kind: "hosts", hosts: ["ws-01"] } }),
      events: [],
      hypotheses: [
        h({
          id: "hyp-1",
          title: "no textual overlap here",
          expectedOutcome: "nothing evidence-related in this text either",
          relatedTechniques: ["T1055"],
          status: "open",
          subjectScope: { kind: "hosts", hosts: ["ws-01"] },
          discriminator: "should never surface — no real text match",
        }),
      ],
      attested: new Map(),
      aliasIndex: EMPTY_ALIAS,
      now: NOW,
    });
    expect(out.discriminator).toBeNull();
    expect(out.discriminatorAvailable).toBe(false);
  });

  it("treats an empty discriminator string as 'no discriminator available', never surfaces blank", () => {
    const out = buildHuntChecklist({
      requirement: req({ subjectScope: { kind: "hosts", hosts: ["ws-01"] } }),
      events: [],
      hypotheses: [
        h({
          id: "hyp-1",
          title: "malware executed on ws-01",
          expectedOutcome: "the binary executed and wrote files to disk",
          status: "open",
          subjectScope: { kind: "hosts", hosts: ["ws-01"] },
          discriminator: "",
        }),
      ],
      attested: new Map(),
      aliasIndex: EMPTY_ALIAS,
      now: NOW,
    });
    expect(out.discriminator).toBeNull();
    expect(out.discriminatorAvailable).toBe(false);
  });

  it("ignores a refuted hypothesis and an exhausted one when suggesting a discriminator", () => {
    const out = buildHuntChecklist({
      requirement: req({ subjectScope: { kind: "hosts", hosts: ["ws-01"] } }),
      events: [],
      hypotheses: [
        h({
          id: "hyp-1",
          title: "malware executed on ws-01",
          expectedOutcome: "the binary executed and wrote files to disk",
          status: "refuted",
          subjectScope: { kind: "hosts", hosts: ["ws-01"] },
          discriminator: "should never surface — refuted",
        }),
        h({
          id: "hyp-2",
          title: "malware executed on ws-01, alt theory",
          expectedOutcome: "the binary executed and wrote files to disk",
          status: "open",
          exhausted: true,
          subjectScope: { kind: "hosts", hosts: ["ws-01"] },
          discriminator: "should never surface — exhausted",
        }),
      ],
      attested: new Map(),
      aliasIndex: EMPTY_ALIAS,
      now: NOW,
    });
    expect(out.discriminator).toBeNull();
  });

  it("does not match a hypothesis whose scope does not overlap the requirement's own scope", () => {
    const out = buildHuntChecklist({
      requirement: req({ subjectScope: { kind: "hosts", hosts: ["ws-01"] } }),
      events: [],
      hypotheses: [
        h({
          id: "hyp-1",
          title: "malware executed on ws-99",
          expectedOutcome: "the binary executed and wrote files to disk",
          status: "open",
          subjectScope: { kind: "hosts", hosts: ["ws-99"] },
          discriminator: "should never surface — different host",
        }),
      ],
      attested: new Map(),
      aliasIndex: EMPTY_ALIAS,
      now: NOW,
    });
    expect(out.discriminator).toBeNull();
  });

  it("treats caseWide as overlapping any host scope", () => {
    const out = buildHuntChecklist({
      requirement: req({ subjectScope: { kind: "hosts", hosts: ["ws-01"] } }),
      events: [],
      hypotheses: [
        h({
          id: "hyp-1",
          title: "case-wide malware theory",
          expectedOutcome: "the binary executed and wrote files to disk",
          status: "open",
          subjectScope: { kind: "caseWide" },
          discriminator: "case-wide Prefetch sweep",
        }),
      ],
      attested: new Map(),
      aliasIndex: EMPTY_ALIAS,
      now: NOW,
    });
    expect(out.discriminator).toBe("case-wide Prefetch sweep");
  });

  it("marks a requirement expired when its deadline is in the past, using a hardcoded now", () => {
    const out = buildHuntChecklist({
      requirement: req({ deadline: "2026-01-01T00:00:00Z" }),
      events: [],
      hypotheses: [],
      attested: new Map(),
      aliasIndex: EMPTY_ALIAS,
      now: NOW,
    });
    expect(out.expired).toBe(true);
  });

  it("does not mark a requirement expired when its deadline is in the future", () => {
    const out = buildHuntChecklist({
      requirement: req({ deadline: "2027-01-01T00:00:00Z" }),
      events: [],
      hypotheses: [],
      attested: new Map(),
      aliasIndex: EMPTY_ALIAS,
      now: NOW,
    });
    expect(out.expired).toBe(false);
  });
});
