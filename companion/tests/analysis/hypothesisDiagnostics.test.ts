import { describe, it, expect } from "vitest";
import type { Hypothesis } from "../../src/analysis/hypothesis.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import {
  assessHypothesisEvidence,
  describeHypothesisEvidence,
  eventUncertainty,
  rankHypothesesAch,
  hypothesisQualifier,
} from "../../src/analysis/hypothesisDiagnostics.js";

// #933 item 22 — an observation says whether it DISTINGUISHES the explanations. Every reading here
// is computed from the per-hypothesis support/contradiction lists alone: no wording, no severity,
// no model number, and never a probability.

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

function ev(id: string, extra: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp: "2026-01-02T03:04:05Z",
    description: `event ${id}`,
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    sources: ["Velociraptor"],
    ...extra,
  };
}

const ids = (n: number, prefix = "e") => Array.from({ length: n }, (_, i) => `${prefix}${i + 1}`);

describe("assessHypothesisEvidence — bearing of one observation across the set", () => {
  it("names a support that also contradicts an alternative as distinguishing, and says which alternative", () => {
    const hyps = [
      h({ id: "phish", title: "Initial access was phishing", relatedEventIds: ["e1", "e2"] }),
      h({
        id: "vpn",
        title: "Initial access was VPN",
        relatedEventIds: ["e2"],
        contradictingEventIds: ["e1"],
      }),
    ];
    const a = assessHypothesisEvidence(hyps).get("phish")!;
    expect(a.support.distinguishing).toEqual([
      { eventId: "e1", separatesFrom: [{ id: "vpn", title: "Initial access was VPN", status: "open" }] },
    ]);
    // e2 supports both — it fits both explanations and chooses neither.
    expect(a.support.consistentWithAlternatives).toEqual([
      { eventId: "e2", assessedBy: 2, notAssessedBy: 0 },
    ]);
    expect(a.support.notAssessedElsewhere).toEqual([]);
    expect(a.reading).toContain("1 separates this from an alternative");
    expect(a.reading).toContain("'Initial access was VPN'");
  });

  it("guardrail: ten observations consistent with the alternative versus one distinguishing contradiction", () => {
    const ten = ids(10);
    const hyps = [
      h({ id: "A", title: "A", relatedEventIds: ten, contradictingEventIds: ["e11"] }),
      h({ id: "B", title: "B", relatedEventIds: [...ten, "e11"] }),
    ];
    const all = assessHypothesisEvidence(hyps);
    const a = all.get("A")!;
    expect(a.support.distinguishing).toHaveLength(0);
    expect(a.support.consistentWithAlternatives).toHaveLength(10);
    expect(a.contradiction.distinguishing).toEqual([
      { eventId: "e11", supports: [{ id: "B", title: "B", status: "open" }] },
    ]);
    expect(a.activeContradictions).toBe(1);
    const b = all.get("B")!;
    expect(b.support.distinguishing.map((d) => d.eventId)).toEqual(["e11"]);
    expect(rankHypothesesAch(hyps).map((x) => x.id)).toEqual(["B", "A"]);
    // Even with A's contradiction gone, ten shared observations do not outrank one that separates.
    const noContra = [h({ ...hyps[0], contradictingEventIds: [] }), hyps[1]];
    expect(rankHypothesesAch(noContra).map((x) => x.id)).toEqual(["B", "A"]);
  });

  it("keeps the fewest-contradictions invariant: a contradiction shared with an alternative still counts against each", () => {
    // H1 and H2 both contradict e1; H3 never assessed it. e1 is "against every explanation that
    // assessed it" (2 of 3) — and it is still one active contradiction on H1 and on H2.
    const hyps = [
      h({ id: "H1", title: "H1", contradictingEventIds: ["e1"] }),
      h({ id: "H2", title: "H2", contradictingEventIds: ["e1"] }),
      h({ id: "H3", title: "H3", relatedEventIds: ["e9"], contradictingEventIds: ["e2"] }),
    ];
    const all = assessHypothesisEvidence(hyps);
    const h1 = all.get("H1")!;
    expect(h1.contradiction.againstEveryAssessed).toEqual([
      { eventId: "e1", assessedBy: 2, notAssessedBy: 1 },
    ]);
    expect(h1.activeContradictions).toBe(1);
    expect(h1.reading).toContain(
      "contradicts every one of the 2 explanations that assessed it; 1 did not assess it",
    );
    // H3's e2 was assessed by nobody else: not "against every explanation" and still counted.
    expect(all.get("H3")!.contradiction.notAssessedElsewhere).toEqual(["e2"]);
    expect(all.get("H3")!.activeContradictions).toBe(1);
  });

  it("never promotes 'not assessed against the alternatives' to distinguishing", () => {
    const hyps = [
      h({ id: "H1", title: "H1", relatedEventIds: ["e1"] }),
      h({ id: "H2", title: "H2", relatedEventIds: ["e2"] }),
    ];
    const a = assessHypothesisEvidence(hyps).get("H1")!;
    expect(a.support.distinguishing).toEqual([]);
    expect(a.support.notAssessedElsewhere).toEqual(["e1"]);
    expect(a.reading).toContain("1 not assessed against the alternatives");
  });

  it("alone in the set: nothing can distinguish, and the reading says why", () => {
    const a = assessHypothesisEvidence([
      h({ id: "H1", title: "H1", relatedEventIds: ["e1"], status: "supported" }),
    ]).get("H1")!;
    expect(a.alternatives).toEqual([]);
    expect(a.support.distinguishing).toEqual([]);
    expect(a.reading).toContain("No alternative was offered, so no observation can separate this from one.");
    expect(hypothesisQualifier(h({ id: "H1", title: "H1", status: "supported" }), a)).toBe(
      "no alternative offered",
    );
  });

  it("a dead hypothesis is not an alternative unless the analyst names it", () => {
    const hyps = [
      h({ id: "live", title: "live", relatedEventIds: ["e1"] }),
      h({ id: "dead", title: "dead", status: "refuted", contradictingEventIds: ["e1"] }),
      h({ id: "gone", title: "gone", exhausted: true, contradictingEventIds: ["e1"] }),
    ];
    const byDefault = assessHypothesisEvidence(hyps).get("live")!;
    expect(byDefault.alternatives).toEqual([]);
    expect(byDefault.alternativesSource).toBe("live");
    expect(byDefault.support.notAssessedElsewhere).toEqual(["e1"]);
    const named = assessHypothesisEvidence([
      h({ ...hyps[0], alternativeIds: ["dead"] }),
      hyps[1],
      hyps[2],
    ]).get("live")!;
    expect(named.alternativesSource).toBe("analyst");
    expect(named.alternatives.map((a) => a.id)).toEqual(["dead"]);
    expect(named.support.distinguishing.map((d) => d.eventId)).toEqual(["e1"]);
  });

  it("an observation assessed both ways on one hypothesis counts for nothing there and is named", () => {
    const hyps = [
      h({ id: "H1", title: "H1", relatedEventIds: ["e1"], contradictingEventIds: ["e1"] }),
      h({ id: "H2", title: "H2", contradictingEventIds: ["e1"] }),
    ];
    const a = assessHypothesisEvidence(hyps).get("H1")!;
    expect(a.assessedBothWays).toEqual(["e1"]);
    expect(a.activeContradictions).toBe(0);
    expect(a.support.distinguishing).toEqual([]);
    // H2's reading: H1 did not assess e1 (its both-ways link is void) → not assessed elsewhere.
    expect(assessHypothesisEvidence(hyps).get("H2")!.contradiction.notAssessedElsewhere).toEqual(["e1"]);
  });

  it("an actively excluded observation is read as not assessed on that hypothesis only", () => {
    const hyps = [
      h({
        id: "H1",
        title: "H1",
        relatedEventIds: ["e1", "e2"],
        excludedEvidence: [
          { eventId: "e1", reason: "same source as e2", by: "analyst", excludedAt: "2026-01-03T00:00:00Z" },
        ],
      }),
      h({ id: "H2", title: "H2", relatedEventIds: ["e1"], contradictingEventIds: ["e2"] }),
    ];
    const all = assessHypothesisEvidence(hyps);
    const a = all.get("H1")!;
    expect(a.excluded).toEqual([
      { eventId: "e1", reason: "same source as e2", by: "analyst", excludedAt: "2026-01-03T00:00:00Z" },
    ]);
    expect(a.support.distinguishing.map((d) => d.eventId)).toEqual(["e2"]);
    expect(a.support.consistentWithAlternatives).toEqual([]);
    // Nothing was deleted: H1 still links e1, and H2's reading sees e1 as not assessed by H1.
    expect(hyps[0].relatedEventIds).toEqual(["e1", "e2"]);
    expect(all.get("H2")!.support.notAssessedElsewhere).toEqual(["e1"]);
    // A restored exclusion is history only.
    const restored = h({
      ...hyps[0],
      excludedEvidence: [{ ...hyps[0].excludedEvidence[0], restoredAt: "2026-01-04T00:00:00Z" }],
    });
    expect(
      assessHypothesisEvidence([restored, hyps[1]]).get("H1")!.support.consistentWithAlternatives,
    ).toEqual([{ eventId: "e1", assessedBy: 2, notAssessedBy: 0 }]);
  });

  it("eligibility first: a false-positive or missing observation is not counted, with its reason", () => {
    const hyps = [
      h({ id: "H1", title: "H1", relatedEventIds: ["e1", "ghost"], contradictingEventIds: ["fp1"] }),
      h({ id: "H2", title: "H2", contradictingEventIds: ["e1"], relatedEventIds: ["fp1"] }),
    ];
    const a = assessHypothesisEvidence(hyps, {
      eligibleEventIds: new Set(["e1", "fp1"]),
      falsePositiveEventIds: new Set(["fp1"]),
    }).get("H1")!;
    expect(a.notCounted).toEqual([
      { eventId: "ghost", reason: "not in the timeline" },
      { eventId: "fp1", reason: "marked false positive" },
    ]);
    expect(a.activeContradictions).toBe(0);
    expect(a.contradiction.distinguishing).toEqual([]);
    expect(a.support.distinguishing.map((d) => d.eventId)).toEqual(["e1"]);
  });

  it("rests on a single observation only for a supported hypothesis with exactly one distinguishing support", () => {
    const hyps = [
      h({ id: "H1", title: "H1", status: "supported", relatedEventIds: ["e1", "e2"] }),
      h({ id: "H2", title: "H2", contradictingEventIds: ["e1"], relatedEventIds: ["e2"] }),
    ];
    expect(assessHypothesisEvidence(hyps).get("H1")!.restsOnSingleObservation).toBe(true);
    const two = [
      h({ ...hyps[0], relatedEventIds: ["e1", "e2", "e3"] }),
      h({ ...hyps[1], contradictingEventIds: ["e1", "e3"] }),
    ];
    expect(assessHypothesisEvidence(two).get("H1")!.restsOnSingleObservation).toBe(false);
    const open = [h({ ...hyps[0], status: "open" }), hyps[1]];
    expect(assessHypothesisEvidence(open).get("H1")!.restsOnSingleObservation).toBe(false);
  });

  it("never turns counts into a probability: the reading carries no percentage, likelihood, confidence or score", () => {
    const forty = ids(40);
    const hyps = [
      h({
        id: "H1",
        title: "H1",
        status: "supported",
        relatedEventIds: forty,
        contradictingEventIds: ["c1"],
      }),
      h({
        id: "H2",
        title: "H2",
        relatedEventIds: ["c1", ...forty.slice(0, 20)],
        contradictingEventIds: forty.slice(20, 25),
      }),
    ];
    for (const a of assessHypothesisEvidence(hyps).values()) {
      expect(a.reading).not.toMatch(/%|probab|likel|confiden|score/i);
    }
  });
});

describe("hypothesisQualifier — the words on the status line", () => {
  it("qualifies a supported hypothesis with no distinguishing support, and a flagged one with its reason", () => {
    const hyps = [
      h({ id: "H1", title: "H1", status: "supported", relatedEventIds: ["e1"] }),
      h({ id: "H2", title: "H2", relatedEventIds: ["e1"] }),
    ];
    const a = assessHypothesisEvidence(hyps).get("H1")!;
    expect(hypothesisQualifier(hyps[0], a)).toBe("no observation separates it from an alternative");
    const flagged = h({
      ...hyps[0],
      needsReview: true,
      reviewReason: "the latest synthesis cites e7 against this",
    });
    expect(hypothesisQualifier(flagged, a)).toBe(
      "no observation separates it from an alternative — review required: the latest synthesis cites e7 against this",
    );
    // An open hypothesis with no distinguishing support carries no "supported" qualifier.
    expect(hypothesisQualifier(h({ ...hyps[0], status: "open" }), a)).toBe("");
  });
});

describe("rankHypothesesAch — ordinal keys only", () => {
  it("orders by fewest active contradictions, then distinguishing support, then unassessed support; dead last", () => {
    const ranked = rankHypothesesAch([
      h({ id: "shared", title: "A", relatedEventIds: ["s1", "s2", "s3"] }),
      h({ id: "distinct", title: "B", relatedEventIds: ["s1", "s2", "s3", "d1"] }),
      h({ id: "lone", title: "C", relatedEventIds: ["l1", "l2"], contradictingEventIds: ["d1"] }),
      h({ id: "refuted", title: "D", status: "refuted", relatedEventIds: ["s1"] }),
      h({ id: "contradicted", title: "E", relatedEventIds: ["s1"], contradictingEventIds: ["x1", "x2"] }),
    ]);
    // "lone" has one contradiction (and it is distinguishing for B), so B and A come first; between
    // them B has one distinguishing support and A has none. Then lone (1), contradicted (2), refuted.
    expect(ranked.map((x) => x.id)).toEqual(["distinct", "shared", "lone", "contradicted", "refuted"]);
  });
});

describe("describeHypothesisEvidence / eventUncertainty — the record's own uncertainty, never invented", () => {
  it("names each uncertainty the record carries and reports a missing observation", () => {
    const events = [
      ev("e1", { yearInferred: true, sources: [], artifactName: undefined }),
      ev("e2", { yearClampedFrom: "1970-01-02T03:04:05Z", skewOffsetMs: 1200 }),
      ev("e3"),
    ];
    expect(eventUncertainty(events[0])).toEqual([
      "year inferred, not read from the record",
      "no named source artifact",
    ]);
    expect(eventUncertainty(events[1])).toEqual([
      "year re-anchored from 1970-01-02T03:04:05Z",
      "time adjusted for clock skew",
    ]);
    expect(eventUncertainty(events[2])).toEqual([]);
    const hyps = [
      h({ id: "H1", title: "H1", status: "supported", relatedEventIds: ["e1", "e9"] }),
      h({ id: "H2", title: "H2", contradictingEventIds: ["e1"] }),
    ];
    const a = assessHypothesisEvidence(hyps).get("H1")!;
    const rows = describeHypothesisEvidence(a, events);
    expect(rows.get("e1")).toEqual({
      eventId: "e1",
      present: true,
      timestamp: "2026-01-02T03:04:05Z",
      description: "event e1",
      uncertainty: ["year inferred, not read from the record", "no named source artifact"],
    });
    expect(rows.get("e9")).toEqual({
      eventId: "e9",
      present: false,
      timestamp: "",
      description: "",
      uncertainty: ["observation no longer in the timeline"],
    });
  });

  it("reads the canonical envelope's clock confidence and low-confidence fields", () => {
    const e = ev("c1", {
      canonical: {
        time: {
          observed: "2026-01-02T03:04:05Z",
          normalized: "2026-01-02T03:04:05Z",
          clockConfidence: "inferred",
        },
        fieldProvenance: {
          "actor.name": { origin: "derived", confidence: "low", recordLocators: ["r1"], derivation: "guess" },
          "host.name": { origin: "raw", confidence: "high", recordLocators: ["r1"], rawFields: ["Computer"] },
        },
      } as unknown as ForensicEvent["canonical"],
    });
    expect(eventUncertainty(e)).toEqual(["clock: inferred", "actor.name read with low confidence"]);
  });
});
