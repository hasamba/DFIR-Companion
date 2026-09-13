import { describe, it, expect } from "vitest";
import {
  applyHypothesisPatch,
  mergeHypotheses,
  reconsiderHypotheses,
  hypothesesSchema,
  FP_REVIEW_REASON,
  type Hypothesis,
  type HypothesisSeed,
} from "../../src/analysis/hypothesis.js";
import {
  excludeEvidence,
  restoreEvidence,
  closeUnlinkedExclusions,
  flagMaterialChanges,
} from "../../src/analysis/hypothesisExclusion.js";

// #933 item 22 — an analyst may exclude an observation from ONE hypothesis's assessment, with an
// audit trail; nothing is deleted, frozen judgments are never rewritten, and a material change in
// what a conclusion rests on is flagged for review with its reason.

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
    sourceKey: partial.id,
    createdAt: "2026-01-01T00:00:00Z",
    updatedAt: "2026-01-01T00:00:00Z",
    statusHistory: [{ status: partial.status ?? "open", changedAt: "2026-01-01T00:00:00Z" }],
    ...partial,
  };
}

function seed(partial: Partial<HypothesisSeed> & { sourceKey: string; title: string }): HypothesisSeed {
  return {
    description: "",
    expectedOutcome: "",
    status: "open",
    relatedTechniques: [],
    relatedEventIds: [],
    relatedIocIds: [],
    contradictingEventIds: [],
    discriminator: "",
    ...partial,
  };
}

const T1 = "2026-02-01T00:00:00Z";
const T2 = "2026-02-02T00:00:00Z";

describe("excludeEvidence / restoreEvidence — an audit trail, not a deletion", () => {
  it("excludes a linked observation, keeps the link, and does not freeze the hypothesis", () => {
    const base = h({ id: "H1", title: "H1", relatedEventIds: ["e1", "e2"] });
    const out = excludeEvidence(base, "e1", "same source as e2", "alice", T1)!;
    expect(out.excludedEvidence).toEqual([
      { eventId: "e1", reason: "same source as e2", by: "alice", excludedAt: T1 },
    ]);
    expect(out.relatedEventIds).toEqual(["e1", "e2"]);
    expect(out.analystTouched).toBe(false);
    expect(out.updatedAt).toBe(T1);
    // Idempotent while active; a second exclusion after a restore appends a new entry.
    expect(excludeEvidence(out, "e1", "again", "alice", T2)).toBe(out);
    const restored = restoreEvidence(out, "e1", "bob", T2)!;
    expect(restored.excludedEvidence[0]).toMatchObject({ eventId: "e1", restoredAt: T2, restoredBy: "bob" });
    const again = excludeEvidence(restored, "e1", "still noise", "alice", "2026-02-03T00:00:00Z")!;
    expect(again.excludedEvidence).toHaveLength(2);
    expect(again.excludedEvidence[1]).toMatchObject({ eventId: "e1", reason: "still noise" });
  });

  it("refuses an observation the hypothesis does not link, and a restore with no active entry", () => {
    const base = h({ id: "H1", title: "H1", relatedEventIds: ["e1"], contradictingEventIds: ["c1"] });
    expect(excludeEvidence(base, "zz", "r", "a", T1)).toBeNull();
    expect(excludeEvidence(base, "c1", "r", "a", T1)).not.toBeNull(); // a contradiction can be excluded too
    expect(restoreEvidence(base, "e1", "a", T1)).toBeNull();
    expect(excludeEvidence(base, "e1", "   ", "a", T1)).toBeNull(); // a reason is required
  });

  it("closes an active exclusion when the observation is unlinked, and relinking does not revive it", () => {
    const excluded = excludeEvidence(
      h({ id: "H1", title: "H1", relatedEventIds: ["e1", "e2"] }),
      "e1",
      "noise",
      "a",
      T1,
    )!;
    const unlinked = closeUnlinkedExclusions(
      applyHypothesisPatch(excluded, { relatedEventIds: ["e2"] }, T2),
      T2,
    );
    expect(unlinked.excludedEvidence[0]).toMatchObject({
      eventId: "e1",
      restoredAt: T2,
      restoredBy: "unlinked",
    });
    // Nothing to close → the same object back (no spurious write).
    expect(closeUnlinkedExclusions(unlinked, "2026-02-03T00:00:00Z")).toBe(unlinked);
    const relinked = applyHypothesisPatch(
      unlinked,
      { relatedEventIds: ["e1", "e2"] },
      "2026-02-03T00:00:00Z",
    );
    expect(relinked.excludedEvidence.every((x) => x.restoredAt)).toBe(true);
  });
});

describe("review flag — cleared only by a status change or an explicit acknowledgement", () => {
  const flagged = h({
    id: "H1",
    title: "H1",
    needsReview: true,
    reviewReason: "the latest synthesis cites e7 against this",
  });

  it("keeps the flag and its reason across a notes or assignee edit", () => {
    const out = applyHypothesisPatch(flagged, { notes: "looking", assignee: "bob" }, T1);
    expect(out.needsReview).toBe(true);
    expect(out.reviewReason).toBe("the latest synthesis cites e7 against this");
  });

  it("clears on a status change or on acknowledgeReview", () => {
    expect(applyHypothesisPatch(flagged, { status: "supported" }, T1)).toMatchObject({
      needsReview: false,
      reviewReason: "",
    });
    expect(applyHypothesisPatch(flagged, { acknowledgeReview: true }, T1)).toMatchObject({
      needsReview: false,
      reviewReason: "",
    });
    expect(applyHypothesisPatch(flagged, { status: "open" }, T1).needsReview).toBe(true); // same status = no change
  });

  it("the false-positive cascade says why it flagged", () => {
    const { hypotheses } = reconsiderHypotheses(
      [h({ id: "H1", title: "H1", relatedEventIds: ["e1"] })],
      { fpEventIds: new Set(["e1"]), fpIocIds: new Set() },
      T1,
    );
    expect(hypotheses[0]).toMatchObject({
      needsReview: true,
      reviewReason: "an event or IOC that supported this hypothesis was marked false positive",
    });
  });

  it("alternativeIds is analyst-owned: patchable, deduped, never self", () => {
    const out = applyHypothesisPatch(
      h({ id: "H1", title: "H1" }),
      { alternativeIds: ["H2", "H2", "H1", " H3 "] },
      T1,
    );
    expect(out.alternativeIds).toEqual(["H2", "H3"]);
  });
});

describe("mergeHypotheses with exclusions", () => {
  it("a refresh keeps the analyst's exclusions and does not prune a hypothesis that carries one", () => {
    const stored = [
      excludeEvidence(h({ id: "k1", title: "one", relatedEventIds: ["e1", "e2"] }), "e1", "noise", "a", T1)!,
      h({ id: "k2", title: "two", relatedEventIds: ["e3"] }),
    ];
    const { hypotheses } = mergeHypotheses(
      stored,
      [seed({ sourceKey: "k1", title: "one (reworded)", relatedEventIds: ["e1", "e2", "e5"] })],
      T2,
    );
    const one = hypotheses.find((x) => x.id === "k1")!;
    expect(one.title).toBe("one (reworded)"); // refreshed — an exclusion is not a freeze
    expect(one.excludedEvidence).toHaveLength(1);
    expect(hypotheses.find((x) => x.id === "k2")).toBeUndefined(); // pristine, no exclusion → pruned as before
    const { hypotheses: kept } = mergeHypotheses([stored[0]], [], T2);
    expect(kept.map((x) => x.id)).toEqual(["k1"]); // carries an exclusion → kept, not pruned
  });

  it("a pre-#933.22 hypotheses.json parses with the new fields defaulted", () => {
    const legacy = { ...h({ id: "x", title: "x" }) } as Record<string, unknown>;
    delete legacy.excludedEvidence;
    delete legacy.alternativeIds;
    delete legacy.reviewReason;
    const [parsed] = hypothesesSchema.parse([legacy]);
    expect(parsed).toMatchObject({ excludedEvidence: [], alternativeIds: [], reviewReason: "" });
  });
});

describe("flagMaterialChanges — frozen judgments preserved, material changes marked with a reason", () => {
  it("guardrail: an excluded observation later becoming relevant flags the hypothesis, changes nothing else", () => {
    const before = [
      excludeEvidence(
        h({
          id: "H1",
          title: "H1",
          relatedEventIds: ["e3", "e4"],
          status: "supported",
          analystTouched: true,
        }),
        "e3",
        "fits everything",
        "a",
        T1,
      )!,
      h({ id: "H2", title: "H2", relatedEventIds: ["e3", "e4"] }),
    ];
    const after = [
      ...before,
      h({ id: "H4", title: "Access was a stolen token", contradictingEventIds: ["e3"] }),
    ];
    const { hypotheses, changed } = flagMaterialChanges(before, after, new Map(), undefined, T2);
    expect(changed).toBe(true);
    const h1 = hypotheses.find((x) => x.id === "H1")!;
    expect(h1.needsReview).toBe(true);
    expect(h1.reviewReason).toBe(
      "an observation you excluded (e3) now separates this from 'Access was a stolen token'",
    );
    expect(h1.status).toBe("supported");
    expect(h1.relatedEventIds).toEqual(["e3", "e4"]);
    expect(h1.excludedEvidence).toHaveLength(1);
    expect(h1.excludedEvidence[0].restoredAt).toBeUndefined();
    // Re-running with the same input is a no-op.
    expect(
      flagMaterialChanges(before, hypotheses, new Map(), undefined, "2026-02-03T00:00:00Z").changed,
    ).toBe(false);
  });

  it("an observation excluded while it already distinguished is the analyst's call — not re-raised on the next merge", () => {
    const before = [
      excludeEvidence(
        h({
          id: "H1",
          title: "H1",
          status: "supported",
          analystTouched: true,
          relatedEventIds: ["e1", "e2"],
        }),
        "e1",
        "noise despite the split",
        "a",
        T1,
      )!,
      h({ id: "H2", title: "H2", contradictingEventIds: ["e1"], relatedEventIds: ["e2"] }),
    ];
    // An unrelated merge: H2 is refreshed with the same links.
    const after = [before[0], h({ ...before[1], description: "reworded" })];
    expect(flagMaterialChanges(before, after, new Map(), undefined, T2).changed).toBe(false);
    // But a NEW alternative that the excluded observation separates it from is a transition.
    const withNew = [...after, h({ id: "H3", title: "H3", contradictingEventIds: ["e1"] })];
    const { hypotheses } = flagMaterialChanges(before, withNew, new Map(), undefined, T2);
    expect(hypotheses[0].reviewReason).toBe("an observation you excluded (e1) now separates this from 'H3'");
  });

  it("adds a material-change reason to an existing false-positive flag, and the cascade adds its reason to a material-change flag", () => {
    const flagged = h({
      id: "H1",
      title: "H1",
      analystTouched: true,
      needsReview: true,
      reviewReason: FP_REVIEW_REASON,
      contradictingEventIds: ["c1"],
      relatedEventIds: ["e1"],
    });
    const before = [flagged, h({ id: "H2", title: "H2" })];
    const after = [flagged, h({ id: "H2", title: "H2", relatedEventIds: ["c1"] })];
    const { hypotheses } = flagMaterialChanges(before, after, new Map(), undefined, T2);
    expect(hypotheses[0].reviewReason).toBe(`${FP_REVIEW_REASON}; c1 now supports 'H2'`);
    // The other way round: a material-change flag, then the supporting event is marked false positive.
    const material = h({ ...flagged, reviewReason: "c1 now supports 'H2'" });
    const out = reconsiderHypotheses([material], { fpEventIds: new Set(["e1"]), fpIocIds: new Set() }, T2);
    expect(out.changed).toBe(true);
    expect(out.hypotheses[0].reviewReason).toBe(`c1 now supports 'H2'; ${FP_REVIEW_REASON}`);
    // And a second cascade for the same cause changes nothing.
    expect(
      reconsiderHypotheses(out.hypotheses, { fpEventIds: new Set(["e1"]), fpIocIds: new Set() }, T2).changed,
    ).toBe(false);
  });

  it("a frozen supported hypothesis whose sole distinguishing support stops distinguishing is flagged, not rewritten", () => {
    const before = [
      h({ id: "H1", title: "H1", status: "supported", analystTouched: true, relatedEventIds: ["e1"] }),
      h({ id: "H2", title: "H2", contradictingEventIds: ["e1"] }),
    ];
    // H2 was refreshed: it now supports e1 too — nothing separates H1 from it any more.
    const after = [before[0], h({ ...before[1], contradictingEventIds: [], relatedEventIds: ["e1"] })];
    const { hypotheses } = flagMaterialChanges(before, after, new Map(), undefined, T2);
    expect(hypotheses[0]).toMatchObject({
      status: "supported",
      needsReview: true,
      reviewReason:
        "the observation(s) this conclusion rested on no longer separate it from the alternatives",
    });
    // A pristine hypothesis in the same position is left to the refresh: not flagged here.
    const pristine = [h({ ...before[0], analystTouched: false }), before[1]];
    const pristineAfter = [pristine[0], after[1]];
    expect(flagMaterialChanges(pristine, pristineAfter, new Map(), undefined, T2).changed).toBe(false);
  });

  it("a contradiction that became distinguishing is flagged with the alternative it now supports", () => {
    const before = [
      h({ id: "H1", title: "H1", analystTouched: true, contradictingEventIds: ["c1"] }),
      h({ id: "H2", title: "Lateral movement over RDP" }),
    ];
    const after = [before[0], h({ ...before[1], relatedEventIds: ["c1"] })];
    const { hypotheses } = flagMaterialChanges(before, after, new Map(), undefined, T2);
    expect(hypotheses[0].reviewReason).toBe("c1 now supports 'Lateral movement over RDP'");
  });

  it("compares a frozen hypothesis with its incoming seed: withdrawn support and new contradictions", () => {
    const stored = [
      h({ id: "k1", title: "H1", status: "supported", analystTouched: true, relatedEventIds: ["e1", "e2"] }),
      h({ id: "k2", title: "H2", contradictingEventIds: ["e1"] }),
    ];
    const seeds = new Map([
      ["k1", seed({ sourceKey: "k1", title: "H1", relatedEventIds: ["e2"], contradictingEventIds: ["e9"] })],
    ]);
    const { hypotheses } = flagMaterialChanges(stored, stored, seeds, undefined, T2);
    expect(hypotheses[0].reviewReason).toBe(
      "the latest synthesis no longer cites e1 as support for this; the latest synthesis cites e9 against this",
    );
    expect(hypotheses[0].relatedEventIds).toEqual(["e1", "e2"]); // the seed was not applied
    // A seed that simply stops proposing the hypothesis is not a material change.
    expect(flagMaterialChanges(stored, stored, new Map(), undefined, T2).changed).toBe(false);
  });

  it("honours eligibility: a false-positive observation cannot make a change material", () => {
    const before = [
      h({ id: "H1", title: "H1", analystTouched: true, contradictingEventIds: ["c1"] }),
      h({ id: "H2", title: "H2" }),
    ];
    const after = [before[0], h({ ...before[1], relatedEventIds: ["c1"] })];
    const out = flagMaterialChanges(
      before,
      after,
      new Map(),
      { eligibleEventIds: new Set(["c1"]), falsePositiveEventIds: new Set(["c1"]) },
      T2,
    );
    expect(out.changed).toBe(false);
  });
});
