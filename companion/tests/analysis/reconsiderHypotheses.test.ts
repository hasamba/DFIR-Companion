import { describe, it, expect } from "vitest";
import { reconsiderHypotheses, type Hypothesis } from "../../src/analysis/hypothesis.js";

function h(partial: Partial<Hypothesis> & { id: string; title: string }): Hypothesis {
  return {
    description: "", expectedOutcome: "", status: "open", relatedTechniques: [],
    relatedEventIds: [], relatedIocIds: [], assignee: "", notes: "",
    source: "synthesis", analystTouched: false, needsReview: false,
    createdAt: "2026-01-01T00:00:00Z", updatedAt: "2026-01-01T00:00:00Z", ...partial,
  };
}
const NOW = "2026-02-02T00:00:00Z";

describe("reconsiderHypotheses (#12)", () => {
  it("flips a PRISTINE hypothesis to unknown + needsReview when its evidence is rejected", () => {
    const { hypotheses: out, changed } = reconsiderHypotheses(
      [h({ id: "hp1", title: "staging", status: "supported", relatedEventIds: ["e5"], analystTouched: false })],
      { fpEventIds: new Set(["e5"]), fpIocIds: new Set() },
      NOW,
    );
    expect(changed).toBe(true);
    expect(out[0].status).toBe("unknown");
    expect(out[0].needsReview).toBe(true);
    expect(out[0].updatedAt).toBe(NOW);
  });

  it("records the flip-to-unknown in statusHistory (issue #95)", () => {
    const { hypotheses: out } = reconsiderHypotheses(
      [h({ id: "hp1", title: "staging", status: "supported", relatedEventIds: ["e5"], analystTouched: false,
        statusHistory: [{ status: "supported", changedAt: "2026-01-01T00:00:00Z" }] })],
      { fpEventIds: new Set(["e5"]), fpIocIds: new Set() },
      NOW,
    );
    expect(out[0].statusHistory).toEqual([
      { status: "supported", changedAt: "2026-01-01T00:00:00Z" },
      { status: "unknown", changedAt: NOW },
    ]);
  });

  it("respects the analyst freeze: a TOUCHED hypothesis keeps its status, only flagged needsReview", () => {
    const { hypotheses: out } = reconsiderHypotheses(
      [h({ id: "hp1", title: "staging", status: "supported", relatedIocIds: ["i2"], analystTouched: true })],
      { fpEventIds: new Set(), fpIocIds: new Set(["i2"]) },
      NOW,
    );
    expect(out[0].status).toBe("supported");   // frozen
    expect(out[0].needsReview).toBe(true);
  });

  it("matches event ids case-insensitively and leaves unrelated hypotheses untouched", () => {
    const { hypotheses: out, changed } = reconsiderHypotheses(
      [
        h({ id: "hp1", title: "a", relatedEventIds: ["E9"] }),   // FP marker stores lowercased
        h({ id: "hp2", title: "b", relatedEventIds: ["e1"] }),
      ],
      { fpEventIds: new Set(["e9"]), fpIocIds: new Set() },
      NOW,
    );
    expect(changed).toBe(true);
    expect(out[0].needsReview).toBe(true);
    expect(out[1].needsReview).toBe(false);
  });

  it("is idempotent — a second pass over an already-flagged pristine hypothesis reports no change", () => {
    const first = reconsiderHypotheses(
      [h({ id: "hp1", title: "a", status: "open", relatedEventIds: ["e5"] })],
      { fpEventIds: new Set(["e5"]), fpIocIds: new Set() }, NOW,
    );
    const second = reconsiderHypotheses(first.hypotheses, { fpEventIds: new Set(["e5"]), fpIocIds: new Set() }, "2026-03-03T00:00:00Z");
    expect(second.changed).toBe(false);
    expect(second.hypotheses[0].updatedAt).toBe(NOW);   // not re-stamped
  });
});
