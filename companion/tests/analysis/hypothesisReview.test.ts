import { describe, it, expect } from "vitest";
import { sanitizeHypothesisReviews } from "../../src/analysis/hypothesis.js";

// Falsification review (issue #71) — pure sanitize core. Turns a raw model response into clean,
// ADVISORY review items: known targets only, real event ids only, coerced status, capped bullets.
describe("sanitizeHypothesisReviews (#71)", () => {
  const known = new Map([
    ["h1", "Initial access was phishing"],
    ["h2", "Data was staged before encryption"],
  ]);
  const validEvents = new Set(["e1", "e2", "e3"]);

  it("drops reviews for unknown hypothesis ids (no invented targets)", () => {
    const out = sanitizeHypothesisReviews(
      [
        { hypothesisId: "h1", recommendedStatus: "supported" },
        { hypothesisId: "ghost", recommendedStatus: "refuted" },
      ],
      known,
      validEvents,
    );
    expect(out.map((r) => r.hypothesisId)).toEqual(["h1"]);
  });

  it("uses the KNOWN title, ignoring the model's echoed (drifted) title", () => {
    const [r] = sanitizeHypothesisReviews(
      [{ hypothesisId: "h1", title: "totally different wording" }],
      known,
      validEvents,
    );
    expect(r.title).toBe("Initial access was phishing");
  });

  it("trims, dedupes, drops blanks and caps support/refute bullets", () => {
    const [r] = sanitizeHypothesisReviews(
      [{
        hypothesisId: "h1",
        supportingEvidence: ["  a phishing email was found  ", "a phishing email was found", "", "   "],
        refutingEvidence: ["no attachment in web-proxy logs"],
      }],
      known,
      validEvents,
    );
    expect(r.supportingEvidence).toEqual(["a phishing email was found"]);
    expect(r.refutingEvidence).toEqual(["no attachment in web-proxy logs"]);
  });

  it("coerces an out-of-enum recommendedStatus to 'unknown' (advisory)", () => {
    const [r] = sanitizeHypothesisReviews(
      [{ hypothesisId: "h1", recommendedStatus: "PROBABLY_TRUE" }],
      known,
      validEvents,
    );
    expect(r.recommendedStatus).toBe("unknown");
  });

  it("accepts a valid recommendedStatus case-insensitively", () => {
    const [r] = sanitizeHypothesisReviews(
      [{ hypothesisId: "h2", recommendedStatus: "Refuted" }],
      known,
      validEvents,
    );
    expect(r.recommendedStatus).toBe("refuted");
  });

  it("filters relatedEventIds to real case events only", () => {
    const [r] = sanitizeHypothesisReviews(
      [{ hypothesisId: "h1", relatedEventIds: ["e1", "e9", "e2"] }],
      known,
      validEvents,
    );
    expect(r.relatedEventIds).toEqual(["e1", "e2"]);
  });

  it("dedupes by hypothesisId (first wins) and caps the count", () => {
    const dup = sanitizeHypothesisReviews(
      [
        { hypothesisId: "h1", rationale: "first" },
        { hypothesisId: "h1", rationale: "second" },
      ],
      known,
      validEvents,
    );
    expect(dup).toHaveLength(1);
    expect(dup[0].rationale).toBe("first");

    const capped = sanitizeHypothesisReviews(
      [{ hypothesisId: "h1" }, { hypothesisId: "h2" }],
      known,
      validEvents,
      1,
    );
    expect(capped).toHaveLength(1);
  });

  it("returns [] for empty / undefined input", () => {
    expect(sanitizeHypothesisReviews(undefined, known, validEvents)).toEqual([]);
    expect(sanitizeHypothesisReviews([], known, validEvents)).toEqual([]);
  });
});
