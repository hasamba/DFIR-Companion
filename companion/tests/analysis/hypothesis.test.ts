import { describe, it, expect } from "vitest";
import {
  normalizeTitle,
  hypothesisAutoKey,
  sanitizeHypotheses,
  mergeHypotheses,
  hypothesisStats,
  buildAnalystHypothesis,
  applyHypothesisPatch,
  type Hypothesis,
  type HypothesisSeed,
} from "../../src/analysis/hypothesis.js";

const NOW = "2026-06-22T00:00:00.000Z";
const LATER = "2026-06-22T01:00:00.000Z";

function seed(over: Partial<HypothesisSeed> & { title: string }): HypothesisSeed {
  return {
    sourceKey: hypothesisAutoKey(over.title),
    title: over.title,
    description: over.description ?? "",
    expectedOutcome: over.expectedOutcome ?? "",
    status: over.status ?? "open",
    relatedTechniques: over.relatedTechniques ?? [],
    relatedEventIds: over.relatedEventIds ?? [],
    relatedIocIds: over.relatedIocIds ?? [],
  };
}

describe("normalizeTitle / hypothesisAutoKey", () => {
  it("normalizes case + whitespace so formatting variants fingerprint identically", () => {
    expect(normalizeTitle("  Initial   Access was PHISHING ")).toBe("initial access was phishing");
    expect(hypothesisAutoKey("Initial access was phishing")).toBe(hypothesisAutoKey("  initial   ACCESS was phishing  "));
  });

  it("returns '' for a blank title and a stable synth: key otherwise", () => {
    expect(hypothesisAutoKey("   ")).toBe("");
    expect(hypothesisAutoKey("X")).toMatch(/^synth:[0-9a-f]+$/);
  });
});

describe("sanitizeHypotheses", () => {
  const events = new Set(["e1", "e2"]);
  const iocs = new Set(["i1"]);

  it("requires a title, caps count, dedupes by key, and coerces status", () => {
    const out = sanitizeHypotheses(
      [
        { title: "", description: "skip me" },
        { title: "Phishing", status: "SUPPORTED" },
        { title: "phishing", status: "open" }, // dup of the previous by normalized title
      ],
      events,
      iocs,
    );
    expect(out).toHaveLength(1);
    expect(out[0].title).toBe("Phishing");
    expect(out[0].status).toBe("supported");
  });

  it("filters evidence links to ids that exist in the case (no dangling refs)", () => {
    const out = sanitizeHypotheses(
      [{ title: "Staging", relatedEventIds: ["e1", "e9", "e2"], relatedIocIds: ["i1", "i9"] }],
      events,
      iocs,
    );
    expect(out[0].relatedEventIds).toEqual(["e1", "e2"]);
    expect(out[0].relatedIocIds).toEqual(["i1"]);
  });

  it("defaults an unknown status to open and honors the max cap", () => {
    const raw = Array.from({ length: 12 }, (_, i) => ({ title: `H${i}`, status: "weird" }));
    const out = sanitizeHypotheses(raw, events, iocs, 3);
    expect(out).toHaveLength(3);
    expect(out.every((h) => h.status === "open")).toBe(true);
  });
});

describe("mergeHypotheses", () => {
  it("appends fresh synthesis hypotheses with id = sourceKey", () => {
    const { hypotheses, changed } = mergeHypotheses([], [seed({ title: "Phishing" })], NOW);
    expect(changed).toBe(true);
    expect(hypotheses).toHaveLength(1);
    expect(hypotheses[0].id).toBe(hypothesisAutoKey("Phishing"));
    expect(hypotheses[0].source).toBe("synthesis");
    expect(hypotheses[0].analystTouched).toBe(false);
  });

  it("refreshes a PRISTINE synthesis hypothesis from a new seed", () => {
    const first = mergeHypotheses([], [seed({ title: "Phishing", description: "old" })], NOW).hypotheses;
    const { hypotheses, changed } = mergeHypotheses(first, [seed({ title: "Phishing", description: "new" })], LATER);
    expect(changed).toBe(true);
    expect(hypotheses).toHaveLength(1);
    expect(hypotheses[0].description).toBe("new");
    expect(hypotheses[0].updatedAt).toBe(LATER);
  });

  it("FREEZES a touched synthesis hypothesis — synthesis no longer overwrites it", () => {
    const base = mergeHypotheses([], [seed({ title: "Phishing", description: "old", status: "open" })], NOW).hypotheses;
    const touched = base.map((h) => applyHypothesisPatch(h, { status: "supported", notes: "confirmed" }, NOW));
    const { hypotheses, changed } = mergeHypotheses(touched, [seed({ title: "Phishing", description: "REWORDED", status: "refuted" })], LATER);
    expect(changed).toBe(false);
    expect(hypotheses[0].description).toBe("old");
    expect(hypotheses[0].status).toBe("supported");
    expect(hypotheses[0].notes).toBe("confirmed");
  });

  it("PRUNES a pristine synthesis hypothesis whose seed disappeared", () => {
    const base = mergeHypotheses([], [seed({ title: "Phishing" }), seed({ title: "Lateral movement" })], NOW).hypotheses;
    const { hypotheses, changed } = mergeHypotheses(base, [seed({ title: "Phishing" })], LATER);
    expect(changed).toBe(true);
    expect(hypotheses.map((h) => h.title)).toEqual(["Phishing"]);
  });

  it("KEEPS a touched synthesis hypothesis whose seed disappeared", () => {
    const base = mergeHypotheses([], [seed({ title: "Lateral movement" })], NOW).hypotheses;
    const touched = base.map((h) => applyHypothesisPatch(h, { status: "refuted" }, NOW));
    const { hypotheses } = mergeHypotheses(touched, [], LATER);
    expect(hypotheses).toHaveLength(1);
    expect(hypotheses[0].status).toBe("refuted");
  });

  it("never touches analyst-authored hypotheses", () => {
    const analyst = buildAnalystHypothesis({ title: "My idea" }, "uuid-1", NOW);
    const { hypotheses } = mergeHypotheses([analyst], [seed({ title: "Phishing" })], LATER);
    expect(hypotheses.find((h) => h.id === "uuid-1")).toBeTruthy();
    expect(hypotheses).toHaveLength(2);
  });

  it("is idempotent: same seeds twice produce no second change", () => {
    const first = mergeHypotheses([], [seed({ title: "Phishing" })], NOW).hypotheses;
    const second = mergeHypotheses(first, [seed({ title: "Phishing" })], LATER);
    expect(second.changed).toBe(false);
  });
});

describe("buildAnalystHypothesis / applyHypothesisPatch", () => {
  it("builds an analyst hypothesis born analystTouched with a default author", () => {
    const h = buildAnalystHypothesis({ title: "  Idea  ", relatedTechniques: ["T1566", "T1566"] }, "id1", NOW);
    expect(h.title).toBe("Idea");
    expect(h.source).toBe("analyst");
    expect(h.analystTouched).toBe(true);
    expect(h.author).toBe("anonymous");
    expect(h.relatedTechniques).toEqual(["T1566"]);
  });

  it("patch marks analystTouched, bumps updatedAt, ignores unknown status", () => {
    const h = buildAnalystHypothesis({ title: "Idea" }, "id1", NOW);
    const patched = applyHypothesisPatch(h, { status: "bogus" as Hypothesis["status"], notes: "n" }, LATER);
    expect(patched.status).toBe("open");
    expect(patched.notes).toBe("n");
    expect(patched.analystTouched).toBe(true);
    expect(patched.updatedAt).toBe(LATER);
  });
});

describe("statusHistory (issue #95)", () => {
  it("a freshly built hypothesis is born with a single status-history entry", () => {
    const h = buildAnalystHypothesis({ title: "Idea", status: "supported" }, "id1", NOW);
    expect(h.statusHistory).toEqual([{ status: "supported", changedAt: NOW }]);
  });

  it("a patch that changes status appends an entry; a patch that doesn't leaves history untouched", () => {
    const h = buildAnalystHypothesis({ title: "Idea" }, "id1", NOW);
    const sameStatus = applyHypothesisPatch(h, { notes: "n" }, LATER);
    expect(sameStatus.statusHistory).toEqual([{ status: "open", changedAt: NOW }]);

    const changed = applyHypothesisPatch(h, { status: "supported" }, LATER);
    expect(changed.statusHistory).toEqual([
      { status: "open", changedAt: NOW },
      { status: "supported", changedAt: LATER },
    ]);
  });

  it("an unknown/ignored status patch does not append a spurious history entry", () => {
    const h = buildAnalystHypothesis({ title: "Idea" }, "id1", NOW);
    const patched = applyHypothesisPatch(h, { status: "bogus" as Hypothesis["status"] }, LATER);
    expect(patched.statusHistory).toEqual([{ status: "open", changedAt: NOW }]);
  });

  it("a fresh synthesis hypothesis is born with its seed status in history", () => {
    const { hypotheses } = mergeHypotheses([], [seed({ title: "Phishing", status: "supported" })], NOW);
    expect(hypotheses[0].statusHistory).toEqual([{ status: "supported", changedAt: NOW }]);
  });

  it("a pristine synthesis refresh that changes status appends to history", () => {
    const first = mergeHypotheses([], [seed({ title: "Phishing", status: "open" })], NOW).hypotheses;
    const { hypotheses } = mergeHypotheses(first, [seed({ title: "Phishing", status: "refuted" })], LATER);
    expect(hypotheses[0].statusHistory).toEqual([
      { status: "open", changedAt: NOW },
      { status: "refuted", changedAt: LATER },
    ]);
  });

  it("a same-status refresh (other fields changed) does not duplicate the history entry", () => {
    const first = mergeHypotheses([], [seed({ title: "Phishing", description: "old", status: "open" })], NOW).hypotheses;
    const { hypotheses } = mergeHypotheses(first, [seed({ title: "Phishing", description: "new", status: "open" })], LATER);
    expect(hypotheses[0].statusHistory).toEqual([{ status: "open", changedAt: NOW }]);
  });
});

describe("hypothesisStats", () => {
  it("counts by status", () => {
    const mk = (id: string, status: Hypothesis["status"]): Hypothesis => ({
      ...buildAnalystHypothesis({ title: id }, id, NOW),
      status,
    });
    const stats = hypothesisStats([mk("a", "open"), mk("b", "open"), mk("c", "supported"), mk("d", "refuted")]);
    expect(stats).toEqual({ total: 4, open: 2, supported: 1, refuted: 1, unknown: 0 });
  });
});
