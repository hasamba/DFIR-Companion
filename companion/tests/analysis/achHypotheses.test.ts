import { describe, it, expect } from "vitest";
import {
  sanitizeHypotheses,
  rankHypothesesAch,
  markExhaustedHypotheses,
  type Hypothesis,
  type HypothesisHuntSignal,
} from "../../src/analysis/hypothesis.js";
import { renderRefutedHypothesesBlock } from "../../src/analysis/priorWork.js";

function h(partial: Partial<Hypothesis> & { id: string; title: string }): Hypothesis {
  return {
    description: "", expectedOutcome: "", status: "open", relatedTechniques: [], relatedEventIds: [],
    relatedIocIds: [], contradictingEventIds: [], discriminator: "", exhausted: false, exhaustedReason: "",
    assignee: "", notes: "", source: "synthesis", analystTouched: false, needsReview: false,
    createdAt: "2026-01-01T00:00:00Z", updatedAt: "2026-01-01T00:00:00Z", ...partial,
  };
}
const NOW = "2026-02-02T00:00:00Z";

describe("sanitizeHypotheses ACH fields (#14)", () => {
  it("keeps contradictingEventIds (filtered to real events) + discriminator", () => {
    const [seed] = sanitizeHypotheses(
      [{ title: "T", relatedEventIds: ["e1"], contradictingEventIds: ["e2", "ghost"], discriminator: "  $MFT on FS01  " }],
      new Set(["e1", "e2"]),
      new Set(),
    );
    expect(seed.contradictingEventIds).toEqual(["e2"]);   // "ghost" dropped (not a real event)
    expect(seed.discriminator).toBe("$MFT on FS01");
  });
});

describe("rankHypothesesAch (#14)", () => {
  it("orders by fewest contradictions, then most support; sinks exhausted/refuted", () => {
    const ranked = rankHypothesesAch([
      h({ id: "wellSupportedButWrong", title: "A", relatedEventIds: ["e1", "e2", "e3"], contradictingEventIds: ["e8", "e9"] }),
      h({ id: "clean", title: "B", relatedEventIds: ["e1"], contradictingEventIds: [] }),
      h({ id: "exhausted", title: "C", contradictingEventIds: [], exhausted: true }),
      h({ id: "oneContra", title: "D", relatedEventIds: ["e1", "e2"], contradictingEventIds: ["e8"] }),
    ]);
    expect(ranked.map((x) => x.id)).toEqual(["clean", "oneContra", "wellSupportedButWrong", "exhausted"]);
  });
});

describe("markExhaustedHypotheses (#14)", () => {
  const hyps = [
    h({ id: "hp_explicit", title: "explicit", relatedTechniques: ["T1048"] }),
    h({ id: "hp_tech", title: "by technique", relatedTechniques: ["T1021"] }),
    h({ id: "hp_supported", title: "supported", status: "supported", relatedTechniques: ["T1021"] }),
  ];

  it("exhausts an OPEN hypothesis after N empty hunts (explicit link or technique match); freezes status", () => {
    const signals: HypothesisHuntSignal[] = [
      { relatedHypothesisId: "hp_explicit", techniques: [], missed: true },
      { relatedHypothesisId: "hp_explicit", techniques: [], missed: true },
      { techniques: ["T1021"], missed: true },   // matches hp_tech AND hp_supported by technique
      { techniques: ["T1021"], missed: true },
      { techniques: ["T1021"], missed: false },  // a hit — not counted
    ];
    const { hypotheses: out, changed } = markExhaustedHypotheses(hyps, signals, NOW, 2);
    expect(changed).toBe(true);
    expect(out.find((x) => x.id === "hp_explicit")!.exhausted).toBe(true);
    expect(out.find((x) => x.id === "hp_tech")!.exhausted).toBe(true);
    // A supported hypothesis is already resolved — exhaustion doesn't apply.
    expect(out.find((x) => x.id === "hp_supported")!.exhausted).toBe(false);
  });

  it("does not exhaust below the miss threshold and is idempotent", () => {
    const one: HypothesisHuntSignal[] = [{ relatedHypothesisId: "hp_explicit", techniques: [], missed: true }];
    expect(markExhaustedHypotheses(hyps, one, NOW, 2).changed).toBe(false);
    const many: HypothesisHuntSignal[] = [
      { relatedHypothesisId: "hp_explicit", techniques: [], missed: true },
      { relatedHypothesisId: "hp_explicit", techniques: [], missed: true },
    ];
    const first = markExhaustedHypotheses(hyps, many, NOW, 2);
    const second = markExhaustedHypotheses(first.hypotheses, many, "2026-03-03T00:00:00Z", 2);
    expect(second.changed).toBe(false);   // already exhausted → no re-stamp
  });
});

describe("renderRefutedHypothesesBlock includes exhausted (#14)", () => {
  it("lists both refuted (analyst) and exhausted hypotheses as negative knowledge", () => {
    const block = renderRefutedHypothesesBlock([
      h({ id: "r", title: "ruled out", status: "refuted", analystTouched: true, source: "analyst" }),
      h({ id: "e", title: "hunted dry", exhausted: true, exhaustedReason: "3 hunts came back empty" }),
    ]);
    expect(block).toContain("[refuted] ruled out");
    expect(block).toContain("[exhausted] hunted dry");
    expect(block).toContain("settled negative knowledge");
  });

  it("returns '' when there is neither", () => {
    expect(renderRefutedHypothesesBlock([h({ id: "o", title: "open one" })])).toBe("");
  });
});
