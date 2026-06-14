import { describe, it, expect } from "vitest";
import {
  gapHypothesesResponseSchema,
  sanitizeGapHypotheses,
  buildGapHypotheses,
  surroundingEvents,
  renderGapForPrompt,
  renderGapsForPrompt,
  hasGapMaterial,
  GAP_HYPOTHESIS_MAX_DEFAULT,
  type GapHypothesisAI,
} from "../../src/analysis/gapHypothesis.js";
import type { TimelineGap } from "../../src/analysis/gapDetect.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

function ev(id: string, ts: string, extra: Partial<ForensicEvent> = {}): ForensicEvent {
  return { id, timestamp: ts, description: extra.description ?? `event ${id}`, severity: extra.severity ?? "Info", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], ...extra };
}

function gap(over: Partial<TimelineGap> = {}): TimelineGap {
  return {
    id: "gap-1",
    startTimestamp: "2026-05-20T08:09:00.000Z",
    endTimestamp: "2026-05-20T10:09:00.000Z",
    durationSeconds: 7200,
    durationLabel: "2h",
    severity: "High",
    complete: true,
    silentSources: ["EventLog"],
    activeSources: [],
    beforeEventId: "a4",
    afterEventId: "b0",
    ...over,
  };
}

// A timeline: 5 events before the gap (a0..a4 at 08:0x) on WEB01, 5 after (b0..b4 at 10:0x) on DC01.
function timeline(): ForensicEvent[] {
  const before = Array.from({ length: 5 }, (_, i) => ev(`a${i}`, `2026-05-20T08:0${i}:00Z`, { asset: "WEB01" }));
  const after = Array.from({ length: 5 }, (_, i) => ev(`b${i}`, `2026-05-20T10:0${i}:00Z`, { asset: "DC01" }));
  return [...before, ...after];
}

function aiHyp(over: Partial<GapHypothesisAI> = {}): GapHypothesisAI {
  return {
    gapId: "gap-1",
    hypothesis: "Logs were cleared to hide credential dumping during the silence.",
    attackerActions: ["Cleared the Security event log", "Ran a discovery tool"],
    confidence: 60,
    severity: "High",
    mitreTechniques: ["T1070.001", "T1003.001"],
    recommendedArtifactIds: ["prefetch", "amcache"],
    ...over,
  };
}

describe("gapHypothesesResponseSchema", () => {
  it("parses a well-formed response", () => {
    const parsed = gapHypothesesResponseSchema.parse({ hypotheses: [aiHyp()] });
    expect(parsed.hypotheses).toHaveLength(1);
    expect(parsed.hypotheses[0].gapId).toBe("gap-1");
  });

  it("is lenient: bad severity falls back, missing fields default", () => {
    const parsed = gapHypothesesResponseSchema.parse({ hypotheses: [{ gapId: "gap-1", severity: "Apocalyptic" }] });
    expect(parsed.hypotheses[0].severity).toBe("Medium");
    expect(parsed.hypotheses[0].hypothesis).toBe("");
    expect(parsed.hypotheses[0].attackerActions).toEqual([]);
    expect(parsed.hypotheses[0].recommendedArtifactIds).toEqual([]);
  });

  it("defaults hypotheses to [] when absent or wrong-typed", () => {
    expect(gapHypothesesResponseSchema.parse({}).hypotheses).toEqual([]);
    expect(gapHypothesesResponseSchema.parse({ hypotheses: "nope" }).hypotheses).toEqual([]);
  });
});

describe("surroundingEvents", () => {
  it("picks the events bounding the gap by id, capping each side", () => {
    const { before, after } = surroundingEvents(gap(), timeline(), 3);
    expect(before.map((e) => e.id)).toEqual(["a2", "a3", "a4"]); // last 3 ending at the before-id
    expect(after.map((e) => e.id)).toEqual(["b0", "b1", "b2"]);  // first 3 starting at the after-id
  });

  it("returns empty sides when the bounding ids are not present", () => {
    const { before, after } = surroundingEvents(gap({ beforeEventId: "x", afterEventId: "y" }), timeline());
    expect(before).toEqual([]);
    expect(after).toEqual([]);
  });
});

describe("renderGapForPrompt / renderGapsForPrompt", () => {
  it("includes the gap id, kind, duration, window and the surrounding events", () => {
    const { before, after } = surroundingEvents(gap(), timeline(), 2);
    const text = renderGapForPrompt(gap(), before, after);
    expect(text).toContain("gap-1");
    expect(text).toContain("complete silence");
    expect(text).toContain("2h");
    expect(text).toContain("[a4]");
    expect(text).toContain("[b0]");
  });

  it("renders a placeholder for no gaps", () => {
    expect(renderGapsForPrompt([], new Map())).toBe("(no gaps)");
  });
});

describe("sanitizeGapHypotheses", () => {
  const valid = new Set(["gap-1", "gap-2"]);

  it("drops hypotheses for unknown gap ids and dedupes by gap id", () => {
    const out = sanitizeGapHypotheses([aiHyp(), aiHyp({ gapId: "gap-9" }), aiHyp({ hypothesis: "dup" })], valid);
    expect(out).toHaveLength(1);
    expect(out[0].gapId).toBe("gap-1");
    expect(out[0].hypothesis).not.toBe("dup"); // first one kept
  });

  it("clamps confidence to 0..100 and filters artifact ids to the real catalog", () => {
    const out = sanitizeGapHypotheses([aiHyp({ confidence: 250, recommendedArtifactIds: ["prefetch", "made-up", "SRUM"] })], valid);
    expect(out[0].confidence).toBe(100);
    expect(out[0].recommendedArtifactIds).toEqual(["prefetch", "srum"]); // lowercased, unknown dropped
  });

  it("treats a negative/NaN confidence as 0", () => {
    expect(sanitizeGapHypotheses([aiHyp({ confidence: -5 })], valid)[0].confidence).toBe(0);
    expect(sanitizeGapHypotheses([aiHyp({ confidence: NaN })], valid)[0].confidence).toBe(0);
  });

  it("caps the number of hypotheses", () => {
    const ids = new Set(Array.from({ length: 20 }, (_, i) => `gap-${i}`));
    const many = Array.from({ length: 20 }, (_, i) => aiHyp({ gapId: `gap-${i}` }));
    expect(sanitizeGapHypotheses(many, ids, 3)).toHaveLength(3);
    expect(sanitizeGapHypotheses(many, ids)).toHaveLength(GAP_HYPOTHESIS_MAX_DEFAULT);
  });

  it("handles undefined input", () => {
    expect(sanitizeGapHypotheses(undefined, valid)).toEqual([]);
  });
});

describe("buildGapHypotheses", () => {
  it("attaches shadow artifacts to EVERY focus gap, even one the AI skipped", () => {
    const gaps = [gap(), gap({ id: "gap-2", complete: false, severity: "Medium", beforeEventId: "a4", afterEventId: "b0" })];
    const surround = new Map(gaps.map((g) => [g.id, surroundingEvents(g, timeline())]));
    // AI only answered gap-1.
    const result = buildGapHypotheses([aiHyp()], gaps, surround);
    expect(result.hypotheses).toHaveLength(2);
    const g1 = result.hypotheses.find((h) => h.gapId === "gap-1")!;
    const g2 = result.hypotheses.find((h) => h.gapId === "gap-2")!;
    expect(g1.hypothesis).toContain("credential dumping");
    expect(g1.shadowArtifacts.length).toBeGreaterThan(0);
    expect(g2.hypothesis).toBe("");                 // AI skipped it
    expect(g2.shadowArtifacts.length).toBeGreaterThan(0); // but still gets collections
    expect(g2.severity).toBe("Medium");             // falls back to the gap's own severity
    expect(g1.targetHosts).toContain("WEB01");
    expect(result.caveat.length).toBeGreaterThan(0);
  });
});

describe("hasGapMaterial", () => {
  it("is false with no gaps, true once one exists", () => {
    expect(hasGapMaterial([])).toBe(false);
    expect(hasGapMaterial([gap()])).toBe(true);
  });
});
