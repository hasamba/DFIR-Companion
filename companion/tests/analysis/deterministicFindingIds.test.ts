import { describe, expect, it } from "vitest";
import { backfillActivityWaveFinding, detectGapsWithWaves } from "../../src/analysis/activityWaves.js";
import { carryOutOfWindowFindings } from "../../src/analysis/ai/synthesisMerge.js";
import { deltaSchema, isDeterministicFindingId } from "../../src/analysis/responseSchema.js";
import { emptyState, type Finding, type ForensicEvent } from "../../src/analysis/stateTypes.js";

/**
 * A deterministic finding id is a PROVENANCE claim (#787).
 *
 * Three separate passes read `f-auto-*` / `f-gap-*` / `f-waves` as proof that a finding was minted
 * by a deterministic backfill and not by a model: `carryOutOfWindowFindings` re-attaches only those
 * across a narrowed window, and each backfill treats one it already sees as its own work being
 * done and skips. But the synthesis prompt echoes every prior finding id back to the model
 * (`buildFindingsEcho`), so the model is SHOWN the very strings those three passes trust.
 *
 * The schema is where that is stopped: a model finding wearing a reserved id is renamed before it
 * can reach state, and every reference to it inside the same delta is renamed with it.
 */

const finding = (id: string, over: Partial<Finding> = {}): Finding => ({
  id,
  severity: "High",
  title: `title ${id}`,
  description: `description ${id}`,
  relatedIocs: [],
  mitreTechniques: [],
  sourceScreenshots: [],
  firstSeen: "2026-01-01T00:00:00.000Z",
  lastUpdated: "2026-01-01T00:00:00.000Z",
  status: "open",
  ...over,
});

const event = (id: string, findingIds: string[], timestamp = "2026-01-01T00:00:00.000Z"): ForensicEvent => ({
  id,
  timestamp,
  description: `event ${id}`,
  severity: "High",
  mitreTechniques: [],
  relatedFindingIds: findingIds,
  sourceScreenshots: [],
});

const parse = (
  findings: unknown[],
  over: Record<string, unknown> = {},
): ReturnType<typeof deltaSchema.parse> =>
  deltaSchema.parse({
    findings,
    iocs: [],
    mitreTechniques: [],
    threadsOpened: [],
    threadsClosed: [],
    timelineNote: "n",
    summary: "s",
    ...over,
  });

const modelFinding = (id: string): Record<string, unknown> => ({
  id,
  severity: "Critical",
  title: "model claim",
  description: "d",
  relatedIocs: [],
  mitreTechniques: [],
  status: "open",
});

describe("reserved deterministic finding ids", () => {
  it.each(["f-auto-e5", "f-gap-e1-e2", "f-waves"])(
    "renames the model's %s out of the reserved space",
    (id) => {
      const delta = parse([modelFinding(id)]);
      expect(delta.findings[0].id).not.toBe(id);
      expect(isDeterministicFindingId(delta.findings[0].id)).toBe(false);
      // The claim itself is kept — only its provenance label is taken away.
      expect(delta.findings[0].title).toBe("model claim");
    },
  );

  it("leaves an ordinary model id untouched", () => {
    expect(parse([modelFinding("f1")]).findings[0].id).toBe("f1");
  });

  it("renames every reference to the finding inside the same delta", () => {
    const delta = parse([modelFinding("f-waves")], {
      forensicEvents: [
        { id: "e1", timestamp: "2026-01-01T00:00:00Z", description: "d", relatedFindingIds: ["f-waves"] },
      ],
      keyQuestions: [{ id: "q1", question: "q?", relatedFindingIds: ["f-waves"] }],
      nextSteps: [{ id: "n1", action: "a", relatedFindingIds: ["f-waves"] }],
    });
    const renamed = delta.findings[0].id;
    expect(delta.forensicEvents?.[0].relatedFindingIds).toEqual([renamed]);
    expect(delta.keyQuestions?.[0].relatedFindingIds).toEqual([renamed]);
    expect(delta.nextSteps?.[0].relatedFindingIds).toEqual([renamed]);
  });

  it("does not collide with an id the model already used for a different finding", () => {
    const delta = parse([modelFinding("f-auto-e5"), modelFinding("f-model-f-auto-e5")]);
    const [a, b] = delta.findings.map((f) => f.id);
    expect(a).not.toBe(b);
    expect(isDeterministicFindingId(a)).toBe(false);
  });

  it("maps a repeated reserved id to one replacement, so the merge still folds them together", () => {
    const delta = parse([modelFinding("f-auto-e5"), modelFinding("f-auto-e5")]);
    expect(delta.findings[0].id).toBe(delta.findings[1].id);
  });
});

describe("what the rename protects", () => {
  it("lets the wave backfill still mint the real f-waves after the model claimed that id", () => {
    const claimed = parse([modelFinding("f-waves")]);
    const state = {
      ...emptyState("c1"),
      findings: claimed.findings.map((f) => finding(f.id, { title: f.title })),
    };
    // Two bursts three weeks apart: the pattern the backfill exists to name.
    const waveEvents = [
      ...[0, 1, 2].map((i) => event(`a${i}`, [], `2026-01-01T00:0${i}:00.000Z`)),
      ...[0, 1, 2].map((i) => event(`b${i}`, [], `2026-01-20T00:0${i}:00.000Z`)),
    ];
    const { pattern } = detectGapsWithWaves(waveEvents);
    expect(pattern).not.toBeNull();

    const out = backfillActivityWaveFinding(state, pattern, "2026-01-21T00:00:00.000Z");
    const waves = out.findings.filter((f) => f.id === "f-waves");
    expect(waves).toHaveLength(1);
    expect(waves[0].title).not.toBe("model claim");
  });

  it("does not carry a renamed model finding across a narrowed window", () => {
    const claimed = parse([modelFinding("f-auto-e9")]);
    const renamed = claimed.findings[0].id;
    const prior = {
      ...emptyState("c1"),
      findings: [finding(renamed)],
      forensicTimeline: [event("e9", [renamed])],
    };
    const next = carryOutOfWindowFindings(
      { ...emptyState("c1"), forensicTimeline: prior.forensicTimeline },
      { prior, inWindowEvents: [], markers: [] },
    );
    expect(next.findings).toEqual([]);
  });

  it("still carries a genuine out-of-window deterministic finding (#751)", () => {
    const genuine = finding("f-gap-e1-e2");
    const prior = {
      ...emptyState("c1"),
      findings: [genuine],
      forensicTimeline: [event("e1", ["f-gap-e1-e2"])],
    };
    const next = carryOutOfWindowFindings(
      { ...emptyState("c1"), forensicTimeline: prior.forensicTimeline },
      { prior, inWindowEvents: [], markers: [] },
    );
    expect(next.findings.map((f) => f.id)).toEqual(["f-gap-e1-e2"]);
    expect(next.forensicTimeline[0].relatedFindingIds).toContain("f-gap-e1-e2");
  });
});
