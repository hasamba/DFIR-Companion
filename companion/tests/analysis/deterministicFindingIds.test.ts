import { describe, expect, it } from "vitest";
import { backfillActivityWaveFinding, detectGapsWithWaves } from "../../src/analysis/activityWaves.js";
import { carryOutOfWindowFindings } from "../../src/analysis/ai/synthesisMerge.js";
import {
  isDeterministicFindingId,
  renameForgedFindingIds,
  type AnalysisDelta,
} from "../../src/analysis/responseSchema.js";
import { mergeDelta } from "../../src/analysis/stateMerge.js";
import { emptyState, type Finding, type ForensicEvent } from "../../src/analysis/stateTypes.js";

/**
 * A deterministic finding id is a PROVENANCE claim (#787).
 *
 * Three passes read `f-auto-*` / `f-gap-*` / `f-waves` as proof that a finding was minted by a
 * backfill and not by a model: `carryOutOfWindowFindings` re-attaches only those across a narrowed
 * window, and each backfill treats one it already sees as its own work being done and skips. But
 * both prompts echo every prior finding id back to the model AND tell it to update by id, so the
 * string alone cannot say who wrote it.
 *
 * The discriminator is the case. An id already in the case is the model doing as it was told; an id
 * that exists nowhere is the model inventing provenance, and only that one is renamed.
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

const delta = (findings: unknown[], over: Record<string, unknown> = {}): AnalysisDelta =>
  ({
    findings,
    iocs: [],
    mitreTechniques: [],
    threadsOpened: [],
    threadsClosed: [],
    timelineNote: "n",
    summary: "s",
    ...over,
  }) as AnalysisDelta;

const modelFinding = (id: string, title = "model claim"): Record<string, unknown> => ({
  id,
  severity: "Critical",
  title,
  description: "d",
  relatedIocs: [],
  mitreTechniques: [],
  status: "open",
});

const ctx = { windowSequence: 0, timestamp: "2026-02-01T00:00:00.000Z", sourceScreenshots: [] };

describe("renameForgedFindingIds", () => {
  it.each(["f-auto-e5", "f-gap-e1-e2", "f-waves"])("renames an invented %s", (id) => {
    const out = renameForgedFindingIds(delta([modelFinding(id)]), new Set());
    expect(out.findings[0].id).not.toBe(id);
    expect(isDeterministicFindingId(out.findings[0].id)).toBe(false);
    // The claim itself is kept — only the borrowed provenance label goes.
    expect(out.findings[0].title).toBe("model claim");
  });

  it("leaves an ordinary model id untouched", () => {
    expect(renameForgedFindingIds(delta([modelFinding("f1")]), new Set()).findings[0].id).toBe("f1");
  });

  it("leaves an id the case already holds untouched — that is an update, not an invention", () => {
    const out = renameForgedFindingIds(delta([modelFinding("f-auto-e5")]), new Set(["f-auto-e5"]));
    expect(out.findings[0].id).toBe("f-auto-e5");
  });

  it("renames every reference to the finding inside the same delta", () => {
    const out = renameForgedFindingIds(
      delta([modelFinding("f-waves")], {
        forensicEvents: [
          { id: "e1", timestamp: "2026-01-01T00:00:00Z", description: "d", relatedFindingIds: ["f-waves"] },
        ],
        keyQuestions: [{ id: "q1", question: "q?", relatedFindingIds: ["f-waves"] }],
        nextSteps: [{ id: "n1", action: "a", relatedFindingIds: ["f-waves"] }],
      }),
      new Set(),
    );
    const renamed = out.findings[0].id;
    expect(out.forensicEvents?.[0].relatedFindingIds).toEqual([renamed]);
    expect(out.keyQuestions?.[0].relatedFindingIds).toEqual([renamed]);
    expect(out.nextSteps?.[0].relatedFindingIds).toEqual([renamed]);
  });

  it("suffixes only on a real clash — another finding in the same delta already owns the name", () => {
    // Reuse is for the name an earlier window gave THIS id. A different finding in the same delta
    // that happens to be called `f-model-f-auto-e5` is not that, so the two must stay separate.
    const out = renameForgedFindingIds(
      delta([modelFinding("f-auto-e5"), modelFinding("f-model-f-auto-e5")]),
      new Set(),
    );
    const ids = out.findings.map((f) => f.id);
    expect(new Set(ids).size).toBe(2);
    expect(ids).toContain("f-model-f-auto-e5-2");
  });

  it("reuses the name an earlier window gave the same invented id, instead of stacking a -2", () => {
    // Window 1 renamed it and the case kept that row. Window 2 repeating the id must UPDATE that
    // row, not append `f-model-f-auto-e5-2` beside it — and again on every window after.
    const out = renameForgedFindingIds(delta([modelFinding("f-auto-e5")]), new Set(["f-model-f-auto-e5"]));
    expect(out.findings[0].id).toBe("f-model-f-auto-e5");
  });

  it("renames the id where a question or next step names it in prose, not only in the link", () => {
    // reconsiderKeyQuestions matches finding ids inside this prose, so a stale one is not cosmetic.
    const out = renameForgedFindingIds(
      delta([modelFinding("f-auto-e5")], {
        keyQuestions: [
          { id: "q1", question: "q?", answer: "see f-auto-e5", pointer: "f-auto-e5", relatedFindingIds: [] },
        ],
        nextSteps: [
          { id: "n1", action: "triage f-auto-e5", rationale: "f-auto-e5 is open", relatedFindingIds: [] },
        ],
      }),
      new Set(),
    );
    expect(out.keyQuestions?.[0].answer).toBe("see f-model-f-auto-e5");
    expect(out.keyQuestions?.[0].pointer).toBe("f-model-f-auto-e5");
    expect(out.nextSteps?.[0].action).toBe("triage f-model-f-auto-e5");
    expect(out.nextSteps?.[0].rationale).toBe("f-model-f-auto-e5 is open");
  });

  it("matches whole ids only, so f-auto-e5 leaves f-auto-e50 alone", () => {
    const out = renameForgedFindingIds(
      delta([modelFinding("f-auto-e5")], {
        nextSteps: [{ id: "n1", action: "f-auto-e50 stays", relatedFindingIds: [] }],
      }),
      new Set(),
    );
    expect(out.nextSteps?.[0].action).toBe("f-auto-e50 stays");
  });

  it("maps a repeated invented id to one replacement, so the merge still folds them together", () => {
    const out = renameForgedFindingIds(
      delta([modelFinding("f-auto-e5"), modelFinding("f-auto-e5")]),
      new Set(),
    );
    expect(out.findings[0].id).toBe(out.findings[1].id);
  });
});

describe("mergeDelta applies the check against the case", () => {
  it("renames an invented deterministic id on its way into the case", () => {
    const merged = mergeDelta(emptyState("c1"), delta([modelFinding("f-auto-e5")]), ctx);
    expect(merged.findings.map((f) => f.id)).toEqual(["f-model-f-auto-e5"]);
  });

  it("updates the real finding in place when the model returns an id the case holds", () => {
    const state = { ...emptyState("c1"), findings: [finding("f-auto-e5", { title: "auto-flagged" })] };
    const merged = mergeDelta(state, delta([modelFinding("f-auto-e5", "refined by the model")]), ctx);
    expect(merged.findings.map((f) => f.id)).toEqual(["f-auto-e5"]);
    expect(merged.findings[0].title).toBe("refined by the model");
  });

  it("honours knownFindingIds, because synthesis merges into an emptied finding list", () => {
    // What replaceConclusions does: the base has no findings, so the case's real ids come via ctx.
    const merged = mergeDelta({ ...emptyState("c1"), findings: [] }, delta([modelFinding("f-auto-e5")]), {
      ...ctx,
      knownFindingIds: new Set(["f-auto-e5"]),
    });
    expect(merged.findings.map((f) => f.id)).toEqual(["f-auto-e5"]);
  });
});

describe("what the rename protects", () => {
  it("lets the wave backfill still mint the real f-waves after the model invented that id", () => {
    const claimed = renameForgedFindingIds(delta([modelFinding("f-waves")]), new Set());
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
    const claimed = renameForgedFindingIds(delta([modelFinding("f-auto-e9")]), new Set());
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
    const prior = {
      ...emptyState("c1"),
      findings: [finding("f-gap-e1-e2")],
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
