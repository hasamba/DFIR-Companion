import { describe, expect, it } from "vitest";
import { backfillActivityWaveFinding, detectGapsWithWaves } from "../../src/analysis/activityWaves.js";
import { carryOutOfWindowFindings } from "../../src/analysis/ai/synthesisMerge.js";
import { BACKFILLS } from "../helpers/deterministicBackfills.js";
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

  it("stops the model minting into the rename namespace, which is what makes reuse provable", () => {
    // Reuse folds a repeated invention onto the row an earlier window created. That is only sound
    // while `f-model-…` can ONLY come from a rename — so a model inventing one is renamed too.
    // Without this, a planted `f-model-f-auto-e5` would absorb a later forged `f-auto-e5`.
    const out = renameForgedFindingIds(delta([modelFinding("f-model-f-auto-e5")]), new Set());
    expect(out.findings[0].id).toBe("f-model-f-model-f-auto-e5");
  });

  it("keeps two inventions apart without arbitrating, because prefixing is injective", () => {
    const out = renameForgedFindingIds(
      delta([modelFinding("f-auto-e5"), modelFinding("f-model-f-auto-e5")]),
      new Set(),
    );
    expect(out.findings.map((f) => f.id)).toEqual(["f-model-f-auto-e5", "f-model-f-model-f-auto-e5"]);
  });

  it("gives a repeated invention the same id every window, so it updates and never appends", () => {
    // The failure this pins: a name chosen by arbitrating a clash means nothing to the next window,
    // so replaying one delta drifts `-2`, `-3`, … and stacks a duplicate finding each time.
    const input = delta([modelFinding("f-auto-e5")]);
    const first = renameForgedFindingIds(input, new Set()).findings.map((f) => f.id);
    const second = renameForgedFindingIds(input, new Set(first)).findings.map((f) => f.id);
    const third = renameForgedFindingIds(input, new Set([...first, ...second])).findings.map((f) => f.id);
    expect(first).toEqual(["f-model-f-auto-e5"]);
    expect(second).toEqual(first);
    expect(third).toEqual(first);
  });

  it("adds no new row on any replay, even when one delta names the same finding two ways", () => {
    // Adversarial shape: `f-auto-e5` and the name it gets renamed to, in one delta. From window two
    // they both denote the row window one created, so they fold onto it. What must never happen is
    // a THIRD name appearing — that is the duplicate accumulation, one indirection later.
    const input = delta([modelFinding("f-auto-e5"), modelFinding("f-model-f-auto-e5")]);
    const first = new Set(renameForgedFindingIds(input, new Set()).findings.map((f) => f.id));
    let known = first;
    for (let window = 0; window < 3; window++) {
      const ids = renameForgedFindingIds(input, known).findings.map((f) => f.id);
      expect(ids.filter((id) => !first.has(id))).toEqual([]);
      known = new Set([...known, ...ids]);
    }
    expect(known).toEqual(first);
  });

  it("lets the model update a renamed finding by the id the prompt now shows it", () => {
    // buildFindingsEcho shows `[f-model-f-auto-e5] title`, and the model is told to update by id.
    // The namespace is closed to MINTING, not to updating a row the case already holds.
    const out = renameForgedFindingIds(
      delta([modelFinding("f-model-f-auto-e5")]),
      new Set(["f-model-f-auto-e5"]),
    );
    expect(out.findings[0].id).toBe("f-model-f-auto-e5");
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

  it("rewrites the id in the kill-chain narrative and the uncertainty ledger too", () => {
    // The attackerPath prompt asks for "citing finding ids and times", and stateMerge persists the
    // narrative verbatim — so the reserved id would survive there after the link had moved.
    const out = renameForgedFindingIds(
      delta([modelFinding("f-auto-e5")], {
        attackerPath: "entry via f-auto-e5 then lateral",
        narrativeTimeline: "f-auto-e5 opened the door",
        uncertainties: [{ topic: "t", basis: "rests on f-auto-e5", gap: "confirm f-auto-e5" }],
        summary: "f-auto-e5 is the lead",
        timelineNote: "raised f-auto-e5",
        threadsOpened: [{ id: "t1", description: "Investigate f-auto-e5" }],
      }),
      new Set(),
    );
    expect(out.attackerPath).toBe("entry via f-model-f-auto-e5 then lateral");
    expect(out.narrativeTimeline).toBe("f-model-f-auto-e5 opened the door");
    // `summary` is persisted as lastSummary and feeds the report and the next prompt;
    // `timelineNote` becomes a timeline row. Both outlive the id if left alone.
    expect(out.summary).toBe("f-model-f-auto-e5 is the lead");
    expect(out.timelineNote).toBe("raised f-model-f-auto-e5");
    // A thread outlives everything else here — it sits in openThreads until an analyst closes it.
    expect(out.threadsOpened[0].description).toBe("Investigate f-model-f-auto-e5");
    expect(out.uncertainties?.[0].basis).toBe("rests on f-model-f-auto-e5");
    expect(out.uncertainties?.[0].gap).toBe("confirm f-model-f-auto-e5");
  });

  it("leaves prose alone when two ids differ only by case, rather than guessing which one it means", () => {
    // mergeDelta compares ids exactly, so `f-auto-E5` and `f-auto-e5` are two findings. A bare
    // case-insensitive rewrite would send prose for both to whichever mapped last.
    const out = renameForgedFindingIds(
      delta([modelFinding("f-auto-e5"), modelFinding("f-auto-E5")], {
        attackerPath: "exact f-auto-e5 and exact f-auto-E5 and ambiguous F-AUTO-E5",
      }),
      new Set(),
    );
    expect(out.findings.map((f) => f.id)).toEqual(["f-model-f-auto-e5", "f-model-f-auto-E5"]);
    // Both exact spellings still move; only the third, which matches neither exactly, is untouched.
    expect(out.attackerPath).toBe(
      "exact f-model-f-auto-e5 and exact f-model-f-auto-E5 and ambiguous F-AUTO-E5",
    );
  });

  it("rewrites the id where the finding's own title or description names it", () => {
    // Left behind, the row cites `f-waves` while wearing another id — and the backfill it no longer
    // blocks then mints `f-waves` for the real wave finding, so the text cites somebody else.
    const out = renameForgedFindingIds(
      delta([
        {
          ...modelFinding("f-waves"),
          title: "f-waves: staged in bursts",
          description: "see f-waves",
          confidenceReason: "derived from f-waves",
        },
        { ...modelFinding("f1"), description: "corroborates f-waves" },
      ]),
      new Set(),
    );
    expect(out.findings[0].id).toBe("f-model-f-waves");
    // The TITLE is deliberately left alone: a finding false-positive marker stores a title keyword
    // and applyFalsePositive matches it by substring, so editing the title would silently undo an
    // analyst's rejection of this finding.
    expect(out.findings[0].title).toBe("f-waves: staged in bursts");
    expect(out.findings[0].description).toBe("see f-model-f-waves");
    expect(out.findings[0].confidenceReason).toBe("derived from f-model-f-waves");
    // An untouched finding citing a renamed one is swept as well.
    expect(out.findings[1].description).toBe("corroborates f-model-f-waves");
  });

  it("rewrites the executive summary, which is persisted and feeds the next prompt", () => {
    const out = renameForgedFindingIds(
      delta([modelFinding("f-auto-e5")], { summary: "the case turns on f-auto-e5" }),
      new Set(),
    );
    expect(out.summary).toBe("the case turns on f-model-f-auto-e5");
  });

  it("does not redirect a citation of a finding the case already holds under a different case", () => {
    // `f-auto-E5` is an existing finding — not renamed, and it owns its own citations. Judging
    // ambiguity from the renamed ids alone would call `f-auto-e5` unique and steal them.
    const out = renameForgedFindingIds(
      delta([modelFinding("f-auto-e5")], { attackerPath: "entry via f-auto-E5, then f-auto-e5" }),
      new Set(["f-auto-E5"]),
    );
    expect(out.findings.map((f) => f.id)).toEqual(["f-model-f-auto-e5"]);
    expect(out.attackerPath).toBe("entry via f-auto-E5, then f-model-f-auto-e5");
  });

  it("rewrites a prose citation whatever its case, because textMentionsFindingId reads it that way", () => {
    const out = renameForgedFindingIds(
      delta([modelFinding("f-auto-e5")], { attackerPath: "see F-AUTO-E5 for the entry point" }),
      new Set(),
    );
    expect(out.attackerPath).toBe("see f-model-f-auto-e5 for the entry point");
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

/**
 * #758: a backfill pass must REGISTER the id shape it mints, and nothing mechanical said so.
 *
 * The register is `responseSchema.ts`'s prefix list, and `isDeterministicFindingId` is the only
 * reader that matters here: `carryOutOfWindowFindings` re-attaches a prior finding across a
 * narrowed window ONLY when that predicate accepts its id. A pass whose id the predicate does not
 * know is therefore not carried — so the first time an analyst narrows the scope, that pass's
 * findings are overwritten in SQLite, and widening the window again does not bring them back. That
 * is the #751 data loss, and the whole suite stays green while it happens.
 *
 * #787 removed the drift BETWEEN the three existing sites by giving them one shared list. It could
 * not do anything about the fourth pass nobody has written yet, which is what this covers: each
 * backfill is RUN, and the id it really mints is put through the predicate and then through the
 * carry. A new pass added to this table without a registered prefix fails on the assertion rather
 * than on a case that lost findings months later.
 *
 * The pair of assertions is deliberate. The predicate alone would pass for a pass that mints a
 * registered id but never back-links its finding to an event — `supportingEventIds` drops an
 * unlinked finding as "nothing proves it is outside the window", so it is silently not carried
 * either. Only running the carry catches that, and running it needs the pass to be in the table.
 *
 * Which is why the table's own completeness is not left to whoever adds the next pass: the
 * architecture gate loads every module under src/ that exports a backfill and fails unless this
 * table runs that very function — by reference, so a stub named after a pass cannot stand in for
 * it. The literal scan there cannot stand in for this either — it reads an unlinked
 * pass's id as perfectly well-formed, because it is.
 */
describe("every deterministic backfill registers the id it mints (#758)", () => {
  it.each(BACKFILLS)("$name mints an id the register knows", ({ run }) => {
    const minted = run().findings;
    // A pass that produced nothing would pass every assertion below without testing anything.
    expect(minted.length, "the fixture no longer triggers this pass").toBeGreaterThan(0);
    for (const f of minted) {
      expect(
        isDeterministicFindingId(f.id),
        `"${f.id}" is not in responseSchema.ts's prefix list, so carryOutOfWindowFindings will ` +
          "drop it the first time an analyst narrows the scope (#751). Register the prefix there",
      ).toBe(true);
    }
  });

  it.each(BACKFILLS)("$name's finding survives a narrowed window", ({ name, run }) => {
    const prior = run();
    // Every event out of scope: the narrowest window there is, and the one #751 was filed about.
    const next = carryOutOfWindowFindings(
      { ...emptyState("c1"), forensicTimeline: prior.forensicTimeline },
      { prior, inWindowEvents: [], markers: [] },
    );
    expect(
      next.findings.map((f) => f.id).sort(),
      `${name}'s findings were deleted by a narrowed window and will not return when it widens`,
    ).toEqual(prior.findings.map((f) => f.id).sort());
  });
});
