import { describe, it, expect } from "vitest";
import {
  reconsiderKeyQuestions,
  reconsiderNextSteps,
  textMentionsFindingId,
  FP_RESET_POINTER,
} from "../../src/analysis/fpCascade.js";
import type { InvestigationQuestion, NextStep } from "../../src/analysis/stateTypes.js";

function q(partial: Partial<InvestigationQuestion> & { id: string }): InvestigationQuestion {
  return { question: "?", status: "answered", answer: "a", pointer: "", ...partial };
}
function step(partial: Partial<NextStep> & { id: string }): NextStep {
  return { priority: "high", action: "do", rationale: "", pointer: "", ...partial };
}

describe("textMentionsFindingId", () => {
  it("matches on id boundaries, not substrings", () => {
    expect(textMentionsFindingId("supported by f1 and f2", "f1")).toBe(true);
    expect(textMentionsFindingId("see f12", "f1")).toBe(false);   // f1 is not a boundary match in f12
    expect(textMentionsFindingId("f-auto-e1 covers it", "f-auto-e1")).toBe(true);
    expect(textMentionsFindingId(undefined, "f1")).toBe(false);
  });
});

describe("reconsiderKeyQuestions", () => {
  it("resets a question that structurally depends on a rejected finding, badging stale in FP-route mode", () => {
    const questions = [
      q({ id: "q1", status: "answered", answer: "yes", relatedFindingIds: ["f1", "f2"] }),
      q({ id: "q2", status: "answered", answer: "unrelated", relatedFindingIds: ["f2"] }),
    ];
    const { questions: out, changed } = reconsiderKeyQuestions(questions, {
      survivingFindingIds: new Set(["f2"]), // f1 rejected
      priorFindingIds: ["f1", "f2"],
      staleReSynth: true,
    });
    expect(changed).toBe(true);
    expect(out[0].status).toBe("unknown");
    expect(out[0].answer).toBe("");
    expect(out[0].pointer).toBe(FP_RESET_POINTER);
    expect(out[0].relatedFindingIds).toEqual(["f2"]);   // dead link pruned
    expect(out[0].staleReSynth).toBe(true);
    expect(out[1].status).toBe("answered");             // q2 untouched
    expect(out[1].staleReSynth).toBeUndefined();
  });

  it("resets on a PROSE mention when there is no structured link", () => {
    const { questions: out } = reconsiderKeyQuestions(
      [q({ id: "q1", status: "partial", answer: "backed by f7", pointer: "finding f7", relatedFindingIds: [] })],
      { survivingFindingIds: new Set([]), priorFindingIds: ["f7"], staleReSynth: true },
    );
    expect(out[0].status).toBe("unknown");
    expect(out[0].staleReSynth).toBe(true);
  });

  it("on the authoritative synthesis pass (staleReSynth off) resets WITHOUT a stale badge and clears prior badges", () => {
    const { questions: out } = reconsiderKeyQuestions(
      [
        q({ id: "q1", status: "answered", relatedFindingIds: ["f1"] }),           // will reset, no badge
        q({ id: "q2", status: "answered", relatedFindingIds: ["f2"], staleReSynth: true }), // stays, badge cleared
      ],
      { survivingFindingIds: new Set(["f2"]), priorFindingIds: ["f1", "f2"] },
    );
    expect(out[0].status).toBe("unknown");
    expect(out[0].staleReSynth).toBeUndefined();
    expect(out[1].status).toBe("answered");
    expect(out[1].staleReSynth).toBeUndefined();        // cleared by authoritative pass
    expect("staleReSynth" in out[0]).toBe(false);       // no lingering undefined key
  });

  it("does not reset an already-unknown question, only prunes its dead links", () => {
    const { questions: out, changed } = reconsiderKeyQuestions(
      [q({ id: "q1", status: "unknown", answer: "", relatedFindingIds: ["f1", "f2"] })],
      { survivingFindingIds: new Set(["f2"]), priorFindingIds: ["f1", "f2"], staleReSynth: true },
    );
    expect(out[0].status).toBe("unknown");
    expect(out[0].relatedFindingIds).toEqual(["f2"]);
    expect(changed).toBe(true);
  });

  it("reports no change when nothing depends on a rejected finding", () => {
    const { changed } = reconsiderKeyQuestions(
      [q({ id: "q1", status: "answered", relatedFindingIds: ["f2"] })],
      { survivingFindingIds: new Set(["f2"]), priorFindingIds: ["f2"], staleReSynth: true },
    );
    expect(changed).toBe(false);
  });
});

describe("reconsiderNextSteps", () => {
  it("badges a step that advances a rejected finding (structural or prose) as stale", () => {
    const steps = [
      step({ id: "n1", action: "Confirm f3", relatedFindingIds: ["f3"] }),
      step({ id: "n2", action: "unrelated pivot", pointer: "see finding f5", relatedFindingIds: [] }),
      step({ id: "n3", action: "keep me", relatedFindingIds: ["f9"] }),
    ];
    const { steps: out, changed } = reconsiderNextSteps(steps, {
      removedFindingIds: new Set(["f3", "f5"]),
      staleReSynth: true,
    });
    expect(changed).toBe(true);
    expect(out[0].staleReSynth).toBe(true);   // structural
    expect(out[1].staleReSynth).toBe(true);   // prose mention
    expect(out[2].staleReSynth).toBeUndefined();
  });

  it("clears a stale badge when nothing is rejected", () => {
    const { steps: out, changed } = reconsiderNextSteps(
      [step({ id: "n1", action: "x", staleReSynth: true })],
      { removedFindingIds: new Set() },
    );
    expect(changed).toBe(true);
    expect(out[0].staleReSynth).toBeUndefined();
    expect("staleReSynth" in out[0]).toBe(false);
  });
});
