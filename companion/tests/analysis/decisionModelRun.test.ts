import { describe, it, expect } from "vitest";
import { gradeEvents, type JevGraderDeps } from "../../src/analysis/ai/jev/jevGrader.js";
import type { JevAnswer, JevQuestion } from "../../src/analysis/ai/jev/jevClient.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

/**
 * #2224: any OpenRouter decision model can now grade a review, so a model that rejects a question
 * must STOP the run — no more billable batches after the first failure — and every graded row must
 * name the model that actually answered for it, even when batches came back under different ids.
 */

function ev(id: string): ForensicEvent {
  return {
    id,
    timestamp: "2026-01-02T03:04:05.000Z",
    description: `desc ${id}`,
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
  };
}

function answersFor(questions: Readonly<Record<string, JevQuestion>>): Record<string, JevAnswer> {
  const answers: Record<string, JevAnswer> = {};
  for (const qid of Object.keys(questions)) {
    answers[qid] = qid.endsWith("_tool")
      ? { type: "noul", noul: 0 }
      : { type: "score", score: 2, legend: {}, probabilities: {}, confidence: 0.5 };
  }
  return answers;
}

const tick = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 5));

describe("a decision-model review stops on the first failure", () => {
  it("sends no new batch after one fails, and rejects only once no request is in flight", async () => {
    const events = Array.from({ length: 12 }, (_, i) => ev(`e${i}`));
    let calls = 0;
    let inFlight = 0;
    const deps: JevGraderDeps = {
      mask: (t) => t,
      ask: async (_state, questions) => {
        const mine = ++calls;
        inFlight += 1;
        try {
          await tick();
          if (mine === 1) throw new Error("HTTP 400: question type not supported");
          await tick();
          return { model: "m", answers: answersFor(questions), usage: { inputTokens: 1, outputTokens: 1 } };
        } finally {
          inFlight -= 1;
        }
      },
    };

    let inFlightAtReject = -1;
    await expect(
      gradeEvents(deps, events, { batchSize: 1 }).catch((err: unknown) => {
        inFlightAtReject = inFlight;
        throw err;
      }),
    ).rejects.toThrow(/not supported/);
    // Four workers start one batch each; none takes another once the first has failed.
    expect(calls).toBeLessThanOrEqual(4);
    expect(inFlightAtReject).toBe(0);
  });
});

describe("each graded row names the model that answered for it", () => {
  it("keeps per-batch model ids instead of stamping the last one on every row", async () => {
    const ids = ["typesafe/jev-1.14", "perplexity/pplx-decider-v1.2"];
    let n = 0;
    const deps: JevGraderDeps = {
      mask: (t) => t,
      ask: async (_state, questions) => {
        const model = ids[n++ % 2];
        await tick();
        return { model, answers: answersFor(questions), usage: { inputTokens: 1, outputTokens: 1 } };
      },
    };
    const r = await gradeEvents(deps, [ev("a"), ev("b")], { batchSize: 1 });
    const models = new Set(r.rows.map((row) => row.model));
    expect(models).toEqual(new Set(ids));
  });

  it("keeps each half's model when a size refusal split the batch", async () => {
    const deps: JevGraderDeps = {
      mask: (t) => t,
      ask: async (_state, questions) => {
        const rows = Object.keys(questions).filter((q) => !q.endsWith("_tool"));
        if (rows.length > 1) throw new Error('HTTP 400: {"detail":{"error_type":"max_tokens_exceeded"}}');
        const model = rows[0] === "R000" ? "model-first-half" : "model-second-half";
        return { model, answers: answersFor(questions), usage: { inputTokens: 1, outputTokens: 1 } };
      },
    };
    const r = await gradeEvents(deps, [ev("a"), ev("b")], { batchSize: 40 });
    const byId = Object.fromEntries(r.rows.map((row) => [row.id, row.model]));
    expect(byId).toEqual({ a: "model-first-half", b: "model-second-half" });
  });
});
