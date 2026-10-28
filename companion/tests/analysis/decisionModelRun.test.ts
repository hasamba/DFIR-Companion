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

describe("the failure the analyst sees is the real one", () => {
  it("keeps the provider's error when a split's other half is stopped by the caller's halt check", async () => {
    // The route's beforeSend throws its OWN error once the review is halted. That stand-in must never
    // replace the model-named failure that caused the halt.
    const deps: JevGraderDeps = {
      mask: (t) => t,
      ask: async (_state, questions, halted) => {
        const rows = Object.keys(questions).filter((q) => !q.endsWith("_tool"));
        if (rows.length > 1) throw new Error('HTTP 400: {"detail":{"error_type":"max_tokens_exceeded"}}');
        if (rows[0] === "R001") throw new Error("Decision model vendor/x: HTTP 401 bad key");
        await tick();
        if (halted()) throw new Error("review halted after an earlier batch failed");
        return { model: "m", answers: answersFor(questions), usage: { inputTokens: 1, outputTokens: 1 } };
      },
    };
    await expect(gradeEvents(deps, [ev("a"), ev("b")], { batchSize: 40 })).rejects.toThrow(
      /HTTP 401 bad key/,
    );
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

describe("a halted review still reports what it already spent (#2235)", () => {
  interface Spend {
    model: string;
    usage: { inputTokens: number; outputTokens: number; costUSD?: number };
    requests: number;
  }
  const billed = { inputTokens: 1, outputTokens: 1, costUSD: 0.01 };
  const tooLarge = (): Error => new Error('HTTP 400: {"detail":{"error_type":"max_tokens_exceeded"}}');

  it("reports the spend of batches that succeeded when a later batch halts the review", async () => {
    const events = Array.from({ length: 12 }, (_, i) => ev(`e${i}`));
    const providerErr = new Error("HTTP 400: question type not supported");
    let calls = 0;
    const deps: JevGraderDeps = {
      mask: (t) => t,
      ask: async (_state, questions) => {
        const mine = ++calls;
        await tick();
        if (mine === 1) throw providerErr;
        await tick();
        return { model: "m", answers: answersFor(questions), usage: billed };
      },
    };
    const spends: Spend[] = [];
    await expect(
      gradeEvents(deps, events, { batchSize: 1, onSpendOnFailure: (s) => spends.push(s) }),
    ).rejects.toBe(providerErr);
    expect(spends).toHaveLength(1);
    const [s] = spends;
    expect(s.requests).toBeGreaterThan(0);
    expect(s.requests).toBe(calls - 1);
    expect(s.model).toBe("m");
    expect(s.usage.inputTokens).toBe(calls - 1);
    expect(s.usage.outputTokens).toBe(calls - 1);
    expect(s.usage.costUSD).toBeCloseTo(0.01 * (calls - 1));
  });

  it("counts the half of a size split that succeeded", async () => {
    const authErr = new Error("Decision model vendor/x: HTTP 401 bad key");
    const deps: JevGraderDeps = {
      mask: (t) => t,
      ask: async (_state, questions) => {
        const rows = Object.keys(questions).filter((q) => !q.endsWith("_tool"));
        if (rows.length > 1) throw tooLarge();
        if (rows[0] === "R001") {
          await tick();
          throw authErr;
        }
        return {
          model: "m",
          answers: answersFor(questions),
          usage: { inputTokens: 7, outputTokens: 3, costUSD: 0.02 },
        };
      },
    };
    const spends: Spend[] = [];
    await expect(
      gradeEvents(deps, [ev("a"), ev("b")], { batchSize: 40, onSpendOnFailure: (s) => spends.push(s) }),
    ).rejects.toBe(authErr);
    expect(spends).toEqual([
      { model: "m", usage: { inputTokens: 7, outputTokens: 3, costUSD: 0.02 }, requests: 1 },
    ]);
  });

  it("counts a request that finishes after the halt", async () => {
    const providerErr = new Error("HTTP 529 overloaded");
    let calls = 0;
    const deps: JevGraderDeps = {
      mask: (t) => t,
      ask: async (_state, questions) => {
        const mine = ++calls;
        if (mine === 1) {
          await tick();
          throw providerErr;
        }
        // Still in flight long after the first request has halted the review.
        await new Promise((resolve) => setTimeout(resolve, 40));
        return { model: "slow", answers: answersFor(questions), usage: { inputTokens: 5, outputTokens: 5 } };
      },
    };
    const spends: Spend[] = [];
    await expect(
      gradeEvents(deps, [ev("a"), ev("b")], { batchSize: 1, onSpendOnFailure: (s) => spends.push(s) }),
    ).rejects.toBe(providerErr);
    expect(spends).toEqual([{ model: "slow", usage: { inputTokens: 5, outputTokens: 5 }, requests: 1 }]);
  });

  it("does not call onSpendOnFailure when nothing was billed", async () => {
    const deps: JevGraderDeps = {
      mask: (t) => t,
      ask: async () => {
        await tick();
        throw new Error("HTTP 401 bad key");
      },
    };
    const spends: Spend[] = [];
    await expect(
      gradeEvents(deps, [ev("a"), ev("b"), ev("c")], {
        batchSize: 1,
        onSpendOnFailure: (s) => spends.push(s),
      }),
    ).rejects.toThrow(/bad key/);
    expect(spends).toEqual([]);
  });
});

describe("the review's headline model is the one that billed the most (#2240)", () => {
  const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));
  const tooLarge = (): Error => new Error('HTTP 400: {"detail":{"error_type":"max_tokens_exceeded"}}');
  const reply = (
    model: string,
    questions: Readonly<Record<string, JevQuestion>>,
    tokens: number,
  ): {
    model: string;
    answers: Record<string, JevAnswer>;
    usage: { inputTokens: number; outputTokens: number };
  } => ({
    model,
    answers: answersFor(questions),
    usage: { inputTokens: tokens, outputTokens: tokens },
  });
  const flush = (): Promise<void> => new Promise((resolve) => setImmediate(resolve));

  // Request N replies as models[N] with tokens[N], but only once the test opens its gate. Every
  // request must be in flight before any gate opens, so a serialized pool fails here, loudly.
  // Gates then open one at a time in releaseOrder, so the finish order is chosen, not slept for.
  const gatedRun = async (models: string[], tokens: number[], releaseOrder: number[]): Promise<string> => {
    const opens: Array<() => void> = [];
    const gates = models.map(() => new Promise<void>((resolve) => opens.push(resolve)));
    let calls = 0;
    const deps: JevGraderDeps = {
      mask: (t) => t,
      ask: async (_state, questions) => {
        const mine = calls++;
        await gates[mine];
        return reply(models[mine], questions, tokens[mine]);
      },
    };
    const review = gradeEvents(
      deps,
      models.map((_, i) => ev(`e${i}`)),
      { batchSize: 1 },
    );
    await flush();
    expect(calls).toBe(models.length);
    for (const i of releaseOrder) {
      opens[i]();
      await flush();
    }
    return (await review).model;
  };
  const forward = (n: number): number[] => Array.from({ length: n }, (_, i) => i);
  const reverse = (n: number): number[] => forward(n).reverse();

  it("names the majority model, not the batch that resolved last", async () => {
    const models = ["big", "small"];
    const tokens = [50, 1];
    expect(await gatedRun(models, tokens, forward(2))).toBe("big");
    expect(await gatedRun(models, tokens, reverse(2))).toBe("big");
  });

  it("names the majority model after a size split, with the exact summed usage", async () => {
    const deps: JevGraderDeps = {
      mask: (t) => t,
      ask: async (_state, questions) => {
        const rows = Object.keys(questions).filter((q) => !q.endsWith("_tool"));
        if (rows.length > 1) throw tooLarge();
        if (rows[0] === "R000") {
          return { ...reply("big", questions, 0), usage: { inputTokens: 100, outputTokens: 50 } };
        }
        await sleep(30);
        return reply("small", questions, 1);
      },
    };
    const r = await gradeEvents(deps, [ev("a"), ev("b")], { batchSize: 40 });
    expect(r.model).toBe("big");
    expect(r.usage).toEqual({ inputTokens: 101, outputTokens: 51 });
    const byId = Object.fromEntries(r.rows.map((row) => [row.id, row.model]));
    expect(byId).toEqual({ a: "big", b: "small" });
  });

  it("uses the same rule when the review fails part way", async () => {
    const authErr = new Error("Decision model vendor/x: HTTP 401 bad key");
    let calls = 0;
    const deps: JevGraderDeps = {
      mask: (t) => t,
      ask: async (_state, questions) => {
        const mine = ++calls;
        if (mine === 1) return reply("big", questions, 20);
        if (mine === 2) {
          await sleep(30);
          return reply("small", questions, 1);
        }
        await sleep(5);
        throw authErr;
      },
    };
    const spends: Array<{ model: string; requests: number }> = [];
    await expect(
      gradeEvents(deps, [ev("a"), ev("b"), ev("c")], {
        batchSize: 1,
        onSpendOnFailure: (s) => spends.push(s),
      }),
    ).rejects.toBe(authErr);
    expect(spends).toHaveLength(1);
    expect(spends[0].model).toBe("big");
    expect(spends[0].requests).toBe(2);
  });

  it("breaks a token tie by request count", async () => {
    const models = ["one-request", "two-requests", "two-requests"];
    const tokens = [2, 1, 1];
    expect(await gatedRun(models, tokens, forward(3))).toBe("two-requests");
    expect(await gatedRun(models, tokens, reverse(3))).toBe("two-requests");
  });

  it("breaks a full tie by model id, whatever order the requests finish in", async () => {
    const models = ["x", "y"];
    const tokens = [3, 3];
    expect(await gatedRun(models, tokens, forward(2))).toBe("x");
    expect(await gatedRun(models, tokens, reverse(2))).toBe("x");
  });

  it("returns an empty model when nothing was billed, so the caller's fallback applies", async () => {
    const deps: JevGraderDeps = {
      mask: (t) => t,
      ask: async () => {
        throw new Error("unreachable");
      },
    };
    const r = await gradeEvents(deps, [], { batchSize: 1 });
    expect(r.model).toBe("");
  });
});
