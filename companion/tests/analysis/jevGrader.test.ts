import { describe, it, expect } from "vitest";
import {
  JEV_REVIEW_DEFAULT_ROWS,
  buildBatchQuestions,
  gradeEvents,
  renderRowForJev,
  type JevGraderDeps,
} from "../../src/analysis/ai/jev/jevGrader.js";
import type { JevAnswer, JevBatchResult } from "../../src/analysis/ai/jev/jevClient.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

function ev(id: string, over: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp: "2026-01-02T03:04:05.000Z",
    description: `desc ${id}`,
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...over,
  };
}

/** A stub Jev that scores row N with the number the test supplies, and never touches the network. */
function stubAsk(scores: Record<string, number>, tooling: Record<string, number> = {}): JevGraderDeps {
  return {
    mask: (t) => t,
    ask: async (_state, questions) => {
      const answers: Record<string, JevAnswer> = {};
      for (const qid of Object.keys(questions)) {
        if (qid.endsWith("_tool")) {
          answers[qid] = { type: "noul", noul: tooling[qid.replace(/_tool$/, "")] ?? 0 };
        } else {
          const s = scores[qid] ?? 0;
          answers[qid] = {
            type: "score",
            score: s,
            legend: { "0": "Info", "1": "Low", "2": "Medium", "3": "High", "4": "Critical" },
            probabilities: { "0": 1 },
            confidence: 0.5,
          };
        }
      }
      const result: JevBatchResult = {
        model: "typesafe/jev-1.13-test",
        answers,
        usage: { inputTokens: 10, outputTokens: 2, costUSD: 0.0001 },
      };
      return result;
    },
  };
}

describe("renderRowForJev", () => {
  it("masks every field it renders, not just the description", () => {
    const e = ev("a", {
      description: "ran SECRETHOST tool",
      path: "C:\\SECRETHOST\\x.exe",
      commandLine: "x.exe --host SECRETHOST",
      message: "context SECRETHOST here",
    });
    const out = renderRowForJev(e, (t) => t.replaceAll("SECRETHOST", "ANON_HOST_1"));
    expect(out).not.toContain("SECRETHOST");
    expect(out).toContain("ANON_HOST_1");
  });

  it("caps a huge message so one row cannot blow the batch budget", () => {
    const out = renderRowForJev(ev("a", { message: "x".repeat(50_000) }), (t) => t);
    expect(out.length).toBeLessThanOrEqual(2_000);
  });
});

describe("buildBatchQuestions", () => {
  it("asks a grade and a tooling question for every row", () => {
    const q = buildBatchQuestions(["R000", "R001"]);
    expect(Object.keys(q).sort()).toEqual(["R000", "R000_tool", "R001", "R001_tool"]);
    expect(q.R000.type).toBe("score");
    expect(q.R000_tool.type).toBe("noul");
  });

  it("uses the five case severities, in order, as the score levels", () => {
    const q = buildBatchQuestions(["R000"]);
    const crit = q.R000.type === "score" ? q.R000.criteria : [];
    expect(crit).toHaveLength(5);
    expect(crit[0]).toMatch(/^Info\b/);
    expect(crit[4]).toMatch(/^Critical\b/);
  });
});

describe("gradeEvents", () => {
  it("ranks rows by grade, highest first, and maps the score onto a severity", async () => {
    const events = [ev("low"), ev("high"), ev("mid")];
    const deps = stubAsk({ R000: 0.2, R001: 3.4, R002: 2.0 });
    const r = await gradeEvents(deps, events, { batchSize: 10 });
    expect(r.rows.map((x) => x.id)).toEqual(["high", "mid", "low"]);
    expect(r.rows[0].grade).toBe("High");
    expect(r.rows[1].grade).toBe("Medium");
    expect(r.rows[2].grade).toBe("Info");
  });

  it("carries the tooling probability through so the panel can filter on it", async () => {
    const events = [ev("a")];
    const r = await gradeEvents(stubAsk({ R000: 2.5 }, { R000: 0.91 }), events, { batchSize: 10 });
    expect(r.rows[0].tooling).toBeCloseTo(0.91);
  });

  it("splits into batches and sums usage across every call", async () => {
    const events = [ev("a"), ev("b"), ev("c"), ev("d"), ev("e")];
    const r = await gradeEvents(stubAsk({}), events, { batchSize: 2 });
    expect(r.rows).toHaveLength(5);
    // 5 rows at 2 per batch = 3 calls, each reporting 10 input tokens.
    expect(r.usage.inputTokens).toBe(30);
    expect(r.usage.costUSD).toBeCloseTo(0.0003);
  });

  it("promotes nothing and mutates no input event", async () => {
    const events = [ev("a")];
    const before = JSON.parse(JSON.stringify(events));
    const r = await gradeEvents(stubAsk({ R000: 4 }), events, { batchSize: 10 });
    expect(events).toEqual(before);
    expect(events[0].severity).toBe("Info");
    expect(events[0].promotedAt).toBeUndefined();
    expect(r).not.toHaveProperty("promoted");
  });

  it("reports how many it graded and says nothing about coverage", async () => {
    // Coverage is the route's to state: only the route can tell a row the cap dropped from a row
    // that was already analyzed, and a flag that cannot tell them apart reported the wrong cause.
    const events = [ev("a"), ev("b")];
    const r = await gradeEvents(stubAsk({}), events, { batchSize: 10 });
    expect(r.usedEvents).toBe(2);
    expect(r).not.toHaveProperty("truncated");
    expect(r).not.toHaveProperty("eventCount");
  });

  it("caps the rows it will read", () => {
    expect(JEV_REVIEW_DEFAULT_ROWS).toBeGreaterThan(0);
    expect(JEV_REVIEW_DEFAULT_ROWS).toBeLessThanOrEqual(20_000);
  });

  it("fails the whole review when a batch fails, rather than silently returning a slice", async () => {
    const deps: JevGraderDeps = {
      mask: (t) => t,
      ask: async () => {
        throw new Error("529 overloaded");
      },
    };
    await expect(gradeEvents(deps, [ev("a")], { batchSize: 10 })).rejects.toThrow(/529/);
  });

  it("keeps every row when batches finish out of order", async () => {
    // Batches run concurrently now. If results were pushed in completion order rather than placed
    // by batch index, a slow first batch would scramble or drop rows without failing anything.
    const events = Array.from({ length: 12 }, (_, i) => ev(`e${i}`));
    let call = 0;
    const deps: JevGraderDeps = {
      mask: (t) => t,
      ask: async (_state, questions) => {
        const mine = call++;
        // Reverse the finishing order: the first batch issued completes last.
        await new Promise((r) => setTimeout(r, (5 - mine) * 4));
        const answers: Record<string, JevAnswer> = {};
        for (const qid of Object.keys(questions)) {
          answers[qid] = qid.endsWith("_tool")
            ? { type: "noul", noul: 0 }
            : { type: "score", score: mine, legend: {}, probabilities: {}, confidence: 0.5 };
        }
        return { model: "m", answers, usage: { inputTokens: 1, outputTokens: 1 } };
      },
    };
    const r = await gradeEvents(deps, events, { batchSize: 3 });
    expect(r.rows).toHaveLength(12);
    expect(new Set(r.rows.map((x) => x.id)).size).toBe(12);
    expect(r.usage.inputTokens).toBe(4);
    // Still ranked highest-grade first regardless of who finished when.
    expect(r.rows.map((x) => x.score)).toEqual([...r.rows.map((x) => x.score)].sort((a, b) => b - a));
  });

  it("refuses a batch size that is not a positive number", async () => {
    // NaN here used to produce one empty batch: nothing graded, no error, a successful-looking run.
    for (const bad of [Number.NaN, 0, -5, Number.POSITIVE_INFINITY]) {
      await expect(gradeEvents(stubAsk({}), [ev("a")], { batchSize: bad })).rejects.toThrow(/batch size/i);
    }
  });
});
