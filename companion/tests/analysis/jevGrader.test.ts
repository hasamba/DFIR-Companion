import { describe, it, expect } from "vitest";
import {
  JEV_REVIEW_DEFAULT_ROWS,
  planBatches,
  buildBatchQuestions,
  gradeEvents,
  renderRowForJev,
  renderRowForToolingQuestion,
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

/**
 * The two views (#1554).
 *
 * The panel HIDES every row the tooling question scores above 0.5. The Velociraptor importer writes
 * the collector's name into the description of essentially every row it imports, and renderRowForJev
 * used to append `artifact=` on top — so the cue the tooling criteria describe was present on rows
 * that had nothing to do with the investigator's kit, and real evidence went behind the filter.
 *
 * These tests pin the MECHANISM: what each question is handed, not what a model then says about it.
 */
describe("renderRowForToolingQuestion", () => {
  const sigma = (over = {}) =>
    ev("a", {
      description: "Velociraptor [Windows.Sigma.Base] Sigma: Encoded PowerShell - Computer: ws-01",
      artifactName: "Windows.Sigma.Base",
      ...over,
    });

  it("drops the collector prefix and the artifact field from the `Velociraptor [X] …` shape", () => {
    const out = renderRowForToolingQuestion(sigma(), (t) => t);
    expect(out).not.toContain("Velociraptor");
    expect(out).not.toContain("Windows.Sigma.Base");
    expect(out).not.toContain("artifact=");
    expect(out).toContain("Sigma: Encoded PowerShell");
  });

  it("drops the collector prefix from the bare `[X] …` shape too", () => {
    const e = sigma({
      description: "[Windows.System.Pslist] Process svchost.exe started",
    });
    const out = renderRowForToolingQuestion(e, (t) => t);
    expect(out).not.toContain("Windows.System.Pslist");
    expect(out).not.toContain("[");
    expect(out).toContain("Process svchost.exe started");
  });

  it("leaves a description that is NOTHING but the prefix alone, rather than blanking the row", () => {
    const out = renderRowForToolingQuestion(
      sigma({ description: "Velociraptor [Windows.Sigma.Base]" }),
      (t) => t,
    );
    expect(out).toContain("Velociraptor [Windows.Sigma.Base]");
  });

  it("still reads as tooling when the row's SUBJECT really is a detection rule file", () => {
    // The 3-of-3 case: strip the prefix and the rule file is still right there in the text.
    const e = ev("r", {
      description: "Velociraptor [Windows.Detection.Yara.NTFS] YARA: pypykatz_cred_dump_lsass_access.yml",
      artifactName: "Windows.Detection.Yara.NTFS",
      path: "C:\\Program Files\\Velociraptor\\rules\\pypykatz_cred_dump_lsass_access.yml",
    });
    const out = renderRowForToolingQuestion(e, (t) => t);
    expect(out).toContain("pypykatz_cred_dump_lsass_access.yml");
    expect(out).toContain("Velociraptor\\rules");
  });

  it("masks every field it renders — a stripped view is not an unmasked view", () => {
    const e = sigma({
      description: "Velociraptor [Windows.Sigma.Base] ran SECRETHOST tool",
      path: "C:\\SECRETHOST\\x.exe",
      commandLine: "x.exe --host SECRETHOST",
      message: "context SECRETHOST here",
    });
    const out = renderRowForToolingQuestion(e, (t) => t.replaceAll("SECRETHOST", "ANON_HOST_1"));
    expect(out).not.toContain("SECRETHOST");
    expect(out).toContain("ANON_HOST_1");
  });

  it("caps a huge message, exactly as the grade view does", () => {
    const out = renderRowForToolingQuestion(sigma({ message: "x".repeat(50_000) }), (t) => t);
    expect(out.length).toBeLessThanOrEqual(2_000);
  });

  it("changes NOTHING for the grade view — severity still gets the artifact name", () => {
    const out = renderRowForJev(sigma(), (t) => t);
    expect(out).toContain("Velociraptor [Windows.Sigma.Base]");
    expect(out).toContain("artifact=Windows.Sigma.Base");
  });
});

describe("buildBatchQuestions", () => {
  it("asks a grade and a tooling question for every row", () => {
    const q = buildBatchQuestions(["R000", "R001"]);
    expect(Object.keys(q).sort()).toEqual(["R000", "R000_tool", "R001", "R001_tool"]);
    expect(q.R000.type).toBe("score");
    expect(q.R000_tool.type).toBe("noul");
  });

  it("points the grade at `rows` and the tooling question at `subjects`", () => {
    // The whole fix is that these two read different keys. Same key = the bug is back.
    const q = buildBatchQuestions(["R000"]);
    expect(q.R000.instructions).toContain("`rows`");
    expect(q.R000_tool.instructions).toContain("`subjects`");
    expect(q.R000_tool.instructions).not.toContain("`rows`");
    const crit = q.R000_tool.type === "noul" ? q.R000_tool.criteria : undefined;
    expect(crit?.false).toMatch(/COLLECTED BY/);
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

  it("hands the tooling question a collector-free view and the grade question the full row", async () => {
    let seen: { rows: Record<string, string>; subjects: Record<string, string> } | null = null;
    const deps: JevGraderDeps = {
      mask: (t) => t,
      ask: async (state, questions) => {
        seen = state as { rows: Record<string, string>; subjects: Record<string, string> };
        const answers: Record<string, JevAnswer> = {};
        for (const qid of Object.keys(questions)) {
          answers[qid] = qid.endsWith("_tool")
            ? { type: "noul", noul: 0 }
            : { type: "score", score: 1, legend: {}, probabilities: {}, confidence: 0.5 };
        }
        return { model: "m", answers, usage: { inputTokens: 1, outputTokens: 1 } };
      },
    };
    await gradeEvents(
      deps,
      [
        ev("a", {
          description: "Velociraptor [Windows.Sigma.Base] Sigma: Encoded PowerShell",
          artifactName: "Windows.Sigma.Base",
        }),
      ],
      { batchSize: 10 },
    );
    const state = seen as unknown as { rows: Record<string, string>; subjects: Record<string, string> };
    expect(state.rows.R000).toContain("Windows.Sigma.Base");
    expect(state.subjects.R000).not.toContain("Windows.Sigma.Base");
    expect(state.subjects.R000).not.toContain("Velociraptor");
    expect(state.subjects.R000).toContain("Sigma: Encoded PowerShell");
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

describe("batching is planned by cost, not by row count (#1568 follow-up)", () => {
  // Found in real use: a 40-row batch of a real archive was refused with `max_tokens_exceeded`.
  // Measured against the live service, 30 rows went through at 35,751 input tokens and 40 did not,
  // so the ceiling is near 36k — and a row count cannot express it, because rows differ by an
  // order of magnitude in size and each one is sent twice.
  it("puts few large rows in a batch and many small ones", () => {
    const big = Array.from({ length: 40 }, () => "x".repeat(8000));
    const small = Array.from({ length: 40 }, () => "x".repeat(60));
    const bigBatches = planBatches(big, 40);
    const smallBatches = planBatches(small, 40);
    expect(bigBatches.length).toBeGreaterThan(smallBatches.length);
    expect(smallBatches).toHaveLength(1);
  });

  it("never emits an empty batch, even for a row larger than the whole budget", () => {
    const plan = planBatches(["y".repeat(500_000), "small"], 40);
    expect(plan.every((b) => b.length > 0)).toBe(true);
    expect(plan.flat()).toEqual([0, 1]);
  });

  it("keeps the row cap as an upper bound when the rows are tiny", () => {
    const plan = planBatches(
      Array.from({ length: 30 }, () => "z"),
      10,
    );
    expect(Math.max(...plan.map((b) => b.length))).toBeLessThanOrEqual(10);
    expect(plan.flat()).toHaveLength(30);
  });

  it("loses no row, whatever the mix of sizes", () => {
    const mixed = Array.from({ length: 77 }, (_, i) => "m".repeat((i % 9) * 3000 + 10));
    expect(planBatches(mixed, 40).flat()).toEqual(mixed.map((_, i) => i));
  });

  it("splits and retries when the service refuses a batch for size", async () => {
    // The budget is a character estimate, so it can still be wrong. A size refusal must be
    // recoverable; anything else must still fail the review.
    const events = Array.from({ length: 4 }, (_, i) => ev(`e${i}`));
    let calls = 0;
    const deps: JevGraderDeps = {
      mask: (t) => t,
      ask: async (_state, questions) => {
        calls += 1;
        const n = Object.keys(questions).length / 2;
        if (n > 1) throw new Error('HTTP 400: {"detail":{"error_type":"max_tokens_exceeded"}}');
        const answers: Record<string, JevAnswer> = {};
        for (const qid of Object.keys(questions)) {
          answers[qid] = qid.endsWith("_tool")
            ? { type: "noul", noul: 0 }
            : { type: "score", score: 2, legend: {}, probabilities: {}, confidence: 0.5 };
        }
        return { model: "m", answers, usage: { inputTokens: 5, outputTokens: 1, costUSD: 0.001 } };
      },
    };
    const r = await gradeEvents(deps, events, { batchSize: 40 });
    expect(r.rows).toHaveLength(4);
    expect(r.usage.inputTokens).toBe(20); // one request per row after the splits
    expect(r.usage.costUSD).toBeCloseTo(0.004);
    expect(calls).toBeGreaterThan(4); // the refused parents are counted too
  });

  it("does NOT retry a failure that is not about size", async () => {
    const deps: JevGraderDeps = {
      mask: (t) => t,
      ask: async () => {
        throw new Error("HTTP 401: bad credentials");
      },
    };
    await expect(gradeEvents(deps, [ev("a"), ev("b")], { batchSize: 40 })).rejects.toThrow(/401/);
  });
});
