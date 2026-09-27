import { describe, expect, it } from "vitest";
import type { AIProvider, AnalyzeRequest } from "../../src/providers/provider.js";
import { loadGoldenCorpus, type GoldenCorpus } from "./corpus.js";
import { runCorpusSuite } from "./corpusRunner.js";

// #1704: the real-run path asks the semantic judge; the mock path keeps the word list.
async function injectionCase(): Promise<GoldenCorpus> {
  const corpus = await loadGoldenCorpus();
  return { ...corpus, cases: corpus.cases.filter((fixture) => fixture.id === "email-prompt-injection") };
}

function provider(canned: string, judgeReply: (request: AnalyzeRequest) => string): AIProvider {
  return {
    name: "stub",
    model: "stub-model",
    async analyze(request: AnalyzeRequest) {
      const judging = request.systemPrompt.startsWith("You grade findings");
      return { rawText: judging ? judgeReply(request) : canned };
    },
  };
}

function everyPair(request: AnalyzeRequest, asserts: boolean): string {
  const statements = [...request.userPrompt.matchAll(/^(S\d+):/gm)].map((match) => match[1]);
  const findings = [...request.userPrompt.matchAll(/^(F\d+) /gm)].map((match) => match[1]);
  return JSON.stringify({
    verdicts: statements.flatMap((statement) =>
      findings.map((finding) => ({ statement, finding, asserts, reason: "graded" })),
    ),
  });
}

describe("runCorpusSuite grades forbidden conclusions with the judge on a real run (#1704)", () => {
  it("takes the judge's 'not asserted' over the word list, and records privacy-safe judge counts", async () => {
    const corpus = await injectionCase();
    const [fixture] = corpus.cases;
    const [row] = await runCorpusSuite(
      corpus,
      () => provider(fixture.canned, (r) => everyPair(r, false)),
      true,
    );
    expect(row.metrics.forbiddenConclusions).toBe(0);
    expect(row.judge?.pairs).toBeGreaterThan(0);
    expect(row.judge?.asserted).toBe(0);
  });

  it("flags a forbidden conclusion the judge finds asserted", async () => {
    const corpus = await injectionCase();
    const [fixture] = corpus.cases;
    const [row] = await runCorpusSuite(
      corpus,
      () => provider(fixture.canned, (r) => everyPair(r, true)),
      true,
    );
    expect(row.metrics.forbiddenConclusions).toBe(1);
    expect(row.status).toBe("quality_failed");
  });

  it("fails the case as provider_failed when the judge never answers validly", async () => {
    const corpus = await injectionCase();
    const [fixture] = corpus.cases;
    const [row] = await runCorpusSuite(corpus, () => provider(fixture.canned, () => "not json"), true);
    expect(row.status).toBe("provider_failed");
    expect(row.errorKind).toBe("judge-invalid-output");
  });

  it("never calls the judge on a mock run", async () => {
    const corpus = await injectionCase();
    const [fixture] = corpus.cases;
    let judged = 0;
    const mock = provider(fixture.canned, (r) => {
      judged += 1;
      return everyPair(r, true);
    });
    const [row] = await runCorpusSuite(corpus, () => mock, false);
    expect(judged).toBe(0);
    expect(row.judge).toBeUndefined();
  });
});
