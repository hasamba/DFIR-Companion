// #2495: #2459 set the rule that an AI reply in the wrong shape reaches the analyst as one plain
// sentence, with the schema detail in the server log. Synthesis and screenshot extraction still
// threw the raw ZodError after their retries ran out, so the AI status pill showed
// `error — [ { "code": "invalid_type", … } ]`. The conversion happens OUTSIDE the retry loop, so the
// per-attempt retry note and the saved failed answer are unchanged.
import { describe, it, expect, beforeEach, vi } from "vitest";
import { mkdtemp, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ZodError } from "zod";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SynthMetaStore } from "../../src/analysis/synthMeta.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import { AiReplyUnreadableError } from "../../src/analysis/ai/aiReplyUnreadable.js";
import type { AnalyzeRequest } from "../../src/providers/provider.js";
import type { CaptureMetadata } from "../../src/types.js";

const FINDING = {
  id: "f1",
  severity: "High",
  title: "Credential dumping",
  description: "LSASS read",
  relatedIocs: [],
  mitreTechniques: ["T1003.001"],
  status: "open",
};

let cases: CaseStore;
let stateStore: StateStore;
let synthMetaStore: SynthMetaStore;
let prompts: string[];
let warns: string[];

const logger = {
  debug: () => undefined,
  info: () => undefined,
  warn: (msg: string) => void warns.push(msg),
  error: () => undefined,
};

function ev(id: string): ForensicEvent {
  return {
    id,
    timestamp: "2026-04-22T11:41:00Z",
    description: "LSASS access",
    severity: "Critical",
    mitreTechniques: ["T1003.001"],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: "WS01",
    sources: ["Sysmon"],
  };
}

function capture(seq: number): CaptureMetadata {
  return {
    caseId: "c1",
    sequenceNumber: seq,
    timestamp: "2026-05-28T10:00:00.000Z",
    url: "https://example.test",
    tabTitle: "t",
    triggerType: "timer",
    contentHash: "0",
    isDuplicate: false,
    screenshotFile: `00000${seq}_t.webp`,
  };
}

function pipelineAnswering(answers: string[], retries: number): AnalysisPipeline {
  let i = 0;
  const analyze = vi.fn(async (req: AnalyzeRequest) => {
    prompts.push(req.userPrompt ?? "");
    return { rawText: answers[Math.min(i++, answers.length - 1)] };
  });
  const provider = { name: "fake", model: "m", analyze };
  return new AnalysisPipeline({
    stateStore,
    synthMetaStore,
    provider,
    synthesisProvider: provider,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    logger: logger as never,
    retries,
    backoffMs: 0,
  });
}

async function failedFiles(): Promise<string[]> {
  try {
    return await readdir(join(cases.caseDir("c1"), "logs"));
  } catch {
    return [];
  }
}

async function rejection(run: Promise<unknown>): Promise<Error> {
  try {
    await run;
  } catch (err) {
    return err as Error;
  }
  throw new Error("expected the run to fail");
}

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-reply-unreadable-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(cases);
  synthMetaStore = new SynthMetaStore(cases);
  prompts = [];
  warns = [];
  const s = emptyState("c1");
  s.forensicTimeline.push(ev("a"), ev("b"));
  await stateStore.save(s);
});

describe("synthesis with an answer in the wrong shape (#2495)", () => {
  it("fails with the plain sentence, logs the schema issues and still saves the answer", async () => {
    const p = pipelineAnswering([JSON.stringify({ findings: "x", summary: "s" })], 0);

    const err = await rejection(p.synthesize("c1"));

    expect(err).toBeInstanceOf(AiReplyUnreadableError);
    expect(err.message).toMatch(/AI reply could not be read/);
    expect(err.message).not.toMatch(/invalid_type/);
    expect(err.cause).toBeInstanceOf(ZodError);
    expect(warns.some((w) => w.includes("synthesis") && w.includes("invalid_type"))).toBe(true);
    expect(await failedFiles()).toHaveLength(1);
  });

  it("one bad answer followed by a good one still succeeds and carries the retry note", async () => {
    const p = pipelineAnswering(
      [JSON.stringify({ findings: [FINDING] }), JSON.stringify({ findings: [FINDING], summary: "ok" })],
      3,
    );

    const state = await p.synthesize("c1");

    expect(state.findings.map((f) => f.title)).toContain("Credential dumping");
    expect(prompts).toHaveLength(2);
    expect(prompts[1]).toContain("Your previous answer omitted: summary");
  });
});

describe("screenshot extraction with an answer in the wrong shape (#2495)", () => {
  it("fails with the plain sentence and logs the schema issues", async () => {
    const p = pipelineAnswering([JSON.stringify({ findings: "x" })], 0);

    const err = await rejection(p.analyzeWindow("c1", [capture(1)]));

    expect(err).toBeInstanceOf(AiReplyUnreadableError);
    expect(err.message).not.toMatch(/invalid_type/);
    expect(warns.some((w) => w.includes("extract") && w.includes("invalid_type"))).toBe(true);
  });
});
