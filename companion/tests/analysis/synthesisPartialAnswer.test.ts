import { describe, it, expect, beforeEach, vi } from "vitest";
import { mkdtemp, readdir, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SynthMetaStore } from "../../src/analysis/synthMeta.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import { outputLimitError, type AnalyzeRequest } from "../../src/providers/provider.js";

// #1602: a partial model answer must not throw a whole synthesis away. Always a temp case root.

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
let requests: AnalyzeRequest[];
let warns: string[];

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

const logger = {
  debug: () => undefined,
  info: () => undefined,
  warn: (msg: string) => void warns.push(msg),
  error: () => undefined,
};

function pipelineAnswering(answers: Array<string | Error>, withMeta = true): AnalysisPipeline {
  let i = 0;
  const analyze = vi.fn(async (req: AnalyzeRequest) => {
    requests.push(req);
    prompts.push(req.userPrompt ?? "");
    const a = answers[Math.min(i++, answers.length - 1)];
    if (a instanceof Error) throw a;
    return { rawText: a };
  });
  return new AnalysisPipeline({
    stateStore,
    ...(withMeta ? { synthMetaStore } : {}),
    synthesisProvider: { name: "fake", model: "m", analyze },
    imageLoader: async () => ({ data: Buffer.from(""), mediaType: "image/png" }) as never,
    logger: logger as never,
    retries: 3,
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

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-partialanswer-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(cases);
  synthMetaStore = new SynthMetaStore(cases);
  prompts = [];
  requests = [];
  warns = [];
  const s = emptyState("c1");
  s.forensicTimeline.push(ev("a"), ev("b"));
  await stateStore.save(s);
});

describe("synthesis on a partial model answer (#1602)", () => {
  it("accepts an answer with only findings and summary, and logs the filled fields", async () => {
    const p = pipelineAnswering([JSON.stringify({ findings: [FINDING], summary: "Opus summary" })]);
    const state = await p.synthesize("c1");
    expect(prompts).toHaveLength(1);
    expect(state.findings.map((f) => f.title)).toContain("Credential dumping");
    const line = warns.find((w) => w.includes("filled"));
    expect(line).toBeDefined();
    for (const f of ["iocs", "mitreTechniques", "threadsOpened", "threadsClosed", "timelineNote"])
      expect(line).toContain(f);
    // The MITRE table is rebuilt from the findings, not erased (Codex review of #1602).
    expect(state.mitreTechniques.map((t) => t.id)).toContain("T1003.001");
  });

  it("retries an answer with only findings once, carrying the omitted-fields note, and saves the answer", async () => {
    const p = pipelineAnswering([
      JSON.stringify({ findings: [FINDING] }),
      JSON.stringify({ findings: [FINDING], summary: "second try" }),
    ]);
    await p.synthesize("c1");
    expect(prompts).toHaveLength(2);
    expect(prompts[0]).not.toContain("Your previous answer");
    expect(prompts[1].startsWith(prompts[0])).toBe(true);
    expect(prompts[1]).toContain("Your previous answer omitted: summary");
    const files = await failedFiles();
    expect(files).toHaveLength(1);
    const body = await readFile(join(cases.caseDir("c1"), "logs", files[0]), "utf8");
    expect(body).toContain("Credential dumping");
    expect(body).toContain("summary");
    expect(warns.some((w) => w.includes(files[0]))).toBe(true);
  });

  it("saves a non-JSON answer raw and tells the next attempt it was not valid JSON", async () => {
    const p = pipelineAnswering([
      "{ not json at all",
      JSON.stringify({ findings: [FINDING], summary: "ok" }),
    ]);
    await p.synthesize("c1");
    expect(prompts[1]).toContain("was not valid JSON");
    const files = await failedFiles();
    expect(files).toHaveLength(1);
    expect(await readFile(join(cases.caseDir("c1"), "logs", files[0]), "utf8")).toContain(
      "{ not json at all",
    );
  });

  it("keeps the note across a transient provider error", async () => {
    const p = pipelineAnswering([
      JSON.stringify({ findings: [FINDING] }),
      new Error("socket hang up"),
      JSON.stringify({ findings: [FINDING], summary: "ok" }),
    ]);
    await p.synthesize("c1");
    expect(prompts).toHaveLength(3);
    expect(prompts[2]).toContain("Your previous answer omitted: summary");
    expect(await failedFiles()).toHaveLength(1); // the provider error has no answer to save
  });

  it("a failed synthesis leaves one raw-answer file per failed attempt, and the original error", async () => {
    const p = pipelineAnswering([JSON.stringify({ findings: [FINDING] })]);
    await expect(p.synthesize("c1")).rejects.toThrow(/summary/);
    expect(prompts).toHaveLength(4);
    expect(await failedFiles()).toHaveLength(4);
  });

  it("warns when there is no store to save the answer to, and still fails with the original error", async () => {
    const p = pipelineAnswering([JSON.stringify({ findings: [FINDING] })], false);
    await expect(p.synthesize("c1")).rejects.toThrow(/summary/);
    expect(warns.some((w) => w.includes("raw answer not saved"))).toBe(true);
  });
});

// A reasoning model can spend its whole output limit thinking and return a cut-off answer. The JSON
// repair then turned that into a stub finding, and the schema reported "relatedIocs Required" —
// true, but the wrong thing to tell the analyst, and all four attempts failed the same way.
describe("synthesis when the model hits its output limit", () => {
  it("asks the provider to refuse a cut-off answer", async () => {
    const p = pipelineAnswering([JSON.stringify({ findings: [FINDING], summary: "ok" })]);
    await p.synthesize("c1");
    expect(requests[0].rejectTruncated).toBe(true);
  });

  it("fails on the first attempt with the output-limit message, not a schema error", async () => {
    const p = pipelineAnswering([outputLimitError("Ollama", 16000, 15600)]);
    await expect(p.synthesize("c1")).rejects.toThrow(/output limit of 16,000 tokens.*DFIR_AI_MAX_TOKENS/s);
    expect(prompts).toHaveLength(1);
  });
});
