import { beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SynthMetaStore } from "../../src/analysis/synthMeta.js";
import { AnalysisRunStore } from "../../src/analysis/analysisRunStore.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import { outputLimitError, type AnalyzeRequest } from "../../src/providers/provider.js";

// #1754: on INC-2026-022 an Opus synthesis stored 13 findings with empty relatedEventIds. The High
// backfill then raised 82 auto findings, some on rows a dismissed finding had explained. Always a
// temp case root.

const NOTE = "cited no events";

let cases: CaseStore;
let stateStore: StateStore;
let runStore: AnalysisRunStore;
let prompts: string[];
let warns: string[];

function ev(id: string, description: string): ForensicEvent {
  return {
    id,
    timestamp: "2026-09-28T11:57:00Z",
    description,
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: "DESKTOP-1",
    sources: ["THOR"],
  };
}

const finding = (id: string, description: string, relatedEventIds?: string[], status = "open") => ({
  id,
  severity: status === "dismissed" ? "Low" : "High",
  title: `finding ${id}`,
  description,
  relatedIocs: [],
  mitreTechniques: [],
  status,
  ...(relatedEventIds ? { relatedEventIds } : {}),
});

const answer = (findings: unknown[]) => JSON.stringify({ findings, summary: "s" });

const UNCITED = answer([
  finding("f1", "Toolkit staged in Public"),
  finding("f2", "Defender disabled"),
  finding("f3", "Sample corpus alerts", undefined, "dismissed"),
]);
const CITED = answer([
  finding("f1", "Toolkit staged in Public", ["29e20"]),
  finding("f2", "Defender disabled", ["29e21"]),
  finding("f3", "Sample corpus alerts", ["4e378"], "dismissed"),
]);

const logger = {
  debug: () => undefined,
  info: () => undefined,
  warn: (msg: string) => void warns.push(msg),
  error: () => undefined,
};

function pipelineAnswering(answers: Array<string | Error>, retries = 3): AnalysisPipeline {
  let i = 0;
  const analyze = vi.fn(async (req: AnalyzeRequest) => {
    prompts.push(req.userPrompt ?? "");
    const a = answers[Math.min(i++, answers.length - 1)];
    if (a instanceof Error) throw a;
    return { rawText: a };
  });
  return new AnalysisPipeline({
    stateStore,
    synthMetaStore: new SynthMetaStore(cases),
    analysisRunStore: runStore,
    synthesisProvider: { name: "fake", model: "m", analyze },
    imageLoader: async () => ({ data: Buffer.from(""), mediaType: "image/png" }) as never,
    logger: logger as never,
    retries,
    backoffMs: 0,
  });
}

async function logFiles(): Promise<string[]> {
  try {
    return await readdir(join(cases.caseDir("c1"), "logs"));
  } catch {
    return [];
  }
}

async function runRetries(): Promise<number | undefined> {
  const synth = (await runStore.list("c1")).filter((r) => r.kind === "synthesis");
  return synth[synth.length - 1]?.execution.retries;
}

async function runWarnings(): Promise<string[]> {
  const runs = await runStore.list("c1");
  const synth = runs.filter((r) => r.kind === "synthesis");
  return synth[synth.length - 1]?.execution.warnings ?? [];
}

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-uncited-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(cases);
  runStore = new AnalysisRunStore(cases, { appVersion: "test" });
  prompts = [];
  warns = [];
  const s = emptyState("c1");
  s.forensicTimeline.push(
    ev("29e20", "YaraFile hit on C:\\Users\\Public\\toolkit\\a.exe"),
    ev("29e21", "Defender real-time protection disabled"),
    ev("4e378", "THOR LogScan: Mimikatz in sample.evtx"),
  );
  await stateStore.save(s);
});

describe("synthesis answer whose findings cite no event (#1754)", () => {
  it("asks once more with a citation note, saves the uncited answer, and keeps the cited retry", async () => {
    const p = pipelineAnswering([UNCITED, CITED]);
    const state = await p.synthesize("c1");
    expect(prompts).toHaveLength(2);
    expect(prompts[0]).not.toContain(NOTE);
    expect(prompts[1].startsWith(prompts[0])).toBe(true);
    expect(prompts[1]).toContain(NOTE);
    expect(await logFiles()).toHaveLength(1);
    expect(state.findings.find((f) => f.id === "f1")?.relatedEventIds).toEqual(["29e20"]);
    expect(await runWarnings()).toContain(
      "citation retry ran: the first answer left 3 of 3 AI finding(s) with no cited event",
    );
    expect(await runRetries()).toBe(1);
  });

  it("does not ask again when the findings cite their events", async () => {
    const p = pipelineAnswering([CITED]);
    await p.synthesize("c1");
    expect(prompts).toHaveLength(1);
    expect(await logFiles()).toHaveLength(0);
    expect(await runRetries()).toBe(0);
    expect((await runWarnings()).some((w) => w.includes("cite no event"))).toBe(false);
  });

  it("does not ask again for an answer with no findings, or with one lone uncited finding", async () => {
    await pipelineAnswering([answer([])]).synthesize("c1");
    expect(prompts).toHaveLength(1);
    prompts = [];
    await pipelineAnswering([answer([finding("f1", "No exfiltration was seen")])]).synthesize("c1", {
      force: true,
    });
    expect(prompts).toHaveLength(1);
  });

  it("runs the citation retry even with the generic retries set to 0", async () => {
    const p = pipelineAnswering([UNCITED, CITED], 0);
    await p.synthesize("c1");
    expect(prompts).toHaveLength(2);
    expect(prompts[1]).toContain(NOTE);
  });

  it("keeps the citation note when the retry's first attempt is not valid JSON", async () => {
    const p = pipelineAnswering([UNCITED, "{ not json", CITED]);
    await p.synthesize("c1");
    expect(prompts).toHaveLength(3);
    expect(prompts[2]).toContain(NOTE);
    expect(prompts[2]).toContain("was not valid JSON");
  });

  it("accepts a retry that still cites nothing, and says so in the log and the run record", async () => {
    const p = pipelineAnswering([UNCITED, UNCITED]);
    const state = await p.synthesize("c1");
    expect(prompts).toHaveLength(2);
    expect(state.findings.map((f) => f.id)).toEqual(expect.arrayContaining(["f1", "f2", "f3"]));
    expect(warns.some((w) => w.includes("the citation retry still left 3 of 3"))).toBe(true);
    expect(await runWarnings()).toContain(
      "3 of 3 AI finding(s) cite no event, so the High backfill cannot tell which rows they cover",
    );
  });

  it("keeps the first answer when the citation retry cannot be had", async () => {
    const p = pipelineAnswering([UNCITED, outputLimitError("fake", 16000, 15600)]);
    const state = await p.synthesize("c1");
    expect(prompts).toHaveLength(2);
    expect(state.findings.map((f) => f.id)).toEqual(expect.arrayContaining(["f1", "f2", "f3"]));
    expect(warns.some((w) => w.includes("citation retry failed"))).toBe(true);
  });
});

describe("a finding whose only citation is an id no event has (#1754, Codex review)", () => {
  it("counts as citing no event in the run record", async () => {
    const p = pipelineAnswering([
      answer([
        finding("f1", "Toolkit staged in Public", ["29e20"]),
        finding("f2", "Defender disabled", ["made-up"]),
      ]),
    ]);
    const state = await p.synthesize("c1");
    expect(prompts).toHaveLength(1);
    expect(state.findings.find((f) => f.id === "f2")?.relatedEventIds).toEqual([]);
    expect(await runWarnings()).toContain(
      "1 of 2 AI finding(s) cite no event, so the High backfill cannot tell which rows they cover",
    );
  });
});

describe("ids a finding names only in its text (#1754 regression)", () => {
  it("become its citations, and a dismissed finding's rows raise no active auto finding", async () => {
    const p = pipelineAnswering([
      answer([
        finding("f1", "Toolkit staged in Public", ["29e20"]),
        finding("f10", "The 11:57 script block (4e378, 29e21) is a normal Windows script.", [], "dismissed"),
      ]),
    ]);
    const state = await p.synthesize("c1");
    expect(prompts).toHaveLength(1); // one uncited finding of two is not a retry
    expect(state.findings.find((f) => f.id === "f10")?.relatedEventIds).toEqual(["4e378", "29e21"]);
    const autoOpen = state.findings.filter((f) => f.id.startsWith("f-auto") && f.status !== "dismissed");
    const autoEvents = new Set(autoOpen.flatMap((f) => f.relatedEventIds ?? []));
    expect(autoEvents.has("4e378")).toBe(false);
    expect(autoEvents.has("29e21")).toBe(false);
    expect(warns.some((w) => w.includes("f10 cited no event; recovered 4e378, 29e21"))).toBe(true);
  });

  it("without the recovery the same rows would be raised: an uncited dismissal covers nothing", async () => {
    const p = pipelineAnswering([
      answer([
        finding("f1", "Toolkit staged in Public", ["29e20"]),
        finding("f10", "The 11:57 script block is a normal Windows script.", [], "dismissed"),
      ]),
    ]);
    const state = await p.synthesize("c1");
    const autoOpen = state.findings.filter((f) => f.id.startsWith("f-auto") && f.status !== "dismissed");
    expect(autoOpen.flatMap((f) => f.relatedEventIds ?? [])).toEqual(
      expect.arrayContaining(["4e378", "29e21"]),
    );
    expect(await runWarnings()).toContain(
      "1 of 2 AI finding(s) cite no event, so the High backfill cannot tell which rows they cover",
    );
  });
});
