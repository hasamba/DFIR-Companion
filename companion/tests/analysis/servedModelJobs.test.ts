// The version each AI job ran on (#1601): "sonnet → Sonnet 5" on a finished job, "sonnet (last run:
// Sonnet 5)" on one still waiting for its answer, and the served id on the synthesis run manifest.
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { JobManager } from "../../src/analysis/jobManager.js";
import {
  createJob,
  emptyJobTable,
  finishJob,
  failJob,
  requeueJob,
  jobSchema,
  stampServedModel,
  getJob,
} from "../../src/analysis/jobRegistry.js";
import { withModelLabels } from "../../src/analysis/jobServedModel.js";
import { ServedModelRegistry, servedModels } from "../../src/analysis/servedModels.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { AnalysisRunStore } from "../../src/analysis/analysisRunStore.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../src/providers/provider.js";
import { CaseStore } from "../../src/storage/caseStore.js";

const T0 = "2026-09-25T00:00:00.000Z";
const SONNET = { model: "sonnet", provider: "claude-code" };

function manager(registry: ServedModelRegistry): JobManager {
  const jobs = new JobManager({ now: () => T0 });
  jobs.useModelResolver(() => SONNET);
  jobs.useServedModels(registry);
  return jobs;
}

describe("JobManager served-model stamp", () => {
  it("stamps the job whose own signal carried the call, and labels it", () => {
    const registry = new ServedModelRegistry();
    const jobs = manager(registry);
    const { jobId, signal } = jobs.register({ caseId: "c1", kind: "synthesis", cancellable: true });
    registry.record({ provider: "claude-code", alias: "sonnet", resolvedModel: "claude-sonnet-5", signal });
    expect(jobs.get(jobId)!.servedModel).toBe("claude-sonnet-5");
    expect(jobs.get(jobId)!.model).toBe("sonnet"); // the pin at registration is untouched
    expect(jobs.list("c1")[0].modelLabel).toBe("sonnet → Sonnet 5");
  });

  it("keeps the stamp once the job finishes", async () => {
    const registry = new ServedModelRegistry();
    const jobs = manager(registry);
    const { jobId, signal } = jobs.register({ caseId: "c1", kind: "synthesis", cancellable: true });
    registry.record({ provider: "claude-code", alias: "sonnet", resolvedModel: "claude-sonnet-5", signal });
    await jobs.finish(jobId);
    const row = jobs.list("c1")[0];
    expect(row.status).toBe("succeeded");
    expect(row.modelLabel).toBe("sonnet → Sonnet 5");
  });

  it("never stamps from a call on another provider or alias that shares the signal", () => {
    const registry = new ServedModelRegistry();
    const jobs = manager(registry);
    const { jobId, signal } = jobs.register({ caseId: "c1", kind: "synthesis", cancellable: true });
    registry.record({ provider: "openrouter", alias: "sonnet", resolvedModel: "x/claude-sonnet", signal });
    registry.record({ provider: "claude-code", alias: "opus", resolvedModel: "claude-opus-5-5", signal });
    expect(jobs.get(jobId)!.servedModel).toBeUndefined();
  });

  it("never stamps from a call without the job's signal", () => {
    const registry = new ServedModelRegistry();
    const jobs = manager(registry);
    const { jobId } = jobs.register({ caseId: "c1", kind: "synthesis", cancellable: true });
    registry.record({ provider: "claude-code", alias: "sonnet", resolvedModel: "claude-sonnet-5" });
    registry.record({
      provider: "claude-code",
      alias: "sonnet",
      resolvedModel: "claude-sonnet-5",
      signal: new AbortController().signal,
    });
    expect(jobs.get(jobId)!.servedModel).toBeUndefined();
  });

  it("never stamps a job that pinned no provider", () => {
    const registry = new ServedModelRegistry();
    const jobs = new JobManager({ now: () => T0 });
    jobs.useModelResolver(() => "sonnet");
    jobs.useServedModels(registry);
    const { jobId, signal } = jobs.register({ caseId: "c1", kind: "synthesis", cancellable: true });
    registry.record({ provider: "claude-code", alias: "sonnet", resolvedModel: "claude-sonnet-5", signal });
    expect(jobs.get(jobId)!.servedModel).toBeUndefined();
    expect(jobs.list("c1")[0].modelLabel).toBe("sonnet");
  });

  it("shows the last served version on a job still waiting for its answer", () => {
    const registry = new ServedModelRegistry();
    const jobs = manager(registry);
    jobs.register({ caseId: "c1", kind: "synthesis", cancellable: true });
    expect(jobs.list("c1")[0].modelLabel).toBe("sonnet"); // nothing known yet: alias only
    registry.record({ provider: "claude-code", alias: "sonnet", resolvedModel: "claude-sonnet-5" });
    expect(jobs.list("c1")[0].modelLabel).toBe("sonnet (last run: Sonnet 5)");
  });

  it("lets a caller that knows the model better name it at registration (a replay)", () => {
    const registry = new ServedModelRegistry();
    const jobs = manager(registry);
    const { jobId, signal } = jobs.register({
      caseId: "c1",
      kind: "synthesis",
      cancellable: true,
      model: { model: "opus", provider: "claude-code" },
    });
    registry.record({ provider: "claude-code", alias: "opus", resolvedModel: "claude-opus-5-5", signal });
    expect(jobs.list("c1").find((j) => j.id === jobId)!.modelLabel).toBe("opus → Opus 5.5");
  });

  it("does not double up when bound twice", async () => {
    const registry = new ServedModelRegistry();
    let emitted = 0;
    const jobs = new JobManager({ now: () => T0, onJob: () => emitted++ });
    jobs.useModelResolver(() => SONNET);
    jobs.useServedModels(registry);
    jobs.useServedModels(registry);
    const { signal } = jobs.register({ caseId: "c1", kind: "synthesis", cancellable: true });
    await new Promise((r) => setTimeout(r, 0));
    const before = emitted;
    registry.record({ provider: "claude-code", alias: "sonnet", resolvedModel: "claude-sonnet-5", signal });
    registry.record({ provider: "claude-code", alias: "sonnet", resolvedModel: "claude-sonnet-5", signal });
    await new Promise((r) => setTimeout(r, 0));
    expect(emitted - before).toBe(1);
  });
});

describe("served model on the ledger", () => {
  it("survives the schema round-trip after stamp and finish", () => {
    let table = createJob(emptyJobTable(), {
      id: "job_1",
      caseId: "c1",
      kind: "synthesis",
      model: "sonnet",
      modelProvider: "claude-code",
      status: "running",
      now: T0,
    });
    table = stampServedModel(table, "job_1", "claude-sonnet-5", T0);
    table = finishJob(table, "job_1", T0);
    const parsed = jobSchema.parse(JSON.parse(JSON.stringify(getJob(table, "job_1"))));
    expect(parsed.servedModel).toBe("claude-sonnet-5");
    expect(parsed.modelProvider).toBe("claude-code");
  });

  // A resumed attempt runs on the provider configured now; the old attempt's answer is not its own.
  it("a resume clears the served model and re-pins the model identity", () => {
    let table = createJob(emptyJobTable(), {
      id: "job_1",
      caseId: "c1",
      kind: "deep-pass",
      model: "sonnet",
      modelProvider: "claude-code",
      status: "running",
      now: T0,
    });
    table = stampServedModel(table, "job_1", "claude-sonnet-5", T0);
    table = failJob(table, "job_1", { code: "x", message: "x", retryable: true, at: T0 }, T0);
    const requeued = getJob(
      requeueJob(table, "job_1", T0, { model: "gpt-6-sol", modelProvider: "openai" }),
      "job_1",
    );
    expect(requeued?.servedModel).toBeUndefined();
    expect(requeued?.model).toBe("gpt-6-sol");
    expect(requeued?.modelProvider).toBe("openai");
    const kept = getJob(requeueJob(table, "job_1", T0), "job_1");
    expect(kept?.model).toBe("sonnet");
    expect(kept?.servedModel).toBeUndefined();
  });

  it("does not stamp a finished job", () => {
    let table = createJob(emptyJobTable(), {
      id: "job_1",
      caseId: "c1",
      kind: "synthesis",
      model: "sonnet",
      now: T0,
    });
    table = finishJob(table, "job_1", T0);
    expect(stampServedModel(table, "job_1", "claude-sonnet-5", T0)).toBe(table);
  });

  // After a restart this process has seen no answer yet, but the ledger has: the newest restored
  // row with the same provider and alias supplies "last run".
  it("takes 'last run' from restored rows when this process has seen no answer", () => {
    const restored = [
      { ...row("old", "succeeded", "2026-09-24T00:00:00.000Z"), servedModel: "claude-sonnet-4-6" },
      { ...row("newer", "succeeded", "2026-09-24T12:00:00.000Z"), servedModel: "claude-sonnet-5" },
      {
        ...row("other", "succeeded", "2026-09-25T00:00:00.000Z"),
        modelProvider: "openrouter",
        servedModel: "zz",
      },
    ];
    const running = row("now", "running", T0);
    const [labelled] = withModelLabels([running], [...restored, running], () => undefined);
    expect(labelled.modelLabel).toBe("sonnet (last run: Sonnet 5)");
  });
});

function row(id: string, status: "running" | "succeeded", updatedAt: string) {
  const table = createJob(emptyJobTable(), {
    id,
    caseId: "c1",
    kind: "synthesis",
    model: "sonnet",
    modelProvider: "claude-code",
    status: "running",
    now: updatedAt,
  });
  const job = getJob(status === "succeeded" ? finishJob(table, id, updatedAt) : table, id)!;
  return { ...job, updatedAt };
}

// End to end through the real provider-call gate and synthesis: no stubbed recorder in between.
describe("synthesis records the served model", () => {
  let stateStore: StateStore;
  let runStore: AnalysisRunStore;
  const answer = JSON.stringify({
    findings: [],
    iocs: [],
    mitreTechniques: [],
    attackerPath: "",
    forensicEvents: [],
    threadsOpened: [],
    threadsClosed: [],
    timelineNote: "",
    summary: "PowerShell activity.",
  });

  beforeEach(async () => {
    const cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-served-model-")));
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "claude-code" });
    stateStore = new StateStore(cases);
    runStore = new AnalysisRunStore(cases, { appVersion: "0.37.0" });
    const seeded = emptyState("c1");
    seeded.forensicTimeline.push({
      id: "evidence-1",
      timestamp: "2026-07-31T10:00:00.000Z",
      description: "PowerShell launched an encoded command",
      severity: "High",
      mitreTechniques: ["T1059.001"],
      relatedFindingIds: [],
      sourceScreenshots: [],
    });
    await stateStore.save(seeded);
  });

  afterEach(() => servedModels.reset());

  function provider(replies: Array<{ rawText: string; resolvedModel?: string }>): AIProvider {
    let call = 0;
    return {
      name: "claude-code",
      model: "sonnet",
      async analyze(_req: AnalyzeRequest): Promise<AnalyzeResult> {
        const reply = replies[Math.min(call++, replies.length - 1)];
        return {
          rawText: reply.rawText,
          ...(reply.resolvedModel ? { usage: { resolvedModel: reply.resolvedModel } } : {}),
        };
      },
    };
  }

  function pipelineWith(p: AIProvider): AnalysisPipeline {
    return new AnalysisPipeline({
      provider: p,
      stateStore,
      analysisRunStore: runStore,
      imageLoader: async () => ({ base64: "A", mimeType: "image/webp" }),
      backoffMs: 0,
    });
  }

  it("stamps the job and writes resolvedModel on the run manifest", async () => {
    const jobs = new JobManager({ now: () => T0 });
    jobs.useModelResolver(() => SONNET);
    jobs.useServedModels(servedModels);
    const { jobId, signal } = jobs.register({ caseId: "c1", kind: "synthesis", cancellable: true });
    await pipelineWith(provider([{ rawText: answer, resolvedModel: "claude-sonnet-5" }])).synthesize("c1", {
      force: true,
      ...(signal ? { signal } : {}),
    });
    await jobs.finish(jobId);
    expect(jobs.list("c1")[0].modelLabel).toBe("sonnet → Sonnet 5");
    const run = (await runStore.list("c1"))[0];
    expect(run.configuration?.model).toBe("sonnet");
    expect(run.configuration?.resolvedModel).toBe("claude-sonnet-5");
  });

  it("records the model of the attempt that succeeded after a bad answer", async () => {
    await pipelineWith(
      provider([
        { rawText: "not json", resolvedModel: "claude-sonnet-4-6" },
        { rawText: answer, resolvedModel: "claude-sonnet-5" },
      ]),
    ).synthesize("c1", { force: true });
    const run = (await runStore.list("c1"))[0];
    expect(run.configuration?.resolvedModel).toBe("claude-sonnet-5");
  });

  // A failed attempt's model must not label an accepted answer that came back without one.
  it("records nothing when only a rejected attempt reported a model", async () => {
    await pipelineWith(
      provider([{ rawText: "not json", resolvedModel: "claude-sonnet-4-6" }, { rawText: answer }]),
    ).synthesize("c1", { force: true });
    const run = (await runStore.list("c1"))[0];
    expect(run.configuration?.resolvedModel).toBeUndefined();
  });

  it("leaves both the job and the manifest alias-only when the provider reports nothing", async () => {
    const jobs = new JobManager({ now: () => T0 });
    jobs.useModelResolver(() => SONNET);
    jobs.useServedModels(servedModels);
    const { jobId, signal } = jobs.register({ caseId: "c1", kind: "synthesis", cancellable: true });
    await pipelineWith(provider([{ rawText: answer }])).synthesize("c1", {
      force: true,
      ...(signal ? { signal } : {}),
    });
    await jobs.finish(jobId);
    expect(jobs.list("c1")[0].modelLabel).toBe("sonnet");
    const run = (await runStore.list("c1"))[0];
    expect(run.configuration?.resolvedModel).toBeUndefined();
  });
});
