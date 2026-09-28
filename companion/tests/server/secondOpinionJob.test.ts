// #1753 — a second opinion is a real job for its whole run, so the jobs chip, the derived AI pill
// (GET /ai-state) and every "is this case busy?" check see it, and a second click cannot start an
// overlapping run whose result would overwrite the first.

import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { resetLimiters } from "../../src/http/rateLimiter.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SecondOpinionStore } from "../../src/analysis/secondOpinionStore.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import { HostMergeDecisionRequired } from "../../src/analysis/hostDuplicateGate.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../src/providers/provider.js";
import { emptyState } from "../../src/analysis/stateTypes.js";

const SYNTH = JSON.stringify({
  findings: [
    {
      id: "f1",
      severity: "High",
      confidence: 80,
      title: "Shared finding",
      description: "d",
      relatedIocs: [],
      mitreTechniques: [],
      status: "open",
      relatedEventIds: [],
    },
  ],
  iocs: [],
  mitreTechniques: [],
  threadsOpened: [],
  threadsClosed: [],
  timelineNote: "",
  summary: "s",
  forensicEvents: [],
  attackerPath: "",
  keyQuestions: [],
  nextSteps: [],
});
const RECONCILE = JSON.stringify({ summary: "agree", verdicts: [] });

/** Model B: holds its synthesis open until the test releases it, or throws. */
class HeldProvider implements AIProvider {
  readonly name = "held";
  readonly model = "model-b";
  synthCalls = 0;
  throws?: Error;
  private release!: () => void;
  private gate = new Promise<void>((resolve) => (this.release = resolve));
  private started!: () => void;
  readonly running = new Promise<void>((resolve) => (this.started = resolve));
  open(): void {
    this.release();
  }
  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    if (/RECONCILING/i.test(req.systemPrompt)) return { rawText: RECONCILE };
    this.synthCalls += 1;
    this.started();
    await this.gate;
    if (this.throws) throw this.throws;
    return { rawText: SYNTH };
  }
}

class PlainProvider implements AIProvider {
  readonly name = "plain";
  readonly model = "model-a";
  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    return { rawText: /RECONCILING/i.test(req.systemPrompt) ? RECONCILE : SYNTH };
  }
}

async function makeApp(withJobs = true) {
  const root = await mkdtemp(join(tmpdir(), "dfir-so-job-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const secondOpinionStore = new SecondOpinionStore(store);
  const a = new PlainProvider();
  const b = new HeldProvider();
  const statuses: string[] = [];
  const jobManager = withJobs ? new JobManager({ perCaseConcurrency: 1 }) : undefined;
  const pipeline = buildRuntimePipeline({
    provider: a,
    synthesisProvider: a,
    stateStore,
    store,
    secondOpinionProvider: b,
    secondOpinionStore,
    synthesisModelLabel: "model-A",
    secondOpinionModelLabel: "model-B",
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, {
    pipeline,
    stateStore,
    aiConfigured: true,
    secondOpinionStore,
    secondOpinionEnabled: true,
    ...(jobManager ? { jobManager } : {}),
    onAiStatus: (_caseId, evt) => statuses.push(evt.status),
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
  const state = emptyState("c1");
  state.forensicTimeline.push({
    id: "e1",
    timestamp: "2026-06-10T00:00:00.000Z",
    description: "beaconing to 1.2.3.4",
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
  });
  await stateStore.save(state);
  return { app, b, jobManager, statuses };
}

const soJobs = (jm: JobManager | undefined) =>
  (jm?.list("c1") ?? []).filter((j) => j.kind === "second-opinion");

beforeEach(() => resetLimiters());

describe("a second opinion is a job for its whole run (#1753)", () => {
  it("the job is running while model B works, the pill derives 'analyzing', and it succeeds at the end", async () => {
    const { app, b, jobManager } = await makeApp();
    const run = request(app)
      .post("/cases/c1/second-opinion")
      .send({})
      .then((r) => r);
    await b.running;

    expect(soJobs(jobManager).map((j) => j.status)).toEqual(["running"]);
    const mid = await request(app).get("/cases/c1/ai-state");
    expect(mid.body.state).toBe("analyzing");
    expect(mid.body.detail).toMatch(/second opinion/);

    b.open();
    expect((await run).status).toBe(200);
    expect(soJobs(jobManager).map((j) => j.status)).toEqual(["succeeded"]);
    expect((await request(app).get("/cases/c1/ai-state")).body.state).toBe("idle");
  });

  it("two clicks at once start ONE run; the second is refused with 409 and the first still lands", async () => {
    const { app, b, jobManager } = await makeApp();
    const first = request(app)
      .post("/cases/c1/second-opinion")
      .send({})
      .then((r) => r);
    const second = request(app)
      .post("/cases/c1/second-opinion")
      .send({})
      .then((r) => r);
    const refused = await second;
    expect(refused.status).toBe(409);
    expect(refused.body.error).toMatch(/already running/);

    b.open();
    expect((await first).status).toBe(200);
    expect(b.synthCalls).toBe(1);
    expect(soJobs(jobManager)).toHaveLength(1);
  });

  it("without a job manager a duplicate is still refused", async () => {
    const { app, b } = await makeApp(false);
    const first = request(app)
      .post("/cases/c1/second-opinion")
      .send({})
      .then((r) => r);
    await b.running;
    expect((await request(app).post("/cases/c1/second-opinion").send({})).status).toBe(409);
    b.open();
    expect((await first).status).toBe(200);
  });

  it("a queued run neither starts the models nor says 'analyzing' until the job ahead ends", async () => {
    const { app, b, jobManager, statuses } = await makeApp();
    const blocker = jobManager!.register({ caseId: "c1", kind: "import", label: "evtx import" });
    await blocker.ready;

    const run = request(app)
      .post("/cases/c1/second-opinion")
      .send({})
      .then((r) => r);
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(soJobs(jobManager).map((j) => j.status)).toEqual(["queued"]);
    expect(b.synthCalls).toBe(0);
    expect(statuses).not.toContain("analyzing");

    await jobManager!.finish(blocker.jobId);
    await b.running;
    expect(statuses).toContain("analyzing");
    b.open();
    expect((await run).status).toBe(200);
  });

  it("a failed run marks the job failed and frees the case for the next job", async () => {
    const { app, b, jobManager } = await makeApp();
    b.throws = new Error("model B down");
    const run = request(app)
      .post("/cases/c1/second-opinion")
      .send({})
      .then((r) => r);
    await b.running;
    b.open();
    expect((await run).status).toBeGreaterThanOrEqual(500);
    expect(soJobs(jobManager).map((j) => j.status)).toEqual(["failed"]);

    const next = jobManager!.register({ caseId: "c1", kind: "import", label: "next" });
    await next.ready; // resolves only if the slot was released
  });

  it("a merge gate ends the job (not left running) and the pill says on hold, not error", async () => {
    const { app, b, jobManager, statuses } = await makeApp();
    b.throws = new HostMergeDecisionRequired([]);
    const run = request(app)
      .post("/cases/c1/second-opinion")
      .send({})
      .then((r) => r);
    await b.running;
    b.open();
    await run;
    const [job] = soJobs(jobManager);
    expect(job.status).not.toBe("running");
    expect(statuses.at(-1)).toBe("blocked");

    const next = jobManager!.register({ caseId: "c1", kind: "import", label: "next" });
    await next.ready;
  });
});
