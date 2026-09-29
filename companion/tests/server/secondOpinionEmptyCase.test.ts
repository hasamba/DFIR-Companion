// #1769 / #1771 — a second opinion on a case with an empty forensic timeline is a refusal, not a
// failure. It answers 200 with the #1676 skip shape, fails no job, and never turns the AI pill red.

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
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../src/providers/provider.js";
import { emptyState } from "../../src/analysis/stateTypes.js";

const SYNTH = JSON.stringify({
  findings: [],
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

class CountingProvider implements AIProvider {
  readonly name = "counting";
  calls = 0;
  constructor(readonly model: string) {}
  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    this.calls += 1;
    return { rawText: /RECONCILING/i.test(req.systemPrompt) ? RECONCILE : SYNTH };
  }
}

async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-so-empty-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const secondOpinionStore = new SecondOpinionStore(store);
  const a = new CountingProvider("model-a");
  const b = new CountingProvider("model-b");
  const statuses: string[] = [];
  const jobManager = new JobManager({ perCaseConcurrency: 1 });
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
    jobManager,
    onAiStatus: (_caseId, evt) => statuses.push(evt.status),
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
  return { app, a, b, jobManager, statuses, stateStore };
}

const soJobs = (jm: JobManager) => jm.list("c1").filter((j) => j.kind === "second-opinion");

beforeEach(() => resetLimiters());

describe("second opinion on an empty case (#1769)", () => {
  it("answers 200 with a skip reason instead of a 500", async () => {
    const { app, a, b } = await makeApp();
    const res = await request(app).post("/cases/c1/second-opinion").send({});
    expect(res.status).toBe(200);
    expect(res.body.skipped).toBe("empty-timeline");
    expect(res.body.message).toMatch(/nothing to review/);
    expect(res.body.deltas).toBeUndefined();
    expect(a.calls + b.calls).toBe(0);
  });

  it("fails no job and never pushes an error status — the AI pill stays idle", async () => {
    const { app, jobManager, statuses } = await makeApp();
    await request(app).post("/cases/c1/second-opinion").send({});
    expect(soJobs(jobManager).map((j) => j.status)).not.toContain("failed");
    expect(statuses).not.toContain("error");
    expect(statuses).not.toContain("analyzing");
    const aiState = await request(app).get("/cases/c1/ai-state");
    expect(aiState.body.state).not.toBe("error");
  });

  it("waits for an import holding the case slot, so events that import lands are reviewed", async () => {
    const { app, b, jobManager, stateStore } = await makeApp();
    const blocker = jobManager.register({ caseId: "c1", kind: "import", label: "evtx import" });
    await blocker.ready;
    const run = request(app)
      .post("/cases/c1/second-opinion")
      .send({})
      .then((r) => r);
    await new Promise((resolve) => setTimeout(resolve, 50));
    const state = emptyState("c1");
    state.forensicTimeline.push({
      id: "e1",
      timestamp: "2026-06-10T00:00:00.000Z",
      description: "beaconing to 1.2.3.4",
      severity: "High",
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
    });
    await stateStore.save(state);
    await jobManager.finish(blocker.jobId);
    const res = await run;
    expect(res.status).toBe(200);
    expect(res.body.skipped).toBeUndefined();
    expect(b.calls).toBeGreaterThan(0);
  });
});
