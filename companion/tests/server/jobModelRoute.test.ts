// The jobs popover can only name a model if the route that starts the work puts one on the job.
//
// The model is read from the provider the pipeline HOLDS, not from process.env at render time. A
// synthesis started under one model and finished after Settings switched to another must keep
// naming the model that actually ran it — otherwise the panel rewrites its own history, which is
// exactly the question an analyst opens it to answer after three timed-out runs.
import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import { MockProvider } from "../../src/providers/provider.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { emptyState } from "../../src/analysis/stateTypes.js";

const SYNTH_RESULT = JSON.stringify({
  findings: [],
  iocs: [],
  mitreTechniques: [],
  attackerPath: "",
  summary: "s",
  forensicEvents: [],
  threadsOpened: [],
  threadsClosed: [],
  timelineNote: "",
});

let app: ReturnType<typeof createApp>;
let jobManager: JobManager;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-jobmodel-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined,
    synthesisProvider: new MockProvider("synth", SYNTH_RESULT, "anthropic/claude-sonnet-4"),
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  jobManager = new JobManager({ perCaseConcurrency: 1 });
  app = createApp(store, { pipeline, stateStore, jobManager, aiConfigured: false });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  // synthesize() early-returns on an empty timeline, so seed one event for it to work on.
  const state = emptyState("c1");
  state.forensicTimeline.push({
    id: "e1",
    timestamp: "2026-05-20T09:00:00Z",
    description: "phish opened",
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
  });
  await stateStore.save(state);
});

describe("the model on a job", () => {
  it("names the synthesis model on the synthesis job", async () => {
    await request(app).post("/cases/c1/synthesize").send({});
    const job = jobManager.list("c1").find((j) => j.kind === "synthesis");
    expect(job?.model).toBe("anthropic/claude-sonnet-4");
  });

  it("leaves the model off an enrichment job, which runs no model", async () => {
    const { jobId } = jobManager.register({ caseId: "c1", kind: "enrichment", label: "enrich (WHOIS)" });
    expect(jobManager.get(jobId)!.model).toBeUndefined();
  });
});
