import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import { MockProvider } from "../../src/providers/provider.js";
import { stopConclusionJobs } from "../../src/routes/caseCloseJobs.js";
import { pollFor } from "../helpers/poll.js";

// #2437 Part B: a synthesis still running when the case is closed or archived used to land its
// conclusions in the frozen case. Closing or archiving now cancels the case's running synthesis,
// deep-pass and enrichment jobs. Import, MCP and cloud-collect jobs are left alone (#2404), and
// the non-cancellable kinds (#2425: Sigma re-grade, Jev review, containment check) finish.

/** A synthesize that never resolves on its own: it waits until its job's signal aborts. */
function hangingSynthesize(calls: { started: number }) {
  return (_caseId: string, opts?: { signal?: AbortSignal }) =>
    new Promise<never>((_resolve, reject) => {
      calls.started += 1;
      const signal = opts?.signal;
      const abort = () => reject(Object.assign(new Error("aborted"), { name: "AbortError" }));
      if (signal?.aborted) return abort();
      signal?.addEventListener("abort", abort, { once: true });
    });
}

async function harness() {
  const jobManager = new JobManager({ perCaseConcurrency: 4, globalConcurrency: 4 });
  await jobManager.ready();
  const store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-2437b-")));
  const stateStore = new StateStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined,
    synthesisProvider: new MockProvider("stub", "{}"),
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const calls = { started: 0 };
  Object.assign(pipeline, { synthesize: hangingSynthesize(calls) });
  const app = createApp(store, { stateStore, pipeline, jobManager, aiConfigured: true });
  await request(app)
    .post("/cases")
    .send({ caseId: "c1", name: "n", investigator: "i", aiProvider: "anthropic" });
  return { app, jobManager, stateStore, calls };
}

function startSynthesis(app: Awaited<ReturnType<typeof harness>>["app"]) {
  return request(app)
    .post("/cases/c1/synthesize")
    .send({})
    .then((res) => res);
}

async function runningSynthesis(jobManager: JobManager, calls: { started: number }) {
  await pollFor("the synthesize call to start", async () => (calls.started > 0 ? true : undefined));
  return pollFor("the synthesis job to be running", async () =>
    jobManager.list("c1").find((j) => j.kind === "synthesis" && j.status === "running"),
  );
}

describe("closing or archiving a case stops the analysis running on it (#2437)", () => {
  it("closing cancels a running synthesis, which answers 499 and writes no conclusions", async () => {
    const { app, jobManager, stateStore, calls } = await harness();
    const before = JSON.stringify((await stateStore.load("c1")).findings);
    const pending = startSynthesis(app);
    const job = await runningSynthesis(jobManager, calls);

    expect((await request(app).patch("/cases/c1/status").send({ status: "closed" })).status).toBe(200);
    expect(jobManager.get(job.id)?.status).toBe("cancelled");
    const res = await pending;
    expect(res.status).toBe(499);
    expect(JSON.stringify((await stateStore.load("c1")).findings)).toBe(before);
  });

  it("closing leaves a running import job alone, and it still finishes", async () => {
    const { app, jobManager } = await harness();
    const imp = jobManager.register({ caseId: "c1", kind: "import", label: "import" });
    await imp.ready;
    expect((await request(app).patch("/cases/c1/status").send({ status: "closed" })).status).toBe(200);
    expect(jobManager.get(imp.jobId)?.status).toBe("running");
    await jobManager.finish(imp.jobId);
    expect(jobManager.get(imp.jobId)?.status).toBe("succeeded");
  });

  it("archiving an open case with removeFromList cancels its running synthesis", async () => {
    const { app, jobManager, calls } = await harness();
    const pending = startSynthesis(app);
    const job = await runningSynthesis(jobManager, calls);
    const res = await request(app).post("/cases/c1/archive").send({ removeFromList: true });
    expect(res.status).toBe(200);
    expect(res.body.removedFromList).toBe(true);
    expect(jobManager.get(job.id)?.status).toBe("cancelled");
    expect((await pending).status).toBe(499);
  });

  it("leaves non-cancellable and out-of-scope kinds running and never throws", async () => {
    const { jobManager } = await harness();
    const sigma = jobManager.register({ caseId: "c1", kind: "sigma-regrade", label: "sigma" });
    const mcp = jobManager.register({ caseId: "c1", kind: "mcp", label: "mcp", cancellable: true });
    const enrich = jobManager.register({ caseId: "c1", kind: "enrichment", label: "e", cancellable: true });
    const deep = jobManager.register({ caseId: "c1", kind: "deep-pass", label: "d", cancellable: true });
    await Promise.all([sigma.ready, mcp.ready, enrich.ready, deep.ready]);
    const stopped = await stopConclusionJobs({ options: { jobManager } }, "c1");
    expect(stopped).toBe(2);
    expect(jobManager.get(sigma.jobId)?.status).toBe("running");
    expect(jobManager.get(mcp.jobId)?.status).toBe("running");
    expect(jobManager.get(enrich.jobId)?.status).toBe("cancelled");
    expect(jobManager.get(deep.jobId)?.status).toBe("cancelled");
    expect(await stopConclusionJobs({ options: {} }, "c1")).toBe(0);
  });
});
