import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import type { JobLedgerStore } from "../../src/analysis/jobLedgerStore.js";
import type { Job } from "../../src/analysis/jobRegistry.js";
import { MockProvider } from "../../src/providers/provider.js";
import { pollFor } from "../helpers/poll.js";

// JobManager.cancel() REJECTS the admission promise it hands out as RegisteredJob.ready ("job
// cancelled before it started"). That rejection only reaches a job still queued — once admitted
// the deferred is already resolved and reject() is a no-op. So every consumer awaiting `ready`
// must keep that await under a rejection handler, or the AbortError escapes into a floated
// promise: Express 4 does not adopt an async handler's returned promise, and the server installs
// no process-level unhandledRejection listener, so a single escape kills the server and every
// in-flight case operation with it.
//
// These cover the two places that could not survive it — the /synthesize route, whose await sat
// outside its try, and JobManager.resume(), which left its admission unguarded across the ledger
// write.

/** Records unhandled rejections for one test. Un-recorded, these are fatal in production. */
function captureUnhandledRejections() {
  const seen: unknown[] = [];
  const onRejection = (reason: unknown) => seen.push(reason);
  process.on("unhandledRejection", onRejection);
  return { seen, stop: () => process.off("unhandledRejection", onRejection) };
}

let rejections: ReturnType<typeof captureUnhandledRejections>;

beforeEach(() => {
  rejections = captureUnhandledRejections();
});

afterEach(() => {
  rejections.stop();
});

/** Give Node's unhandled-rejection detection time to reach the listener above. */
async function settleRejectionDetection() {
  for (let i = 0; i < 10; i += 1) await new Promise((resolve) => setImmediate(resolve));
}

function describeRejections(seen: unknown[]): string {
  return seen.map((r) => (r instanceof Error ? `${r.name}: ${r.message}` : String(r))).join("; ");
}

async function harness() {
  // perCaseConcurrency 1 mirrors the ledger-backed default, so a second job for the same case
  // stays queued — the only state in which cancel() rejects an admission.
  const jobManager = new JobManager({ perCaseConcurrency: 1, globalConcurrency: 1 });
  await jobManager.ready();
  const root = await mkdtemp(join(tmpdir(), "dfir-cancel-crash-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined,
    synthesisProvider: new MockProvider("stub", "{}"),
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, { stateStore, pipeline, jobManager, aiConfigured: true });
  return { app, jobManager };
}

describe("cancelling a job that never started", () => {
  it("answers POST /cases/:id/synthesize with 499 instead of killing the server", async () => {
    const { app, jobManager } = await harness();
    await request(app)
      .post("/cases")
      .send({ caseId: "INC-1", name: "case", investigator: "alice", aiProvider: "anthropic" });

    // Occupy the case's only concurrency slot with an unrelated job that never finishes, so the
    // synthesis job below is admitted nowhere and parks in "queued".
    jobManager.register({ caseId: "INC-1", kind: "import" });

    // .then() is what actually dispatches a supertest request — keep the promise, don't await it:
    // the handler is parked inside `await job.ready`.
    const synthesize = request(app)
      .post("/cases/INC-1/synthesize")
      .send({})
      .then((res) => res);

    const queued = await pollFor("the synthesis job to reach 'queued'", async () =>
      jobManager.list("INC-1").find((job) => job.kind === "synthesis" && job.status === "queued"),
    );

    const cancelled = await request(app).post(`/api/jobs/${queued.id}/cancel`);
    expect(cancelled.status).toBe(200);

    // Assert this BEFORE awaiting the response: unfixed, the handler never answers at all, so the
    // escaped AbortError is the failure worth reporting rather than a request timeout.
    await settleRejectionDetection();
    expect(describeRejections(rejections.seen)).toBe("");

    const res = await synthesize;
    expect(res.status).toBe(499);
    expect(res.body.error).toBe("synthesis cancelled");
  });

  it("keeps a resumed job's admission handled while its ledger write is in flight", async () => {
    // resume() publishes the admission into this.admissions BEFORE awaiting the ledger write, and
    // only attaches a handler afterwards via runResumedJob. A cancel landing inside that window
    // rejects a promise nobody is listening to yet.
    let openWindow: () => void = () => {};
    let closeWindow: () => void = () => {};
    const windowOpen = new Promise<void>((resolve) => {
      openWindow = resolve;
    });
    const windowClosed = new Promise<void>((resolve) => {
      closeWindow = resolve;
    });

    const ledger: Pick<JobLedgerStore, "listAll" | "insert" | "update" | "prune"> = {
      listAll: async () => [],
      insert: async () => ({ inserted: true }),
      prune: async () => 0,
      update: async (job: Job) => {
        // Only the requeue write inside resume() carries "queued"; register() inserts, the
        // scheduler writes "running", fail() writes "failed" and cancel() writes "cancelled" —
        // so this stalls exactly the window under test and lets the cancel through.
        if (job.status !== "queued") return;
        openWindow();
        await windowClosed;
      },
    };

    const jobManager = new JobManager({
      ledger: ledger as JobLedgerStore,
      perCaseConcurrency: 1,
      globalConcurrency: 1,
    });
    await jobManager.ready();
    jobManager.registerResumeHandler("import", async () => {}, { cancellable: () => true });

    const registered = jobManager.register({
      caseId: "INC-2",
      kind: "import",
      cancellable: true,
      resumable: true,
      maxRetries: 2,
    });
    await registered.durable;
    await jobManager.fail(registered.jobId, new Error("interrupted"), { retryable: true });

    const resuming = jobManager.resume(registered.jobId);
    await windowOpen;
    await jobManager.cancel(registered.jobId);

    await settleRejectionDetection();
    expect(describeRejections(rejections.seen)).toBe("");

    closeWindow();
    await resuming;
  });
});
