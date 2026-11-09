import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { SynthMetaStore } from "../../src/analysis/synthMeta.js";
import { MockProvider } from "../../src/providers/provider.js";
import { ActivityLogStore } from "../../src/analysis/activityLog.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import { pollFor } from "../helpers/poll.js";

// #2407: the second look runs as a job, so its forced re-synthesis takes the case's one job slot
// instead of running beside another synthesis. Harness copied from secondLookRoute.test.ts.
// The second look at the route (#1554). It stopped being the tail of every synthesis and became a
// button, so the properties worth pinning here are the ones only the route can show: the preview
// changes nothing, the default run re-synthesizes, the opt-out promotes without re-synthesizing,
// and an install with no raw record says so instead of reporting an empty sweep as a success.

const ev = (id: string, timestamp: string, description: string): ForensicEvent => ({
  id,
  timestamp,
  description,
  severity: "High",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
});

// A schema-valid synthesis delta whose evidenceRequest names the keyword only the raw row carries.
const DELTA = JSON.stringify({
  findings: [],
  iocs: [],
  mitreTechniques: [],
  forensicEvents: [],
  threadsOpened: [],
  threadsClosed: [],
  timelineNote: "",
  summary: "s",
  evidenceRequests: [{ keywords: ["rsync"], reason: "rows the prompt did not show" }],
});

async function harness(opts: { withSuperTimeline?: boolean; jobManager?: JobManager } = {}) {
  const withSuper = opts.withSuperTimeline !== false;
  const store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-secondlook-route-")));
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
  const stateStore = new StateStore(store);
  const seeded = emptyState("c1");
  seeded.forensicTimeline.push(
    ev("e1", "2026-05-20T09:00:00.000Z", "powershell -enc"),
    ev("e2", "2026-05-20T11:00:00.000Z", "net use"),
  );
  await stateStore.save(seeded);

  const superTimelineStore = new SuperTimelineStore(store);
  await superTimelineStore.append("c1", [
    ev("rawhit", "2026-05-20T10:00:00.000Z", "rsync -a /data nfs-01:/backup archive.zip"),
    ev("rawmiss", "2026-05-20T10:05:00.000Z", "unrelated noise"),
  ]);

  const provider = new MockProvider("mock", DELTA);
  const pipeline = buildRuntimePipeline({
    provider,
    synthesisProvider: provider,
    stateStore,
    store,
    imageLoader: async () => ({ base64: "A", mimeType: "image/webp" }),
  });
  // The route gates on the APP's super-timeline option, the way the Jev review does — omitting it
  // is how an install without a raw record is modelled here.
  const app = createApp(store, {
    pipeline,
    stateStore,
    aiConfigured: true,
    activityLogStore: new ActivityLogStore(store),
    ...(withSuper ? { superTimelineStore } : {}),
    ...(opts.jobManager ? { jobManager: opts.jobManager } : {}),
  });
  return { app, stateStore, store, synthMetaStore: new SynthMetaStore(store), superTimelineStore, provider };
}

/** One synthesis, so the model's own evidence request is on the synth-meta for the button to read. */
async function seedSynthesis(app: Awaited<ReturnType<typeof harness>>["app"]): Promise<void> {
  const res = await request(app).post("/cases/c1/synthesize").send({});
  expect(res.status).toBe(200);
}

describe("POST /cases/:id/second-look runs as a job (#2407)", () => {
  it("registers a second-look job that ends succeeded", async () => {
    const jobManager = new JobManager();
    const { app } = await harness({ jobManager });
    await seedSynthesis(app);
    const res = await request(app).post("/cases/c1/second-look").send({});
    expect(res.status).toBe(200);
    const job = jobManager.list("c1").find((j) => j.kind === "second-look");
    expect(job).toMatchObject({
      status: "succeeded",
      cancellable: true, // #2425: Cancel is closed only for the promotion window
      label: "second look + re-synthesis",
    });
  });

  it("waits behind a synthesis already holding the case's slot", async () => {
    const jobManager = new JobManager({ globalConcurrency: 1, perCaseConcurrency: 1 });
    const { app, stateStore } = await harness({ jobManager });
    await seedSynthesis(app);
    const busy = jobManager.register({ caseId: "c1", kind: "synthesis", label: "synthesis" });
    await busy.ready;

    const pending = request(app)
      .post("/cases/c1/second-look")
      .send({})
      .then((r) => r);
    await pollFor("the second look to queue", async () =>
      jobManager.list("c1").find((j) => j.kind === "second-look" && j.status === "queued") ? true : undefined,
    );
    // Nothing is promoted while the other synthesis holds the slot.
    expect((await stateStore.load("c1")).forensicTimeline.some((e) => e.id === "rawhit")).toBe(false);

    await jobManager.finish(busy.jobId);
    const res = await pending;
    expect(res.status).toBe(200);
    expect(res.body.promoted).toBe(1);
    expect(jobManager.list("c1").find((j) => j.kind === "second-look")?.status).toBe("succeeded");
  });

  it("fails the job when the run throws", async () => {
    const jobManager = new JobManager();
    const { app, stateStore } = await harness({ jobManager });
    await seedSynthesis(app);
    stateStore.save = async () => {
      throw new Error("disk full (staged)");
    };
    const res = await request(app).post("/cases/c1/second-look").send({ resynthesize: false });
    expect(res.status).toBe(500);
    const job = jobManager.list("c1").find((j) => j.kind === "second-look");
    expect(job).toMatchObject({ status: "failed", failure: { code: "second_look_failed" } });
  });
});

// #2425: Second Look is cancellable, with safe stop points. Cancel is CLOSED while the promotion
// writes rows (a cancel frees the case's slot at once, and must never do so mid-write); the sweep
// before it and the re-synthesis after it stop on the job's signal. A run that promoted rows and
// then did not finish its re-synthesis still records the sweep and marks the conclusions out of date.
describe("POST /cases/:id/second-look is cancellable at safe points (#2425)", () => {
  it("a queued second look can be cancelled: 499, nothing promoted", async () => {
    const jobManager = new JobManager({ globalConcurrency: 1, perCaseConcurrency: 1 });
    const { app, stateStore } = await harness({ jobManager });
    await seedSynthesis(app);
    const busy = jobManager.register({ caseId: "c1", kind: "synthesis", label: "synthesis" });
    await busy.ready;
    const pending = request(app)
      .post("/cases/c1/second-look")
      .send({})
      .then((r) => r);
    const queued = await pollFor("the second look to queue", async () =>
      jobManager.list("c1").find((j) => j.kind === "second-look" && j.status === "queued"),
    );
    expect(queued.cancellable).toBe(true);
    expect((await jobManager.cancel(queued.id)).ok).toBe(true);
    const res = await pending;
    expect(res.status).toBe(499);
    expect(res.body.promoted).toBe(0);
    await jobManager.finish(busy.jobId);
    expect((await stateStore.load("c1")).forensicTimeline.some((e) => e.id === "rawhit")).toBe(false);
  });

  it("refuses Cancel while the promotion writes rows", async () => {
    const jobManager = new JobManager();
    const { app, stateStore } = await harness({ jobManager });
    await seedSynthesis(app);
    const seen: Array<{ cancellable?: boolean; cancel?: string }> = [];
    const save = stateStore.save.bind(stateStore);
    stateStore.save = async (state) => {
      const job = jobManager.list("c1").find((j) => j.kind === "second-look" && j.status === "running");
      if (job && seen.length === 0) {
        const result = await jobManager.cancel(job.id);
        seen.push({ cancellable: job.cancellable, cancel: result.ok ? "ok" : result.reason });
      }
      return save(state);
    };
    const res = await request(app).post("/cases/c1/second-look").send({ resynthesize: false });
    expect(res.status).toBe(200);
    expect(res.body.promoted).toBe(1);
    expect(seen).toEqual([{ cancellable: false, cancel: "not-cancellable" }]);
    expect(jobManager.list("c1").find((j) => j.kind === "second-look")?.status).toBe("succeeded");
  });

  it("a cancel during the re-synthesis answers 499, records the sweep and marks the conclusions out of date", async () => {
    const jobManager = new JobManager();
    const { app, stateStore, synthMetaStore, provider } = await harness({ jobManager });
    await seedSynthesis(app);
    const analyze = provider.analyze.bind(provider);
    provider.analyze = async (req) => {
      const job = jobManager.list("c1").find((j) => j.kind === "second-look" && j.status === "running");
      if (job) await jobManager.cancel(job.id);
      return analyze(req);
    };
    const res = await request(app).post("/cases/c1/second-look").send({});
    expect(res.status).toBe(499);
    expect(res.body.promoted).toBe(1);
    expect((await stateStore.load("c1")).forensicTimeline.some((e) => e.id === "rawhit")).toBe(true);
    const meta = await synthMetaStore.load("c1");
    expect(meta?.secondLook?.promoted).toBe(1);
    expect(meta?.outOfDate).toBeTruthy();
    expect(jobManager.list("c1").find((j) => j.kind === "second-look")?.status).toBe("cancelled");
  });

  it("a failed re-synthesis after promotion records the sweep and marks the conclusions out of date", async () => {
    const jobManager = new JobManager();
    const { app, synthMetaStore, provider } = await harness({ jobManager });
    await seedSynthesis(app);
    provider.analyze = async () => {
      throw new Error("provider down (staged)");
    };
    const res = await request(app).post("/cases/c1/second-look").send({});
    expect(res.status).toBe(500);
    expect(res.body.promoted).toBe(1);
    const meta = await synthMetaStore.load("c1");
    expect(meta?.secondLook?.promoted).toBe(1);
    expect(meta?.outOfDate).toBeTruthy();
    expect(jobManager.list("c1").find((j) => j.kind === "second-look")?.status).toBe("failed");
  });
});
