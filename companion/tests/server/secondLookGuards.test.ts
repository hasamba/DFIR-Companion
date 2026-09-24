import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { MockProvider } from "../../src/providers/provider.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { pollFor } from "../helpers/poll.js";

// The second look never runs twice at once for the same case (#1576). Its re-synthesis is forced,
// so two overlapping presses would both plan the same promotions from the pre-promotion state and
// both pay for a full synthesis — the same double bill the Jev review's guard stops (#1551).

type Run = { resolve: () => void; reject: (e: Error) => void };

const RESULT = {
  promoted: 0,
  leads: [],
  shapeCapped: 0,
  truncated: false,
  resynthesized: false,
  summary: "s",
};

async function harness(ids: string[] = ["c1"]) {
  const store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-secondlook-guard-")));
  const stateStore = new StateStore(store);
  for (const caseId of ids) {
    await store.createCase({ caseId, name: "n", investigator: "i", aiProvider: "mock" });
    await stateStore.save(emptyState(caseId));
  }
  const provider = new MockProvider("mock", "{}");
  const pipeline = buildRuntimePipeline({
    provider,
    synthesisProvider: provider,
    stateStore,
    store,
    imageLoader: async () => ({ base64: "A", mimeType: "image/webp" }),
  });

  // Every run parks here until the test settles it, so "in flight" is a state the test controls
  // rather than a timing window it hopes to hit.
  const runs: Run[] = [];
  let calls = 0;
  pipeline.secondLook = () => {
    calls += 1;
    return new Promise((resolve, reject) => {
      runs.push({ resolve: () => resolve(RESULT), reject });
    });
  };

  const app = createApp(store, {
    pipeline,
    stateStore,
    aiConfigured: true,
    superTimelineStore: new SuperTimelineStore(store),
  });
  return { app, runs, calls: () => calls };
}

/** Resolves once `runs` holds `n` parked runs, so a POST is known to be past the guard. */
async function parked(runs: Run[], n: number): Promise<void> {
  await pollFor(
    () => `${n} parked second-look run(s), saw ${runs.length}`,
    async () => (runs.length >= n ? true : undefined),
  );
  expect(runs.length).toBe(n);
}

describe("the second look's concurrent-run guard (#1576)", () => {
  it("refuses a second run for the same case while the first is in flight", async () => {
    const { app, runs, calls } = await harness();
    const first = request(app)
      .post("/cases/c1/second-look")
      .send({})
      .then((r) => r);
    await parked(runs, 1);

    const second = await request(app).post("/cases/c1/second-look").send({});
    expect(second.status).toBe(409);
    expect(String(second.body.error)).toMatch(/already running/);
    expect(calls()).toBe(1);

    runs[0].resolve();
    expect((await first).status).toBe(200);

    // Settled, so the case is free again.
    const third = request(app)
      .post("/cases/c1/second-look")
      .send({})
      .then((r) => r);
    await parked(runs, 2);
    runs[1].resolve();
    expect((await third).status).toBe(200);
  });

  it("releases the case when the run throws", async () => {
    const { app, runs } = await harness();
    const first = request(app)
      .post("/cases/c1/second-look")
      .send({})
      .then((r) => r);
    await parked(runs, 1);
    runs[0].reject(new Error("super-timeline unavailable"));
    expect((await first).status).toBe(500);

    const next = request(app)
      .post("/cases/c1/second-look")
      .send({})
      .then((r) => r);
    await parked(runs, 2);
    runs[1].resolve();
    expect((await next).status).toBe(200);
  });

  it("holds the lock per case: two different cases run at the same time", async () => {
    const { app, runs } = await harness(["c1", "c2"]);
    const a = request(app)
      .post("/cases/c1/second-look")
      .send({})
      .then((r) => r);
    const b = request(app)
      .post("/cases/c2/second-look")
      .send({})
      .then((r) => r);
    await parked(runs, 2);
    runs.forEach((r) => r.resolve());
    expect((await a).status).toBe(200);
    expect((await b).status).toBe(200);
  });
});
