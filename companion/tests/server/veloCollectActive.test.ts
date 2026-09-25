import { describe, it, expect, vi, afterEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ArtifactBundleStore } from "../../src/analysis/artifactBundleStore.js";
import { VeloHuntStore } from "../../src/analysis/veloHuntStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { SynthMetaStore } from "../../src/analysis/synthMeta.js";
import { VelociraptorClient, type VqlRunner } from "../../src/integrations/velociraptor/velociraptorApi.js";
import { pollFor, POLL_TIMEOUT_MS } from "../helpers/poll.js";

// #1662: the collect route answers 202 and says "poll hunt-jobs". A re-collect of a hunt that already
// says "imported" keeps saying "imported" until the pass writes "collecting", and the pass writes
// "imported" again BEFORE its last step (the out-of-date mark) and before it lets go of the hunt. So
// "status imported" alone cannot tell a finished collect from one that has not started or not ended.
// `collectActive` must answer "is a collect running right now" for every job, whatever its status.

type JobView = { status: string; collectActive?: boolean };

/** A promise the test resolves by hand, to hold a collect at one exact point. */
function gate(): { wait: Promise<void>; open: () => void } {
  let open = () => {};
  const wait = new Promise<void>((resolve) => (open = resolve));
  return { wait, open };
}

async function makeApp(runner: VqlRunner) {
  const root = await mkdtemp(join(tmpdir(), "dfir-velocollectactive-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined,
    synthesisProvider: undefined,
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const client = new VelociraptorClient(
    {
      apiConfigPath: "/x/api.yaml",
      binary: "velociraptor",
      timeoutMs: 5000,
      maxRows: 1000,
      maxOutputBytes: 1024 * 1024,
      guiUrl: "https://velo.example/",
    },
    runner,
  );
  const app = createApp(store, {
    pipeline,
    stateStore,
    importMetaStore: new ImportMetaStore(store),
    velociraptorClient: client,
    artifactBundleStore: new ArtifactBundleStore(join(dirname(root), "bundles")),
    veloHuntStore: new VeloHuntStore(store),
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  await request(app)
    .post("/cases/c1/velociraptor/run-bundle")
    .send({ bundleId: "best-practice", waitMinutes: 30 });
  return app;
}

const huntJob = async (app: Parameters<typeof request>[0]): Promise<JobView> =>
  (await request(app).get("/cases/c1/velociraptor/hunt-jobs")).body[0];

const collect = async (app: Parameters<typeof request>[0]): Promise<void> => {
  expect((await request(app).post("/cases/c1/velociraptor/collect")).status).toBe(202);
};

const collectDone = (app: Parameters<typeof request>[0]): Promise<JobView> =>
  pollFor(
    () => "the collect to finish",
    async () => {
      const job = await huntJob(app);
      return job?.status === "imported" && job.collectActive === false ? job : undefined;
    },
  );

describe("hunt-jobs says a collect is running, whatever the stored status (#1662)", () => {
  afterEach(() => vi.restoreAllMocks());

  it(
    "a re-collect of an imported hunt reports collectActive before it writes any status",
    async () => {
      let hold: ReturnType<typeof gate> | null = null;
      let reached = false;
      const runner: VqlRunner = async (statements) => {
        const p = statements[0];
        if (p.includes("hunt(") && p.includes("artifacts=["))
          return { rows: [{ Hunt: { HuntId: "H.ACT1", state: "RUNNING" } }], raw: "" };
        if (p.includes("FROM hunts()")) {
          reached = true;
          if (hold) await hold.wait; // the collect's first read, before its "collecting" write
          return { rows: [{ state: "RUNNING" }], raw: "" };
        }
        return { rows: [], raw: "" };
      };
      const app = await makeApp(runner);
      await collect(app);
      await collectDone(app);

      hold = gate();
      reached = false;
      await collect(app);
      await pollFor(
        () => "the re-collect to reach its first read",
        async () => (reached ? true : undefined),
      );
      const during = await huntJob(app);
      expect(during.status).toBe("imported"); // nothing written yet: the stored status is the old one
      expect(during.collectActive).toBe(true);

      hold.open();
      expect((await collectDone(app)).collectActive).toBe(false);
    },
    POLL_TIMEOUT_MS * 2,
  );

  it(
    "a collect still reports collectActive after it writes imported, until its last step lands",
    async () => {
      const hold = gate();
      let marking = false;
      const realMark = SynthMetaStore.prototype.markOutOfDate;
      vi.spyOn(SynthMetaStore.prototype, "markOutOfDate").mockImplementation(async function (
        this: SynthMetaStore,
        ...args: Parameters<SynthMetaStore["markOutOfDate"]>
      ) {
        marking = true;
        await hold.wait;
        return realMark.apply(this, args);
      });
      const runner: VqlRunner = async (statements) => {
        const p = statements[0];
        if (p.includes("hunt(") && p.includes("artifacts=["))
          return { rows: [{ Hunt: { HuntId: "H.ACT2", state: "RUNNING" } }], raw: "" };
        // Client counts change the hunt outcome, so a zero-row collect marks the conclusions (#1612).
        if (p.includes("FROM hunts()"))
          return { rows: [{ state: "RUNNING", stats: { total_clients_scheduled: 1 } }], raw: "" };
        return { rows: [], raw: "" };
      };
      const app = await makeApp(runner);
      await collect(app);
      await pollFor(
        () => "the collect to reach the out-of-date mark",
        async () => (marking ? true : undefined),
      );
      const during = await huntJob(app);
      expect(during.status).toBe("imported"); // already written — but the pass has not ended
      expect(during.collectActive).toBe(true);

      hold.open();
      expect((await collectDone(app)).collectActive).toBe(false);
    },
    POLL_TIMEOUT_MS * 2,
  );
});
