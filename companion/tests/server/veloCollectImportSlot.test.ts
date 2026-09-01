import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { ArtifactBundleStore } from "../../src/analysis/artifactBundleStore.js";
import { VeloHuntStore } from "../../src/analysis/veloHuntStore.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import {
  VelociraptorClient,
  type VqlRunner,
  type VelociraptorApiConfig,
} from "../../src/integrations/velociraptor/velociraptorApi.js";
import { pollFor, POLL_TIMEOUT_MS } from "../helpers/poll.js";

// A hunt collect writes to the same forensic timeline the dashboard's imports write to, and reports
// "+N events" as a diff of that timeline. Two things follow, and this file pins both:
//
//   1. It must hold the case's import slot while it writes. Without that, an import running
//      alongside lands inside the collect's count and inside its undo checkpoint — undoing the
//      collect would take the analyst's import with it.
//   2. Its diff must be measured from the state it finds when the slot is granted, not from the
//      state at the start of the collect (which is minutes of network reads earlier).
//
// It also reports the super-timeline count, which the collect path never used to record: that
// number is what lets the cockpit card cross-check "+N forensic" against what actually landed.

const veloCfg: VelociraptorApiConfig = {
  apiConfigPath: "/x/api.yaml",
  binary: "velociraptor",
  timeoutMs: 5000,
  maxRows: 1000,
  maxOutputBytes: 1024 * 1024,
  guiUrl: "https://velo.example/",
};

// One Pstree row, no uploads — the smallest collect that lands a forensic event.
const runner: VqlRunner = async (statements) => {
  const p = statements[0];
  if (p.includes("artifact_definitions()"))
    return {
      rows: [{ name: "Generic.System.Pstree", description: "Process tree", type: "CLIENT" }],
      raw: "",
    };
  if (p.includes("hunt(") && p.includes("artifacts="))
    return { rows: [{ Hunt: { HuntId: "H.SLOT1", state: "RUNNING" } }], raw: "" };
  if (p.includes("hunt_results(") && p.includes("Pstree"))
    return {
      rows: [
        {
          Name: "rundll32.exe",
          Pid: 4321,
          CommandLine: "rundll32.exe C:\\Users\\Public\\payload.dll,Start",
          Timestamp: "2026-06-01T10:00:00Z",
        },
      ],
      raw: "",
    };
  return { rows: [], raw: "" };
};

// One raw MFT row for the super-only bundle, which never touches the forensic timeline.
const superOnlyRunner: VqlRunner = async (statements) => {
  const p = statements[0];
  if (p.includes("hunt(") && p.includes("artifacts="))
    return { rows: [{ Hunt: { HuntId: "H.SLOT2", state: "RUNNING" } }], raw: "" };
  if (p.includes("hunt_results(") && p.includes("Windows.NTFS.MFT"))
    return {
      rows: [{ OSPath: "C:\\evil.exe", Created0x10: "2026-06-01T00:00:00Z", FileName: "evil.exe" }],
      raw: "",
    };
  return { rows: [], raw: "" };
};

// A one-event chainsaw report — the analyst's own import, which the collect must not count.
const ANALYST_IMPORT = {
  filename: "analyst.json",
  text: JSON.stringify([
    {
      group: "Sigma",
      kind: "individual",
      document: {
        kind: "evtx",
        path: "Sysmon.evtx",
        data: {
          Event: {
            System: {
              Provider: { "#attributes": { Name: "Microsoft-Windows-Sysmon" } },
              EventID: 1,
              Channel: "Microsoft-Windows-Sysmon/Operational",
              Computer: "WIN-DC01.corp.local",
              TimeCreated: { "#attributes": { SystemTime: "2023-01-02T10:00:00.000Z" } },
            },
            EventData: {
              UtcTime: "2023-01-02 10:00:00.000",
              Image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
              CommandLine: "powershell.exe -nop -w hidden -enc SQBFAFgA",
              ParentImage: "C:\\Program Files\\Microsoft Office\\winword.exe",
            },
          },
        },
      },
      rule: {
        name: "Analyst Encoded PowerShell Command Line",
        level: "high",
        tags: ["attack.execution", "attack.t1059.001"],
      },
      timestamp: "2023-01-02T10:00:00.000Z",
    },
  ]),
};

async function makeApp(vqlRunner: VqlRunner = runner) {
  const root = await mkdtemp(join(tmpdir(), "dfir-velo-slot-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const superTimelineStore = new SuperTimelineStore(store);
  const importMetaStore = new ImportMetaStore(store);
  // One import at a time per case — the production setting, and the whole point of the slot.
  const jobManager = new JobManager({ perCaseConcurrency: 1 });
  const veloHuntStore = new VeloHuntStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined,
    synthesisProvider: undefined,
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, {
    pipeline,
    stateStore,
    importMetaStore,
    superTimelineStore,
    jobManager,
    velociraptorClient: new VelociraptorClient(veloCfg, vqlRunner),
    artifactBundleStore: new ArtifactBundleStore(join(dirname(root), "bundles")),
    veloHuntStore,
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, stateStore, superTimelineStore, importMetaStore, jobManager, veloHuntStore };
}

type App = Awaited<ReturnType<typeof makeApp>>["app"];

async function huntJobStatus(app: App): Promise<string> {
  const jobs = await request(app).get("/cases/c1/velociraptor/hunt-jobs");
  return (jobs.body as Array<{ status?: string }>)[0]?.status ?? "no job at all";
}

// The whole hunt job, not just its status — the phase fields are the subject of the #770 test below.
type HuntJobView = {
  status?: string;
  collectPhase?: string;
  collectRows?: number;
  collectActive?: boolean;
};

async function huntJob(app: App): Promise<HuntJobView> {
  const jobs = await request(app).get("/cases/c1/velociraptor/hunt-jobs");
  return (jobs.body as HuntJobView[])[0] ?? {};
}

async function waitForCollect(app: App): Promise<void> {
  let last = "no job at all";
  await pollFor(
    () => `the hunt job to reach a terminal status, last saw "${last}"`,
    async () => {
      last = await huntJobStatus(app);
      if (last === "error") throw new Error("velo hunt collect errored");
      return last === "imported" ? true : undefined;
    },
  );
}

describe("a Velociraptor hunt collect takes the case's import slot", () => {
  it(
    "counts only its own events when an import runs first",
    async () => {
      const { app, stateStore, importMetaStore, jobManager } = await makeApp();

      // Hold the case's only slot, then queue the analyst's import AHEAD of the collect. Both wait.
      const blocker = jobManager.register({ caseId: "c1", kind: "enrichment", label: "holds the slot" });
      await blocker.durable;
      expect((await request(app).post("/cases/c1/import").send(ANALYST_IMPORT)).status).toBe(202);
      await request(app)
        .post("/cases/c1/velociraptor/run-bundle")
        .send({ bundleId: "best-practice", waitMinutes: 30 });
      expect((await request(app).post("/cases/c1/velociraptor/collect")).status).toBe(202);

      // With the slot held, the collect cannot have written anything — it is waiting its turn behind
      // the import, which is itself waiting behind the blocker.
      expect((await stateStore.load("c1")).forensicTimeline).toHaveLength(0);
      expect(await huntJobStatus(app)).not.toBe("imported");

      await jobManager.finish(blocker.jobId); // import runs, then the collect
      await waitForCollect(app);

      const state = await stateStore.load("c1");
      expect(state.forensicTimeline.length).toBeGreaterThan(1); // both landed — the count below is real
      const meta = await importMetaStore.load("c1");
      expect(meta.lastImportKind).toBe("velociraptor"); // the collect wrote the last record
      // Everything except the analyst's one event, and none of its text in the diff.
      expect(meta.addedCount).toBe(state.forensicTimeline.length - 1);
      expect(meta.lastDiff?.added.map((e) => e.description).join(" | ") ?? "").not.toContain("Analyst");
    },
    POLL_TIMEOUT_MS * 2,
  );

  it(
    "records the super-timeline count a collect appended",
    async () => {
      const { app, superTimelineStore, importMetaStore } = await makeApp();
      await request(app)
        .post("/cases/c1/velociraptor/run-bundle")
        .send({ bundleId: "best-practice", waitMinutes: 30 });
      expect((await request(app).post("/cases/c1/velociraptor/collect")).status).toBe(202);
      await waitForCollect(app);

      const meta = await importMetaStore.load("c1");
      const superTotal = (await superTimelineStore.query("c1", { limit: 100 })).total;
      expect(superTotal).toBeGreaterThan(0);
      // The dual-write makes the super-timeline a superset of the forensic import, so for one collect
      // into an empty case the two counts agree. Reporting neither as `undefined` is the point: the
      // cockpit card cannot cross-check a count it never received.
      expect(meta.superTimelineAddedCount).toBe(superTotal);
      expect(meta.superTimelineAddedCount).toBe(meta.addedCount);
    },
    POLL_TIMEOUT_MS * 2,
  );

  it(
    "records the super-timeline count for a super-only bundle, whose forensic count is always 0",
    async () => {
      const { app, stateStore, superTimelineStore, importMetaStore } = await makeApp(superOnlyRunner);
      await request(app)
        .post("/cases/c1/velociraptor/run-bundle")
        .send({ bundleId: "super-timeline-triage" });
      expect((await request(app).post("/cases/c1/velociraptor/collect")).status).toBe(202);
      await waitForCollect(app);

      const superTotal = (await superTimelineStore.query("c1", { limit: 100 })).total;
      expect(superTotal).toBeGreaterThan(0);
      expect((await stateStore.load("c1")).forensicTimeline).toHaveLength(0); // super-only, by design
      const meta = await importMetaStore.load("c1");
      // Without this the card reads "0 forensic events · super-timeline count unavailable" — a
      // super-only collect looks like it imported nothing at all.
      expect(meta.addedCount).toBe(0);
      expect(meta.superTimelineAddedCount).toBe(superTotal);
    },
    POLL_TIMEOUT_MS * 2,
  );
});

// The same slot, from the analyst's side (#770). Holding it is correct; being SILENT about holding it
// is what made a routine wait look like a hang — the card showed a bare "collecting" badge with no
// text, no countdown, and no button for the whole time.
describe("a queued collect says what it is waiting for", () => {
  it(
    "reports the queue wait while it lasts, and stops reporting it once the import lands",
    async () => {
      const { app, jobManager } = await makeApp();
      const blocker = jobManager.register({ caseId: "c1", kind: "enrichment", label: "holds the slot" });
      await blocker.durable;
      await request(app)
        .post("/cases/c1/velociraptor/run-bundle")
        .send({ bundleId: "best-practice", waitMinutes: 30 });
      expect((await request(app).post("/cases/c1/velociraptor/collect")).status).toBe(202);

      // The reads finish quickly against the stub runner; the slot is what it cannot have.
      let seen: HuntJobView = {};
      await pollFor(
        () => `the collect to report a queue wait, last saw ${JSON.stringify(seen)}`,
        async () => {
          seen = await huntJob(app);
          return seen.collectPhase === "queued" ? true : undefined;
        },
      );
      expect(seen.status).toBe("collecting");
      // The row count is what turns "waiting" into "waiting, with N rows already in hand".
      expect(seen.collectRows).toBeGreaterThan(0);
      // And it is genuinely in flight — the claim the card makes rests on this, not on the status.
      expect(seen.collectActive).toBe(true);

      await jobManager.finish(blocker.jobId);
      await waitForCollect(app);

      // Cleared on the way out, or the card would keep explaining a wait that ended.
      const done = await huntJob(app);
      expect(done.status).toBe("imported");
      expect(done.collectPhase).toBeUndefined();
      expect(done.collectRows).toBeUndefined();
    },
    POLL_TIMEOUT_MS * 2,
  );

  // The trap the phase fields walk straight into. A stored "collecting" outlives the process that
  // wrote it: this is a job exactly as a server killed mid-collect leaves it, and no later process is
  // collecting it. Answering from the file would have the card assert an import that stopped hours ago
  // AND withhold the one button that recovers it, since the status never leaves "collecting" by itself.
  it("does not read a stored collecting status as a collect that is still running", async () => {
    const { app, veloHuntStore } = await makeApp();
    await veloHuntStore.upsert("c1", {
      bundleId: "best-practice",
      bundleName: "Best Practice",
      artifacts: ["Generic.System.Pstree"],
      huntId: "H.STRANDED",
      launchedAt: "2026-06-01T00:00:00.000Z",
      waitMinutes: 30,
      collectAt: "2026-06-01T00:30:00.000Z",
      status: "collecting",
      collectPhase: "importing",
      collectRows: 171,
    });

    const job = await huntJob(app);
    expect(job.status).toBe("collecting");
    expect(job.collectActive).toBe(false);
  });
});
