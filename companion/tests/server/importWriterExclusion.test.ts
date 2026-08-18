import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { ImportLock } from "../../src/analysis/importLock.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import { pollFor, POLL_TIMEOUT_MS } from "../helpers/poll.js";

// One import writer per case, whatever the path and whatever the job settings.
//
// The job queue is not enough on its own: /push, the MCP ingest and the Velociraptor monitors never
// queue at all, and DFIR_JOBS_PER_CASE is an operator setting whose value above 1 makes admission
// stop meaning exclusivity. Both gaps end the same way — a foreign write lands between an import's
// snapshot and its diff, so its events are counted as that import's own and are swept into the undo
// checkpoint the import pushes. These tests pin the lock that closes them.

const PUSH_TOKEN = "test-push-token";

const chainsaw = (rule: string, ts: string) =>
  JSON.stringify([
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
              TimeCreated: { "#attributes": { SystemTime: ts } },
            },
            EventData: {
              UtcTime: ts.replace("T", " ").replace("Z", ""),
              Image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
              CommandLine: "powershell.exe -nop -w hidden -enc SQBFAFgA",
              ParentImage: "C:\\Program Files\\Microsoft Office\\winword.exe",
            },
          },
        },
      },
      rule: { name: rule, level: "high", tags: ["attack.execution", "attack.t1059.001"] },
      timestamp: ts,
    },
  ]);

const BASELINE = chainsaw("Baseline Encoded PowerShell Command Line", "2023-02-01T08:00:00.000Z");
const PUSHED = chainsaw("Pushed Encoded PowerShell Command Line", "2023-02-01T09:00:00.000Z");
const FIRST = chainsaw("First Encoded PowerShell Command Line", "2023-01-02T10:00:00.000Z");
const SECOND = chainsaw("Second Encoded PowerShell Command Line", "2023-01-03T11:22:33.000Z");

async function makeApp(opts: { importLock?: ImportLock; perCaseConcurrency?: number } = {}) {
  const root = await mkdtemp(join(tmpdir(), "dfir-import-excl-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const superTimelineStore = new SuperTimelineStore(store);
  const importMetaStore = new ImportMetaStore(store);
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
    pushToken: PUSH_TOKEN,
    ...(opts.importLock ? { importLock: opts.importLock } : {}),
    ...(opts.perCaseConcurrency
      ? { jobManager: new JobManager({ perCaseConcurrency: opts.perCaseConcurrency }) }
      : {}),
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, stateStore, importMetaStore };
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

describe("one import writer per case", () => {
  it(
    "makes a /push ingest wait for the import section, then run it",
    async () => {
      // Injecting the lock lets the test BE the import that is mid-section: /push takes no job, so
      // this is the only thing that can hold it back.
      const importLock = new ImportLock();
      const { app, stateStore } = await makeApp({ importLock });
      const push = (text: string, filename: string) =>
        request(app)
          .post("/cases/c1/push")
          .set("X-DFIR-Key", PUSH_TOKEN)
          .send({ text, filename, source: "test" });
      const timelineLength = async (): Promise<number> =>
        (await stateStore.load("c1")).forensicTimeline.length;

      // Measure one UNBLOCKED push first. "It did not write yet" only means something against how
      // long this ingest actually takes on this machine — a fixed sleep would pass on a slow box
      // whether or not the lock exists.
      const startedAt = Date.now();
      expect((await push(BASELINE, "baseline.json")).status).toBe(202);
      await pollFor("the baseline push to land", async () => ((await timelineLength()) ? true : undefined));
      const unblockedMs = Date.now() - startedAt;

      const release = await importLock.acquire("c1");
      expect((await push(PUSHED, "pushed.json")).status).toBe(202);

      await sleep(Math.max(250, unblockedMs * 5)); // ample time for an unlocked ingest to finish
      // Still one event: had the push written here, its rows would have landed inside the holder's
      // diff and its undo checkpoint.
      expect(await timelineLength()).toBe(1);

      release();
      await pollFor("the pushed event to land once the import section is free", async () =>
        (await timelineLength()) === 2 ? true : undefined,
      );
      expect(await timelineLength()).toBe(2); // deferred, never dropped
    },
    POLL_TIMEOUT_MS * 3,
  );

  it(
    "keeps each import's count to its own events when the job queue admits several at once",
    async () => {
      // DFIR_JOBS_PER_CASE above 1: both imports are admitted immediately, so admission proves
      // nothing about exclusivity and only the lock keeps their sections apart.
      const { app, stateStore, importMetaStore } = await makeApp({ perCaseConcurrency: 4 });

      const [a, b] = await Promise.all([
        request(app).post("/cases/c1/import").send({ text: FIRST, filename: "first.json" }),
        request(app).post("/cases/c1/import").send({ text: SECOND, filename: "second.json" }),
      ]);
      expect(a.status).toBe(202);
      expect(b.status).toBe(202);

      const state = await pollFor("both imports to land in the forensic timeline", async () => {
        const current = await stateStore.load("c1");
        return current.forensicTimeline.length >= 2 ? current : undefined;
      });
      expect(state.forensicTimeline).toHaveLength(2);

      // Whichever import ran second, it snapshotted after the first released — so it reports one
      // event, not both. Without the lock the two interleave: they both snapshot the empty case, and
      // the run above shows they can also lose one import's events outright (two read-modify-writes
      // of the same state, last save wins) — which is why the assertion on the timeline comes first.
      const meta = await pollFor("the second import cycle to record its summary", async () => {
        const current = await importMetaStore.load("c1");
        return current.lastImportedAt ? current : undefined;
      });
      expect(meta.addedCount).toBe(1);
      expect(meta.lastDiff?.added).toHaveLength(1);
    },
    POLL_TIMEOUT_MS * 2,
  );
});
