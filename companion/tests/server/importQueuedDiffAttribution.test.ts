import { describe, it, expect } from "vitest";
import type { Express } from "express";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import { pollFor, POLL_TIMEOUT_MS } from "../helpers/poll.js";

// An import's "+N events" must count only what THAT import added.
//
// The import route answers 202 immediately and does the work in the background, behind the job
// queue (perCaseConcurrency is 1, so a case runs one import at a time). The diff that produces
// "+N events" is taken against a snapshot of the investigation state. If that snapshot is taken
// when the request arrives, an import that then waits in the queue diffs against a state from
// BEFORE the imports ahead of it ran, and claims their events as its own: drop 17 artifact files
// on the dashboard at once and the last one reports the whole batch (observed: a 2-row registry
// artifact reporting "308 forensic events · 2 super-timeline events").
//
// The super-timeline count never had the bug — append() returns what it actually inserted, and the
// earlier imports had already written their own rows — which is why the two counts disagreed and
// made the over-attribution visible. So the invariant this test states is the one the two counts
// share: for a single-file import both must equal that file's own event count.
//
// The snapshot therefore belongs AFTER the queue admits the import (tracking.start() awaits
// job.ready), not when the request is accepted.

const HUNT = (ts: string, rule: string) => [
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
];

// Two files, one event each, distinct in both time and description so neither correlation nor the
// super-timeline's content dedup can merge them — the counts below then mean what they say.
const FIRST = {
  filename: "first.json",
  text: JSON.stringify(HUNT("2023-01-02T10:00:00.000Z", "First Encoded PowerShell Command Line")),
};
const SECOND = {
  filename: "second.json",
  text: JSON.stringify(HUNT("2023-01-03T11:22:33.000Z", "Second Encoded PowerShell Command Line")),
};

async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-import-queue-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const superTimelineStore = new SuperTimelineStore(store);
  const importMetaStore = new ImportMetaStore(store);
  // One import at a time per case — the production setting, and what makes the second import wait.
  const jobManager = new JobManager({ perCaseConcurrency: 1 });
  // No-AI pipeline: the deterministic chainsaw importer populates the timeline with no model call.
  const pipeline = buildRuntimePipeline({
    provider: undefined,
    synthesisProvider: undefined,
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, { pipeline, stateStore, importMetaStore, superTimelineStore, jobManager });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, stateStore, superTimelineStore, importMetaStore, jobManager };
}

async function startImport(app: Express, file: { filename: string; text: string }): Promise<string> {
  const res = await request(app).post("/cases/c1/import").send(file);
  expect(res.status).toBe(202);
  expect(typeof res.body.file).toBe("string");
  return res.body.file as string;
}

describe("a queued import counts only its own events", () => {
  it(
    "does not attribute the events of the imports ahead of it in the queue",
    async () => {
      const { app, stateStore, superTimelineStore, importMetaStore, jobManager } = await makeApp();

      // Hold the case's only slot so BOTH imports queue: the second one is accepted, and waits,
      // while the first still has not run. That is the state the stale snapshot came from.
      const blocker = jobManager.register({ caseId: "c1", kind: "enrichment", label: "holds the slot" });
      await blocker.durable;
      const firstFile = await startImport(app, FIRST);
      const secondFile = await startImport(app, SECOND);
      expect(secondFile).not.toBe(firstFile);

      // Release the queue: the first import runs to completion (its events land), then the second.
      await jobManager.finish(blocker.jobId);

      // import-meta is written at the end of an import cycle and carries that cycle's own stored
      // filename, so matching the SECOND file proves both cycles finished.
      let seen = "(nothing)";
      await pollFor(
        () => `import-meta to record the '${secondFile}' import cycle (last saw '${seen}')`,
        async () => {
          seen = (await importMetaStore.load("c1")).lastImportFile || "(nothing)";
          return seen === secondFile ? true : undefined;
        },
      );

      const state = await stateStore.load("c1");
      expect(state.forensicTimeline.length).toBe(2); // both files landed — the counts below are not vacuous
      expect((await superTimelineStore.query("c1", { limit: 100 })).total).toBe(2);

      const meta = await importMetaStore.load("c1");
      expect(meta.addedCount).toBe(1); // the second file's own single event, not the batch
      expect(meta.superTimelineAddedCount).toBe(1);
      expect(meta.lastDiff?.added.map((e) => e.description).join(" | ")).toContain("Second");
      expect(meta.lastDiff?.added.map((e) => e.description).join(" | ")).not.toContain("First");
    },
    POLL_TIMEOUT_MS * 2,
  );
});
