import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { ForensicGateControlStore } from "../../src/analysis/forensicGateControl.js";
import { SynthMetaStore } from "../../src/analysis/synthMeta.js";
import { ImportLock } from "../../src/analysis/importLock.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import { MockProvider } from "../../src/providers/provider.js";
import { pollFor, POLL_TIMEOUT_MS } from "../helpers/poll.js";

// #2404, the decision recorded in the PR: closing a case while an import runs lets the import FINISH
// AND BE RECORDED — evidence is never dropped — but the automatic re-synthesis that follows an import
// does not write AI conclusions into the now-closed case. The conclusions are marked out of date
// instead, so reopening says "press Re-synthesize".

const ISO = "2026-05-02T10:00:00Z";
const THOR =
  [
    { level: "Warning", module: "Filescan", message: "Suspicious file", time: ISO, file: "C:\\Temp\\a.exe" },
    { level: "Notice", module: "Filescan", message: "Noticed file", time: ISO, file: "C:\\Temp\\b.exe" },
  ]
    .map((r) => JSON.stringify(r))
    .join("\n") + "\n";

const SYNTH = JSON.stringify({
  findings: [],
  iocs: [],
  mitreTechniques: [],
  forensicEvents: [],
  threadsOpened: [],
  threadsClosed: [],
  timelineNote: "",
  summary: "s",
});

describe("closing a case while an import runs (#2404)", () => {
  it(
    "the import finishes and is recorded; no re-synthesis runs; the conclusions are marked out of date",
    async () => {
      const store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-2404-close-")));
      const stateStore = new StateStore(store);
      const superTimelineStore = new SuperTimelineStore(store);
      const importMetaStore = new ImportMetaStore(store);
      const provider = new MockProvider("mock", SYNTH);
      const pipeline = buildRuntimePipeline({
        provider,
        synthesisProvider: provider,
        stateStore,
        store,
        imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
      });
      const importLock = new ImportLock();
      const jobManager = new JobManager();
      const app = createApp(store, {
        pipeline,
        stateStore,
        superTimelineStore,
        importMetaStore,
        forensicGateControlStore: new ForensicGateControlStore(store),
        importLock,
        jobManager,
        aiConfigured: true,
      });
      await request(app)
        .post("/cases")
        .send({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
      await request(app).post("/cases/c1/ai-control").send({ enabled: true });

      const release = await importLock.acquire("c1");
      const res = await request(app)
        .post("/cases/c1/import-thor")
        .send({ text: THOR, filename: "thor.json" });
      expect(res.status).toBe(202);
      expect((await request(app).patch("/cases/c1/status").send({ status: "closed" })).status).toBe(200);
      release();

      // Evidence first: the import lands in the timeline and its record is written.
      await pollFor("the import to record its import-meta", async () => {
        const meta = await importMetaStore.load("c1");
        return meta?.lastImportFile === res.body.file ? true : undefined;
      });
      expect((await superTimelineStore.query("c1", {})).total).toBe(2);
      const synthMeta = new SynthMetaStore(store);
      const marked = await pollFor("the conclusions to be marked out of date", async () => {
        const meta = await synthMeta.load("c1");
        return meta.outOfDate ?? undefined;
      });
      expect(marked.reason).toMatch(/after the case was closed/);
      expect(jobManager.list("c1").filter((j) => j.kind === "synthesis")).toEqual([]);
    },
    POLL_TIMEOUT_MS * 2,
  );
});
