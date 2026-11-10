// #2497, end to end: a CloudTrail upload into a case whose severity gate is High. The merge builds
// the "Cloud coverage gap" note (cloud audit logs, no host telemetry); the demote that follows must
// keep it — at its Medium grade — while the ungraded telemetry still leaves the forensic timeline.
// A second import rebuilds the note in place: still exactly one, same id.
import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import type { Express } from "express";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { ForensicGateControlStore } from "../../src/analysis/forensicGateControl.js";
import { COVERAGE_EVENT_ID } from "../../src/analysis/cloudMetadataAccess.js";
import { pollFor, POLL_TIMEOUT_MS } from "../helpers/poll.js";

const record = (i: number, day: string) => ({
  eventVersion: "1.08",
  userIdentity: {
    type: "IAMUser",
    principalId: "AIDAEXAMPLE",
    arn: "arn:aws:iam::123456789012:user/alice",
    accountId: "123456789012",
    userName: "alice",
  },
  eventTime: `${day}T10:0${i}:00Z`,
  eventSource: "iam.amazonaws.com",
  eventName: "ListUsers",
  awsRegion: "us-east-1",
  sourceIPAddress: "203.0.113.7",
  userAgent: "aws-cli/2.0",
  requestParameters: null,
  responseElements: null,
  requestID: `req-${day}-${i}`,
  eventID: `evt-${day}-${i}`,
  readOnly: true,
  eventType: "AwsApiCall",
  recipientAccountId: "123456789012",
});

const upload = (day: string) => ({
  filename: `cloudtrail-${day}.json`,
  text: JSON.stringify({ Records: [0, 1, 2].map((i) => record(i, day)) }),
});

async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-coverage-gate-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const superTimelineStore = new SuperTimelineStore(store);
  const importMetaStore = new ImportMetaStore(store);
  const forensicGateControlStore = new ForensicGateControlStore(store);
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
    superTimelineStore,
    importMetaStore,
    forensicGateControlStore,
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, stateStore, importMetaStore };
}

async function importAndWait(
  app: Express,
  importMetaStore: ImportMetaStore,
  file: { filename: string; text: string },
) {
  const res = await request(app).post("/cases/c1/import").send(file);
  expect(res.status, JSON.stringify(res.body)).toBe(202);
  const stored = res.body.file as string;
  await pollFor(
    () => `import cycle for '${stored}'`,
    async () => ((await importMetaStore.load("c1")).lastImportFile === stored ? true : undefined),
  );
}

describe("coverage notes survive a High severity gate (#2497)", () => {
  it(
    "keeps the Cloud coverage gap at Medium on a High-gated case, once, across two imports",
    async () => {
      const { app, stateStore, importMetaStore } = await makeApp();
      const put = await request(app).put("/cases/c1/forensic-gate").send({ minSeverity: "High" });
      expect(put.status).toBe(200);

      await importAndWait(app, importMetaStore, upload("2026-03-01"));
      let forensic = (await stateStore.load("c1")).forensicTimeline;
      let notes = forensic.filter((e) => e.id === COVERAGE_EVENT_ID);
      expect(notes).toHaveLength(1);
      expect(notes[0].severity).toBe("Medium");
      expect(notes[0].sources).toContain("Coverage");
      // The ungraded ListUsers telemetry is still cut by the gate.
      expect(
        forensic.filter(
          (e) => e.id !== COVERAGE_EVENT_ID && e.severity !== "High" && e.severity !== "Critical",
        ),
      ).toEqual([]);

      await importAndWait(app, importMetaStore, upload("2026-03-02"));
      forensic = (await stateStore.load("c1")).forensicTimeline;
      notes = forensic.filter((e) => e.id === COVERAGE_EVENT_ID);
      expect(notes).toHaveLength(1);
      expect(notes[0].severity).toBe("Medium");
    },
    POLL_TIMEOUT_MS * 2,
  );
});
