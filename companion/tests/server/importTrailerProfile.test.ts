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
import { ActivityLogStore } from "../../src/analysis/activityLog.js";
import { AnalysisRunStore } from "../../src/analysis/analysisRunStore.js";
import { pollFor } from "../helpers/poll.js";

// #993 — the route now threads an analyst-declared web-log trailer profile through to
// combinedLogImport.ts's `readTrailer`. A 403 line bumps to Low severity so the event lands
// directly in the forensic timeline (Info would be demoted to the super-timeline only).
const SQUID_LINE =
  '10.30.10.14 - - [15/May/2024:06:50:28 +0000] "GET /secure/data HTTP/1.1" 403 512 "-" "Mozilla/5.0" TCP_MISS:HIER_DIRECT';

async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-trailer-profile-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const superTimelineStore = new SuperTimelineStore(store);
  const importMetaStore = new ImportMetaStore(store);
  const forensicGateControlStore = new ForensicGateControlStore(store);
  const activityLogStore = new ActivityLogStore(store);
  const analysisRunStore = new AnalysisRunStore(store, { appVersion: "test" });
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
    activityLogStore,
    analysisRunStore,
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, stateStore };
}

describe("POST /cases/:id/import — declared web-log trailer profile (#993)", () => {
  it("recognises the Squid trailer only when the analyst declares squid_combined", async () => {
    const { app, stateStore } = await makeApp();
    const res = await request(app)
      .post("/cases/c1/import")
      .send({ filename: "proxy_access.log", text: SQUID_LINE, webLogFormat: "squid_combined" });
    expect(res.status).toBe(202);
    expect(res.body.kind).toBe("combinedlog");

    const state = await pollFor("the combined-log import to land", async () => {
      const s = await stateStore.load("c1");
      return s.forensicTimeline.length > 0 ? s : undefined;
    });
    const event = state.forensicTimeline[0];
    expect(event.description).toContain("(squid_combined, declared format)");
    expect(event.description).toContain("cache miss");
    expect(event.description).not.toContain("trailer: TCP_MISS");
  });

  it("leaves the Squid token unlabelled when no profile is declared", async () => {
    const { app, stateStore } = await makeApp();
    const res = await request(app)
      .post("/cases/c1/import")
      .send({ filename: "proxy_access.log", text: SQUID_LINE });
    expect(res.status).toBe(202);

    const state = await pollFor("the undeclared combined-log import to land", async () => {
      const s = await stateStore.load("c1");
      return s.forensicTimeline.length > 0 ? s : undefined;
    });
    const event = state.forensicTimeline[0];
    expect(event.description).not.toContain("declared format");
    expect(event.description).toContain("trailer: TCP_MISS:HIER_DIRECT");
  });

  it("ignores webLogFormat entirely for a non-combinedlog kind", async () => {
    const { app, stateStore } = await makeApp();
    const res = await request(app)
      .post("/cases/c1/import")
      .send({
        filename: "thor.json",
        text: JSON.stringify({
          time: "2026-05-20T10:00:00Z",
          hostname: "WIN-01",
          level: "Alert",
          module: "Filescan",
          message: "x",
          file: "C:\\Tools\\evil.exe",
          modified: "2026-05-20T10:00:00Z",
        }),
        webLogFormat: "squid_combined",
      });
    expect(res.status).toBe(202);
    expect(res.body.kind).toBe("thor");
    const state = await pollFor("the THOR import to land", async () => {
      const s = await stateStore.load("c1");
      return s.forensicTimeline.length > 0 ? s : undefined;
    });
    expect(state.forensicTimeline[0].description).not.toContain("squid_combined");
  });
});
