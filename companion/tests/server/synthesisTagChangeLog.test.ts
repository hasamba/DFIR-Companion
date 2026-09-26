import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ActivityLogStore } from "../../src/analysis/activityLog.js";
import { awaitActivityEntry } from "../helpers/activityLog.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { emptyState, type Finding, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { AIProvider, AnalyzeResult } from "../../src/providers/provider.js";

// #1684 — f8 lost T1048.003 on a re-synthesis with no new evidence, and the activity log said only
// "synthesis ran — N finding(s)". A kept finding whose tags move now gets its own line.

const ev = (id: string): ForensicEvent => ({
  id,
  timestamp: "2026-06-01T10:00:00.000Z",
  description: `event ${id}`,
  severity: "Medium",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
});

const finding = (id: string, mitreTechniques: string[], eventId: string): Finding => ({
  id,
  severity: "High",
  title: `finding ${id}`,
  description: `finding ${id}`,
  relatedIocs: [],
  mitreTechniques,
  sourceScreenshots: [],
  firstSeen: "2026-06-01T10:00:00.000Z",
  lastUpdated: "2026-06-01T10:00:00.000Z",
  status: "open",
  relatedEventIds: [eventId],
});

const modelFinding = (id: string, mitreTechniques: string[], eventId: string) => ({
  id,
  severity: "High",
  title: `finding ${id}`,
  description: `finding ${id}`,
  relatedIocs: [],
  mitreTechniques,
  status: "open",
  relatedEventIds: [eventId],
});

class Provider implements AIProvider {
  readonly name = "scripted";
  readonly model = "mock-model";
  async analyze(): Promise<AnalyzeResult> {
    return {
      rawText: JSON.stringify({
        findings: [
          modelFinding("f8", ["T1567", "T1041", "T1119"], "e8"),
          modelFinding("f9", ["T1486", "T1490"], "e9"),
        ],
        iocs: [],
        mitreTechniques: [],
        attackerPath: "",
        summary: "s",
        forensicEvents: [],
        threadsOpened: [],
        threadsClosed: [],
        timelineNote: "",
      }),
    };
  }
}

async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-tag-change-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const provider = new Provider();
  const pipeline = buildRuntimePipeline({
    provider,
    synthesisProvider: provider,
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, {
    pipeline,
    stateStore,
    aiConfigured: true,
    activityLogStore: new ActivityLogStore(store),
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
  await stateStore.save({
    ...emptyState("c1"),
    forensicTimeline: [ev("e8"), ev("e9")],
    findings: [finding("f8", ["T1567", "T1048.003", "T1041"], "e8"), finding("f9", ["T1490", "T1486"], "e9")],
  });
  return app;
}

describe("re-synthesis logs the ATT&CK tag changes on kept findings (#1684)", () => {
  it("writes one line for the finding whose tags moved and none for the unchanged one", async () => {
    const app = await makeApp();

    const res = await request(app).post("/cases/c1/synthesize").send({});
    expect(res.status).toBe(200);

    // The summary line is appended after the tag lines, so once it is there they all are.
    await awaitActivityEntry(app, "c1", "synthesis");
    const log = await request(app).get("/cases/c1/activity-log");
    const lines = (log.body as { action: string; detail: string }[])
      .filter((e) => e.action === "synthesis-tag-change")
      .map((e) => e.detail);
    expect(lines).toEqual([
      "finding f8 ATT&CK tags changed on re-synthesis — added T1119; removed T1048.003",
    ]);
  });
});
