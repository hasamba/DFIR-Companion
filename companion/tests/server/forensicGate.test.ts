import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { ForensicGateControlStore } from "../../src/analysis/forensicGateControl.js";
import type { VelociraptorRunResult } from "../../src/integrations/velociraptor/velociraptorApi.js";

// Info telemetry (an ungraded MFT row) — routed to the super-timeline only under the default gate; a
// High YARA detection stays in the forensic timeline. Mirrors veloImportExternal.test.ts's fixtures.
const MFT_ROW = { OSPath: "C:\\evil.exe", Created0x10: "2026-06-01T00:00:00Z", FileName: "evil.exe" };
const YARA_ROW = { _Source: "Windows.Detection.Yara", Rule: "EvilRule", Namespace: "n", OSPath: "C:\\bad.dll", Created0x10: "2026-06-01T01:00:00Z" };

interface MockVeloClient {
  getHuntArtifacts(huntId: string): Promise<string[]>;
  huntResultsByArtifact(huntId: string, artifacts: string[]): Promise<{ results: Record<string, unknown[]>; skipped: string[] }>;
  getFlowInfo(clientId: string, flowId: string): Promise<{ artifacts: string[]; hostname: string }>;
  collectionResults(clientId: string, flowId: string, artifact: string): Promise<VelociraptorRunResult>;
  huntGuiUrlFor(huntId: string): string | undefined;
  flowGuiUrlFor(clientId: string, flowId: string): string | undefined;
}

async function makeApp(huntResults: Record<string, unknown[]> = { "Windows.Detection.Yara": [YARA_ROW], "Windows.NTFS.MFT": [MFT_ROW] }) {
  const root = await mkdtemp(join(tmpdir(), "dfir-fgate-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const superTimelineStore = new SuperTimelineStore(store);
  const forensicGateControlStore = new ForensicGateControlStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined, synthesisProvider: undefined, stateStore, store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });

  const client: MockVeloClient = {
    async getHuntArtifacts() {
      return Object.keys(huntResults);
    },
    async huntResultsByArtifact() {
      return { results: huntResults, skipped: [] };
    },
    async getFlowInfo() {
      return { artifacts: ["Windows.NTFS.MFT"], hostname: "DESKTOP-01" };
    },
    async collectionResults() {
      return { rows: [MFT_ROW], total: 1, truncated: false };
    },
    huntGuiUrlFor(huntId: string) {
      return `https://velo.example/app/index.html?org_id=root#/hunts/${huntId}`;
    },
    flowGuiUrlFor(clientId: string, flowId: string) {
      return `https://velo.example/app/index.html?org_id=root#/collected/${clientId}/${flowId}`;
    },
  };

  const app = createApp(store, {
    pipeline, stateStore, superTimelineStore, forensicGateControlStore,
    velociraptorClient: client as unknown as Parameters<typeof createApp>[1]["velociraptorClient"],
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, stateStore, superTimelineStore };
}

describe("forensic-timeline severity gate at the import seams", () => {
  it("default gate keeps the High detection in forensic but demotes the Info telemetry to super only", async () => {
    const { app, stateStore } = await makeApp();
    const res = await request(app).post("/cases/c1/velociraptor/import-external").send({ ref: "H.ABC" });
    expect(res.status).toBe(200);

    const forensic = (await stateStore.load("c1")).forensicTimeline;
    const sevs = forensic.map((e) => e.severity);
    expect(sevs).toContain("High");                                  // graded detection stays
    expect(sevs.some((s) => s === "Info")).toBe(false);              // Info telemetry demoted out

    // The super-timeline is the COMPLETE record — it must still hold both the High and the Info event.
    const st = (await request(app).get("/cases/c1/super-timeline")).body;
    const stSevs = (st.events as Array<{ severity: string }>).map((e) => e.severity);
    expect(stSevs).toContain("High");
    expect(stSevs).toContain("Info");
  });

  it("GET reports the per-case override (null) and the effective default", async () => {
    const { app } = await makeApp();
    const res = await request(app).get("/cases/c1/forensic-gate");
    expect(res.status).toBe(200);
    expect(res.body.minSeverity).toBe(null);
    expect(res.body.effective).toBe("Low");
  });

  it("setting the gate to Info re-admits the Info telemetry into the forensic timeline", async () => {
    const { app, stateStore } = await makeApp();
    const put = await request(app).put("/cases/c1/forensic-gate").send({ minSeverity: "Info" });
    expect(put.status).toBe(200);
    expect(put.body.minSeverity).toBe("Info");
    expect(put.body.effective).toBe("Info");

    // Fresh hunt ref so the imported ids don't dedupe-collapse against the first (unrun) import.
    const res = await request(app).post("/cases/c1/velociraptor/import-external").send({ ref: "H.ABC2" });
    expect(res.status).toBe(200);

    const sevs = (await stateStore.load("c1")).forensicTimeline.map((e) => e.severity);
    expect(sevs).toContain("High");
    expect(sevs).toContain("Info");                                  // no longer demoted
  });

  it("rejects an invalid minSeverity with 400", async () => {
    const { app } = await makeApp();
    const res = await request(app).put("/cases/c1/forensic-gate").send({ minSeverity: "Bogus" });
    expect(res.status).toBe(400);
  });

  it("clears the per-case override when minSeverity is null", async () => {
    const { app } = await makeApp();
    await request(app).put("/cases/c1/forensic-gate").send({ minSeverity: "High" });
    const cleared = await request(app).put("/cases/c1/forensic-gate").send({ minSeverity: null });
    expect(cleared.status).toBe(200);
    expect(cleared.body.minSeverity).toBe(null);
    expect(cleared.body.effective).toBe("Low");
  });

  it("promotion bypasses the gate — an Info super event promotes into the forensic timeline", async () => {
    const { app, stateStore, superTimelineStore } = await makeApp();
    // Default-gate import: the Info MFT event lands in super only, demoted from forensic.
    await request(app).post("/cases/c1/velociraptor/import-external").send({ ref: "H.ABC" });
    expect((await stateStore.load("c1")).forensicTimeline.some((e) => e.severity === "Info")).toBe(false);

    // Find the Info super event and promote it — promotion must NOT be gated.
    const st = (await request(app).get("/cases/c1/super-timeline")).body;
    const infoEvent = (st.events as Array<{ id: string; severity: string }>).find((e) => e.severity === "Info");
    expect(infoEvent).toBeDefined();
    const prom = await request(app).post("/cases/c1/super-timeline/promote").send({ eventIds: [infoEvent!.id] });
    expect(prom.status).toBe(200);
    expect(prom.body.promoted).toBe(1);

    // The promoted Info event is now in the forensic timeline despite the default gate.
    expect((await stateStore.load("c1")).forensicTimeline.some((e) => e.id === infoEvent!.id)).toBe(true);
    void superTimelineStore;
  });
});
