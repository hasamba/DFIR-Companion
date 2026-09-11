import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ForensicGateControlStore } from "../../src/analysis/forensicGateControl.js";
import type { VelociraptorRunResult } from "../../src/integrations/velociraptor/velociraptorApi.js";

// A `superTimelineOnly` import against a server with NO super-timeline store falls through to the
// forensic importer (composition/veloExternalIngest.ts). That path must not demote: with the gate
// configured, demote would strip every Info row from the forensic timeline and there is no super
// store for them to land in — the rows would exist in neither record. Pinned after the seam
// refactor (#932 item 12) reintroduced exactly that.
const MFT_ROW = { OSPath: "C:\\evil.exe", Created0x10: "2026-06-01T00:00:00Z", FileName: "evil.exe" };

async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-velo-superonly-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const forensicGateControlStore = new ForensicGateControlStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined,
    synthesisProvider: undefined,
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const client = {
    async getHuntArtifacts() {
      return ["Windows.NTFS.MFT"];
    },
    async huntResultsByArtifact() {
      return { results: { "Windows.NTFS.MFT": [MFT_ROW] }, skipped: [] };
    },
    async huntArtifactRows(): Promise<VelociraptorRunResult> {
      return { rows: [MFT_ROW], total: 1, truncated: false };
    },
    async getFlowInfo() {
      return { artifacts: ["Windows.NTFS.MFT"], hostname: "DESKTOP-01" };
    },
    async collectionResults(): Promise<VelociraptorRunResult> {
      return { rows: [MFT_ROW], total: 1, truncated: false };
    },
    huntGuiUrlFor() {
      return undefined;
    },
    flowGuiUrlFor() {
      return undefined;
    },
  };
  const app = createApp(store, {
    pipeline,
    stateStore,
    forensicGateControlStore, // the gate is live…
    // …and there is deliberately NO superTimelineStore.
    velociraptorClient: client as unknown as NonNullable<
      Parameters<typeof createApp>[1]
    >["velociraptorClient"],
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, stateStore };
}

describe("superTimelineOnly import with no super-timeline store", () => {
  it("keeps the Info rows in the forensic timeline instead of demoting them into nothing", async () => {
    const { app, stateStore } = await makeApp();
    const res = await request(app)
      .post("/cases/c1/velociraptor/import-external")
      .send({ ref: "H.ABC", superTimelineOnly: true });
    expect(res.status).toBe(200);
    const forensic = (await stateStore.load("c1")).forensicTimeline;
    expect(forensic.length).toBeGreaterThan(0);
    expect(forensic.map((e) => e.severity)).toContain("Info");
  });
});
