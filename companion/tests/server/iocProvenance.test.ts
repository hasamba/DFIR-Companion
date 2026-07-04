import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import type { ForensicEvent, IOC } from "../../src/analysis/stateTypes.js";

// Provenance is computed over forensic ∪ super events: a detection-linked IOC appears in a Low+ event,
// a telemetry-only IOC appears only in Info events (which — under the severity gate — live in the
// super-timeline, not the forensic timeline). So the route MUST see super events, not just forensic.
const HIGH_EVENT: ForensicEvent = {
  id: "e-high",
  timestamp: "2026-06-01T00:00:00Z",
  description: "malicious beacon to 10.9.9.9",
  severity: "High",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
};

const INFO_SUPER_EVENT: ForensicEvent = {
  id: "e-info",
  timestamp: "2026-06-01T01:00:00Z",
  description: "MFT entry for benign.exe at 10.1.1.1",
  severity: "Info",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
};

const DETECTION_IOC: IOC = { id: "i-det", type: "ip", value: "10.9.9.9", firstSeen: "2026-06-01T00:00:00Z" };
const TELEMETRY_IOC: IOC = { id: "i-tel", type: "ip", value: "10.1.1.1", firstSeen: "2026-06-01T01:00:00Z" };

async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-ioc-prov-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const superTimelineStore = new SuperTimelineStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined, synthesisProvider: undefined, stateStore, store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, { pipeline, stateStore, superTimelineStore });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, stateStore, superTimelineStore };
}

describe("GET /cases/:id/ioc-provenance", () => {
  it("classifies an IOC in a High forensic event as detection and an Info-only super IOC as telemetry", async () => {
    const { app, stateStore, superTimelineStore } = await makeApp();
    // Forensic timeline: the High event + both IOCs live in state.
    const state = emptyState("c1");
    state.forensicTimeline = [HIGH_EVENT];
    state.iocs = [DETECTION_IOC, TELEMETRY_IOC];
    await stateStore.save(state);
    // The Info event that references the telemetry IOC lives ONLY in the super-timeline.
    await superTimelineStore.append("c1", [INFO_SUPER_EVENT]);

    const res = await request(app).get("/cases/c1/ioc-provenance");
    expect(res.status).toBe(200);
    expect(res.body["i-det"]).toBe("detection");
    expect(res.body["i-tel"]).toBe("telemetry");
  });

  it("404s for an unknown case", async () => {
    const { app } = await makeApp();
    const res = await request(app).get("/cases/nope/ioc-provenance");
    expect(res.status).toBe(404);
  });
});
