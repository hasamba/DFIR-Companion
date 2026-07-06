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
import type { Finding, ForensicEvent, IOC } from "../../src/analysis/stateTypes.js";

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

const DET_IOC: IOC = {
  id: "i-det", type: "ip", value: "10.9.9.9", firstSeen: "2026-06-01T00:00:00Z",
  enrichments: [{ source: "VirusTotal", verdict: "malicious", fetchedAt: "2026-06-01T02:00:00Z" }],
};
const TEL_IOC: IOC = { id: "i-tel", type: "ip", value: "10.1.1.1", firstSeen: "2026-06-01T01:00:00Z" };

const FINDING: Finding = {
  id: "f1", severity: "High", title: "C2 beacon", description: "d", relatedIocs: ["i-det"],
  sourceScreenshots: [], mitreTechniques: [], firstSeen: "2026-06-01T00:00:00Z", lastUpdated: "2026-06-01T00:00:00Z", status: "open",
};

async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-ioc-prov-chain-"));
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

describe("GET /cases/:id/ioc-provenance-chain", () => {
  it("assembles extraction + enrichment + findings across forensic and super events", async () => {
    const { app, stateStore, superTimelineStore } = await makeApp();
    const state = emptyState("c1");
    state.forensicTimeline = [HIGH_EVENT];
    state.iocs = [DET_IOC, TEL_IOC];
    state.findings = [FINDING];
    await stateStore.save(state);
    await superTimelineStore.append("c1", [INFO_SUPER_EVENT]);

    const res = await request(app).get("/cases/c1/ioc-provenance-chain");
    expect(res.status).toBe(200);
    expect(res.body["i-det"].extraction.map((e: { eventId: string }) => e.eventId)).toEqual(["e-high"]);
    expect(res.body["i-det"].enrichment).toEqual([
      { source: "VirusTotal", verdict: "malicious", score: undefined, fetchedAt: "2026-06-01T02:00:00Z", link: undefined },
    ]);
    expect(res.body["i-det"].findings.map((f: { findingId: string }) => f.findingId)).toEqual(["f1"]);
    // telemetry IOC's supporting event lives only in the super-timeline — route must still see it.
    expect(res.body["i-tel"].extraction.map((e: { eventId: string }) => e.eventId)).toEqual(["e-info"]);
    expect(res.body["i-tel"].findings).toEqual([]);
  });

  it("404s for an unknown case", async () => {
    const { app } = await makeApp();
    const res = await request(app).get("/cases/nope/ioc-provenance-chain");
    expect(res.status).toBe(404);
  });
});
