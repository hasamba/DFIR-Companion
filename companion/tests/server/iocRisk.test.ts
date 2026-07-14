import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { IocWhitelistStore } from "../../src/analysis/iocWhitelistStore.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import type { ForensicEvent, IOC } from "../../src/analysis/stateTypes.js";

const CRIT_EVENT: ForensicEvent = {
  id: "e1", timestamp: "2026-06-01T00:00:00Z", description: "C2 to 9.9.9.9", severity: "Critical",
  mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], srcIp: "9.9.9.9", sources: ["EDR", "Firewall"],
};
const MALICIOUS_IP: IOC = { id: "i-bad", type: "ip", value: "9.9.9.9", firstSeen: "2026-06-01T00:00:00Z", enrichments: [
  { source: "VirusTotal", verdict: "malicious", fetchedAt: "" },
  { source: "AbuseIPDB", verdict: "malicious", fetchedAt: "" },
] };
const WHITELISTED_DOMAIN: IOC = { id: "i-wl", type: "domain", value: "safe.example.com", firstSeen: "2026-06-01T00:00:00Z" };

async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-ioc-risk-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const iocWhitelistStore = new IocWhitelistStore(join(root, "whitelist.json"));
  const pipeline = buildRuntimePipeline({
    provider: undefined, synthesisProvider: undefined, stateStore, store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, { pipeline, stateStore, iocWhitelistStore });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, stateStore, iocWhitelistStore };
}

describe("GET /cases/:id/ioc-risk", () => {
  it("scores a corroborated-malicious IP in a Critical event as critical/high, and a whitelisted domain as benign", async () => {
    const { app, stateStore, iocWhitelistStore } = await makeApp();
    const state = emptyState("c1");
    state.forensicTimeline = [CRIT_EVENT];
    state.iocs = [MALICIOUS_IP, WHITELISTED_DOMAIN];
    await stateStore.save(state);
    await iocWhitelistStore.add({ match: "exact", pattern: "safe.example.com", iocType: "domain" });

    const res = await request(app).get("/cases/c1/ioc-risk");
    expect(res.status).toBe(200);
    expect(["critical", "high"]).toContain(res.body["i-bad"].score);
    expect(res.body["i-bad"].factors.length).toBeGreaterThan(0);
    expect(res.body["i-wl"].score).toBe("benign");
  });

  it("404s for an unknown case", async () => {
    const { app } = await makeApp();
    expect((await request(app).get("/cases/nope/ioc-risk")).status).toBe(404);
  });
});
