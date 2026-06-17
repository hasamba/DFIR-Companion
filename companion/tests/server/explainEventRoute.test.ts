import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../src/providers/provider.js";

class StubProvider implements AIProvider {
  readonly name = "stub";
  async analyze(_req: AnalyzeRequest): Promise<AnalyzeResult> {
    return {
      rawText: JSON.stringify({
        summary: "PowerShell spawned by Word",
        whyItMatters: "Classic macro initial access",
        normalContext: "Unusual in office environments",
        suspiciousIndicators: "WINWORD.EXE parent process",
        attackMapping: "T1059.001",
        pivotQueries: [{ platform: "velociraptor", query: "SELECT * FROM pslist()", rationale: "check process tree" }],
        evidenceFor: "Macro execution chain",
        evidenceAgainst: "Could be legitimate automation",
        relatedEventIds: [],
      }),
    };
  }
}

async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-explain-route-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  await store.createCase({ caseId: "c1", name: "Test", investigator: "analyst", aiProvider: null });
  const s = emptyState("c1");
  s.forensicTimeline.push({
    id: "ev1", timestamp: "2026-06-01T10:00:00Z", description: "powershell.exe spawned",
    severity: "High", mitreTechniques: ["T1059.001"], relatedFindingIds: [], sourceScreenshots: [],
    processName: "powershell.exe", parentName: "WINWORD.EXE", asset: "WS01",
  });
  await stateStore.save(s);
  const provider = new StubProvider();
  const pipeline = buildRuntimePipeline({ provider, stateStore, store, imageLoader: async () => ({ base64: "AA", mimeType: "image/webp" }) });
  const app = createApp(store, { pipeline, stateStore, aiConfigured: true });
  return { app };
}

describe("POST /cases/:id/events/:eid/explain", () => {
  it("returns a structured explanation for a known event", async () => {
    const { app } = await makeApp();
    const res = await request(app).post("/cases/c1/events/ev1/explain");
    expect(res.status).toBe(200);
    expect(res.body.summary).toBeTruthy();
    expect(res.body.whyItMatters).toBeTruthy();
    expect(Array.isArray(res.body.pivotQueries)).toBe(true);
  });

  it("returns 404 for an unknown event id", async () => {
    const { app } = await makeApp();
    const res = await request(app).post("/cases/c1/events/nonexistent/explain");
    expect(res.status).toBe(404);
    expect(res.body.error).toMatch(/event not found/i);
  });

  it("returns 501 when AI is not configured", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-explain-noai-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    await store.createCase({ caseId: "c2", name: "T", investigator: "i", aiProvider: null });
    const app = createApp(store, { stateStore, aiConfigured: false });
    const res = await request(app).post("/cases/c2/events/ev1/explain");
    expect(res.status).toBe(501);
  });

  it("returns 404 for an unknown case id", async () => {
    const { app } = await makeApp();
    const res = await request(app).post("/cases/no-such-case/events/ev1/explain");
    expect(res.status).toBe(404);
  });
});
