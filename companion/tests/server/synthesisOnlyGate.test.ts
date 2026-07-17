import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { MockProvider } from "../../src/providers/provider.js";
import { emptyState } from "../../src/analysis/stateTypes.js";

// Regression tests for the provider-gate mismatch: DFIR_AI_PROVIDER is the SCREENSHOT (vision)
// model, DFIR_AI_SYNTH_PROVIDER is ALL TEXT WORK. An OCR-less install sets ONLY the synthesis
// provider — so every text-AI route must gate on pipeline.hasSynthesisProvider(), NOT on the
// vision provider (hasAiProvider / aiConfigured). These apps are built exactly like that install:
// provider: undefined, synthesisProvider: <mock>, aiConfigured: false — and must get 200, not 501.
async function makeSynthOnlyApp(canned: string) {
  const root = await mkdtemp(join(tmpdir(), "dfir-synthonly-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined,
    synthesisProvider: new MockProvider("synth-only", canned),
    stateStore, store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, { pipeline, stateStore, aiConfigured: false });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, store, stateStore };
}

describe("synthesis-provider gate (no vision provider)", () => {
  it("POST /cases/:id/synthesize runs on the synthesis provider alone", async () => {
    const { app, stateStore } = await makeSynthOnlyApp(JSON.stringify({
      findings: [{ id: "f1", severity: "High", title: "synth finding", description: "d",
        relatedIocs: [], mitreTechniques: [], status: "open", relatedEventIds: ["e1"] }],
      iocs: [], mitreTechniques: [], attackerPath: "path", summary: "s",
      forensicEvents: [], threadsOpened: [], threadsClosed: [], timelineNote: "",
    }));
    // synthesize() early-returns on an empty timeline (nothing to synthesize), so seed one event.
    const s = emptyState("c1");
    s.forensicTimeline.push({
      id: "e1", timestamp: "2026-05-20T09:00:00Z", description: "phish opened",
      severity: "High", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [],
    });
    await stateStore.save(s);
    const res = await request(app).post("/cases/c1/synthesize").send({});
    expect(res.status).toBe(200);
    expect(res.body.findings).toBe(1);
  });

  it("POST /cases/:id/ask answers on the synthesis provider alone", async () => {
    const { app } = await makeSynthOnlyApp(JSON.stringify({
      answer: "No evidence of exfiltration.", status: "unknown",
      pointer: "Check egress proxy/firewall logs.", relatedEventIds: [],
    }));
    const res = await request(app).post("/cases/c1/ask").send({ question: "was data exfiltrated?" });
    expect(res.status).toBe(200);
    expect(res.body.answer).toBeTruthy();
  });

  it("POST /cases/:id/events/:eid/explain explains on the synthesis provider alone", async () => {
    const { app, stateStore } = await makeSynthOnlyApp(JSON.stringify({
      summary: "PowerShell spawned by Word",
      whyItMatters: "Classic macro initial access",
      normalContext: "Unusual in office environments",
      suspiciousIndicators: "WINWORD.EXE parent process",
      attackMapping: "T1059.001",
      pivotQueries: [{ platform: "velociraptor", query: "SELECT * FROM pslist()", rationale: "check process tree" }],
      evidenceFor: "Macro execution chain",
      evidenceAgainst: "Could be legitimate automation",
      relatedEventIds: [],
    }));
    const s = emptyState("c1");
    s.forensicTimeline.push({
      id: "ev1", timestamp: "2026-06-01T10:00:00Z", description: "powershell.exe spawned",
      severity: "High", mitreTechniques: ["T1059.001"], relatedFindingIds: [], sourceScreenshots: [],
    });
    await stateStore.save(s);
    const res = await request(app).post("/cases/c1/events/ev1/explain");
    expect(res.status).toBe(200);
    expect(res.body.summary).toBeTruthy();
  });

  it("POST /cases/:id/executive-summary generates on the synthesis provider alone", async () => {
    const { app } = await makeSynthOnlyApp(JSON.stringify({ summary: "Management summary." }));
    const res = await request(app).post("/cases/c1/executive-summary").send({});
    expect(res.status).toBe(200);
    expect(res.body.summary).toBeTruthy();
  });

  it("POST /cases/:id/import-csv accepts CSV analysis on the synthesis provider alone", async () => {
    const { app } = await makeSynthOnlyApp(JSON.stringify({
      findings: [], iocs: [], mitreTechniques: [], threadsOpened: [], threadsClosed: [],
      timelineNote: "", summary: "", forensicEvents: [],
    }));
    const res = await request(app).post("/cases/c1/import-csv")
      .send({ filename: "results.csv", csv: "ts,event\n2026-06-01T10:00:00Z,logon\n" });
    expect(res.status).toBe(202);
    expect(res.body.accepted).toBe(true);
  });

  it("still 501s when NEITHER provider is configured", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-noai-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    const pipeline = buildRuntimePipeline({
      provider: undefined, synthesisProvider: undefined, stateStore, store,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
    const app = createApp(store, { pipeline, stateStore, aiConfigured: false });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const synth = await request(app).post("/cases/c1/synthesize").send({});
    expect(synth.status).toBe(501);
    const ask = await request(app).post("/cases/c1/ask").send({ question: "q" });
    expect(ask.status).toBe(501);
    const csv = await request(app).post("/cases/c1/import-csv").send({ filename: "x.csv", csv: "a,b\n1,2\n" });
    expect(csv.status).toBe(501);
  });
});
