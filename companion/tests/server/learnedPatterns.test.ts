import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { LearnedPatternStore } from "../../src/analysis/learnedPatternStore.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../src/providers/provider.js";

// Captures the last synthesis userPrompt so we can assert the learned-patterns block was injected, and
// returns a minimal valid delta so synthesize() completes.
class CapturingProvider implements AIProvider {
  readonly name = "mock";
  readonly model = "mock-model";
  lastUserPrompt = "";
  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    this.lastUserPrompt = req.userPrompt;
    return { rawText: JSON.stringify({
      findings: [], iocs: [], mitreTechniques: [], threadsOpened: [], threadsClosed: [], timelineNote: "", summary: "s",
    }) };
  }
}

async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-learned-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const learnedPatternStore = new LearnedPatternStore(store);
  const provider = new CapturingProvider();
  const pipeline = buildRuntimePipeline({
    provider, synthesisProvider: provider, stateStore, store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, { pipeline, stateStore, learnedPatternStore, aiConfigured: true });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
  return { app, store, stateStore, learnedPatternStore, provider };
}

describe("learned dismissal patterns (#65)", () => {
  it("records a reasoned finding dismissal and returns it; recurrence bumps the count", async () => {
    const { app } = await makeApp();
    await request(app).post("/cases/c1/false-positive").send({ kind: "finding", ref: "BloodHound ingestor", reason: "authorized-test", markedBy: "Alice" });
    let patterns = (await request(app).get("/cases/c1/learned-patterns")).body;
    expect(patterns).toHaveLength(1);
    expect(patterns[0]).toMatchObject({ signature: "bloodhound ingestor", reason: "authorized-test", count: 1 });

    // Same class dismissed again → count 2, not a new row.
    await request(app).post("/cases/c1/false-positive").send({ kind: "finding", ref: "bloodhound ingestor", reason: "authorized-test", markedBy: "Alice" });
    patterns = (await request(app).get("/cases/c1/learned-patterns")).body;
    expect(patterns).toHaveLength(1);
    expect(patterns[0].count).toBe(2);
  });

  it("learns from an event marker's label but skips IOC markers", async () => {
    const { app } = await makeApp();
    await request(app).post("/cases/c1/false-positive").send({ kind: "event", ref: "e12", label: "Nessus vulnerability scan burst", reason: "known-good-tool" });
    await request(app).post("/cases/c1/false-positive").send({ kind: "ioc", ref: "10.0.0.9", reason: "known-good-tool" });
    const patterns = (await request(app).get("/cases/c1/learned-patterns")).body;
    expect(patterns).toHaveLength(1);                                  // IOC not learned
    expect(patterns[0].signature).toBe("nessus vulnerability scan burst");
  });

  it("does not learn from an opaque event marker with no label", async () => {
    const { app } = await makeApp();
    await request(app).post("/cases/c1/false-positive").send({ kind: "event", ref: "e7", reason: "duplicate" });
    expect((await request(app).get("/cases/c1/learned-patterns")).body).toEqual([]);
  });

  it("feeds the PREVIOUSLY DISMISSED PATTERNS block into the synthesis prompt", async () => {
    const { app, stateStore, learnedPatternStore, provider } = await makeApp();
    // Seed a learned pattern + a timeline so synthesize runs an AI call.
    await learnedPatternStore.record("c1", { text: "BloodHound ingestor", reason: "authorized-test" }, "2026-07-15T00:00:00Z");
    const s = emptyState("c1");
    s.forensicTimeline.push({ id: "e1", timestamp: "2026-06-01T10:00:00Z", description: "some event", severity: "High", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [] });
    await stateStore.save(s);

    await request(app).post("/cases/c1/synthesize").send({});
    expect(provider.lastUserPrompt).toContain("PREVIOUSLY DISMISSED PATTERNS");
    expect(provider.lastUserPrompt).toContain("bloodhound ingestor");
    expect(provider.lastUserPrompt).toMatch(/LOWER its confidence/);
  });

  it("returns 501 when the store is not configured", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-learned-noai-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    await store.createCase({ caseId: "c2", name: "n", investigator: "i", aiProvider: null });
    const app = createApp(store, { stateStore, aiConfigured: false });
    expect((await request(app).get("/cases/c2/learned-patterns")).status).toBe(501);
  });
});
