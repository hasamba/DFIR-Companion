import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, setServerLogger } from "../../src/server.js";
import { createConsoleLogger } from "../../src/logging/logger.js";
import { AiCostStore } from "../../src/analysis/aiCost.js";

let store: CaseStore;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-aicost-route-"));
  store = new CaseStore(root);
  setServerLogger(createConsoleLogger("error"));
});

describe("GET /cases/:id/ai-cost", () => {
  it("returns the case's AI cost state, all-empty for a fresh case", async () => {
    await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const app = createApp(store, { aiCostStore: new AiCostStore(store) });
    const res = await request(app).get("/cases/c1/ai-cost");
    expect(res.status).toBe(200);
    expect(res.body.vision.totalCalls).toBe(0);
    expect(res.body.synthesis.totalCalls).toBe(0);
    expect(res.body.other.totalCalls).toBe(0);
  });

  it("returns 501 when aiCostStore isn't configured", async () => {
    await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const app = createApp(store, {});
    const res = await request(app).get("/cases/c1/ai-cost");
    expect(res.status).toBe(501);
  });

  it("reflects a recorded call", async () => {
    await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const aiCostStore = new AiCostStore(store);
    await aiCostStore.record("c1", "synthesis", "openrouter", "anthropic/claude-opus-4.8", { costUSD: 0.5 });
    const app = createApp(store, { aiCostStore });
    const res = await request(app).get("/cases/c1/ai-cost");
    expect(res.body.synthesis.totalCalls).toBe(1);
    expect(res.body.synthesis.totalCostUSD).toBeCloseTo(0.5);
  });
});
