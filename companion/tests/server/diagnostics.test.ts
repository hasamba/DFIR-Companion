import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, setServerLogger } from "../../src/server.js";
import { createConsoleLogger } from "../../src/logging/logger.js";
import { ProviderError, type AIProvider } from "../../src/providers/provider.js";

let store: CaseStore;
let root: string;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "dfir-diag-"));
  store = new CaseStore(root);
  setServerLogger(createConsoleLogger("error"));
});

describe("GET /diagnostics", () => {
  it("returns the report shape and a shareable text blob", async () => {
    const app = createApp(store, {});
    const res = await request(app).get("/diagnostics");
    expect(res.status).toBe(200);
    const r = res.body.report;
    expect(r).toBeTruthy();
    expect(r.disk).toHaveProperty("freeBytes");
    expect(r.disk).toHaveProperty("level");
    expect(r.cases).toEqual({ count: 0, open: 0, closed: 0 });
    expect(r.queue).toHaveProperty("bufferedCaptures", 0);
    expect(r.queue).toHaveProperty("synthInFlight", 0);
    expect(r.ai).toHaveProperty("configured");
    expect(Array.isArray(r.importers.recentFailures)).toBe(true);
    expect(typeof res.body.text).toBe("string");
    expect(res.body.text).toContain("DFIR Companion — Diagnostics");
  });

  it("counts open vs closed cases", async () => {
    await store.createCase({ caseId: "open-1", name: "A", investigator: "x", aiProvider: null });
    await store.createCase({ caseId: "closed-1", name: "B", investigator: "x", aiProvider: null });
    await store.updateCaseMeta("closed-1", { status: "closed" });
    const app = createApp(store, {});
    const res = await request(app).get("/diagnostics");
    expect(res.body.report.cases).toEqual({ count: 2, open: 1, closed: 1 });
  });

  it("NEVER leaks an API key into the diagnostics payload", async () => {
    process.env.DFIR_AI_PROVIDER = "openai";
    process.env.DFIR_AI_MODEL = "gpt-4o";
    process.env.DFIR_AI_KEY = "sk-must-not-leak-12345";
    try {
      const app = createApp(store, {});
      const res = await request(app).get("/diagnostics");
      expect(JSON.stringify(res.body)).not.toContain("sk-must-not-leak-12345");
      expect(res.body.report.ai.provider).toBe("openai");
      expect(res.body.report.ai.configured).toBe(true);
    } finally {
      delete process.env.DFIR_AI_PROVIDER;
      delete process.env.DFIR_AI_MODEL;
      delete process.env.DFIR_AI_KEY;
    }
  });
});

describe("GET /diagnostics/sizes", () => {
  it("totals bytes and lists per-case sizes after a file is written", async () => {
    await store.createCase({ caseId: "case-1", name: "C", investigator: "x", aiProvider: null });
    await store.saveImport("case-1", "0001_evidence.json", "x".repeat(1234));
    const app = createApp(store, {});
    const res = await request(app).get("/diagnostics/sizes");
    expect(res.status).toBe(200);
    expect(res.body.totalBytes).toBeGreaterThanOrEqual(1234);
    const c = res.body.cases.find((x: { caseId: string }) => x.caseId === "case-1");
    expect(c).toBeTruthy();
    expect(c.bytes).toBeGreaterThanOrEqual(1234);
    expect(res.body.largestFiles.length).toBeGreaterThan(0);
    expect(res.body.truncated).toBe(false);
  });
});

describe("POST /diagnostics/ai-test", () => {
  it("returns 501 when no provider builder is configured", async () => {
    const app = createApp(store, {});
    const res = await request(app).post("/diagnostics/ai-test");
    expect(res.status).toBe(501);
    expect(res.body.ok).toBe(false);
  });

  it("returns ok with latency when the provider responds", async () => {
    const fake: AIProvider = {
      name: "fake",
      analyze: async () => ({ rawText: "OK" }),
    };
    const app = createApp(store, { aiTestProvider: () => fake });
    const res = await request(app).post("/diagnostics/ai-test");
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.provider).toBe("fake");
    expect(res.body.reply).toBe("OK");
    expect(typeof res.body.latencyMs).toBe("number");
  });

  it("maps a ProviderError to an actionable kind without 500ing", async () => {
    const fake: AIProvider = {
      name: "fake",
      analyze: async () => { throw new ProviderError("bad key", "auth"); },
    };
    const app = createApp(store, { aiTestProvider: () => fake });
    const res = await request(app).post("/diagnostics/ai-test");
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(false);
    expect(res.body.kind).toBe("auth");
    expect(res.body.error).toContain("bad key");
  });
});
