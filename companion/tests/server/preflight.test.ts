import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, setServerLogger } from "../../src/server.js";
import { createConsoleLogger } from "../../src/logging/logger.js";
import { ProviderError, type AIProvider } from "../../src/providers/provider.js";
import type { EnrichmentProvider } from "../../src/enrichment/provider.js";

let store: CaseStore;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-preflight-"));
  store = new CaseStore(root);
  setServerLogger(createConsoleLogger("error"));
});

// Minimal fake AI provider
function fakeAi(opts: { ok: boolean; name?: string; error?: string }): AIProvider {
  return {
    name: opts.name ?? "fake",
    analyze: async () => {
      if (!opts.ok) throw new ProviderError(opts.error ?? "bad key", "auth");
      return { rawText: '{"ok":true}' };
    },
  };
}

// Minimal fake enrichment provider with a probe
function fakeEnrich(name: string, reachable: boolean): EnrichmentProvider {
  return {
    name,
    scope: "local",
    probe: async () => {
      if (!reachable) throw new Error("probe failed");
    },
    lookup: async () => null,
  } as unknown as EnrichmentProvider;
}

describe("GET /diagnostics/preflight", () => {
  it("returns 200 with report shape when AI is not configured", async () => {
    const app = createApp(store, {});
    const res = await request(app).get("/diagnostics/preflight");
    expect(res.status).toBe(200);
    expect(res.body.report).toBeTruthy();
    expect(Array.isArray(res.body.report.items)).toBe(true);
    expect(typeof res.body.report.ranAt).toBe("string");
    expect(typeof res.body.report.durationMs).toBe("number");
    expect(typeof res.body.report.anyFailed).toBe("boolean");
    expect(typeof res.body.report.anyCriticalFailed).toBe("boolean");
    expect(typeof res.body.text).toBe("string");
    expect(res.body.text).toContain("Pre-Flight");
  });

  it("reports AI as critical failure when not configured", async () => {
    const app = createApp(store, {});
    const res = await request(app).get("/diagnostics/preflight");
    expect(res.status).toBe(200);
    const aiItem = res.body.report.items.find((i: { name: string }) => i.name === "AI provider");
    expect(aiItem).toBeTruthy();
    expect(aiItem.ok).toBe(false);
    expect(aiItem.critical).toBe(true);
    expect(res.body.report.anyCriticalFailed).toBe(true);
  });

  it("reports AI as ok when the provider responds", async () => {
    const app = createApp(store, { aiTestProvider: () => fakeAi({ ok: true }) });
    const res = await request(app).get("/diagnostics/preflight");
    expect(res.status).toBe(200);
    const aiItem = res.body.report.items.find((i: { name: string }) => i.name === "AI provider");
    expect(aiItem).toBeTruthy();
    expect(aiItem.ok).toBe(true);
    expect(aiItem.critical).toBe(true);
    expect(res.body.report.anyCriticalFailed).toBe(false);
  });

  it("reports AI as critical failure when provider throws a ProviderError", async () => {
    const app = createApp(store, { aiTestProvider: () => fakeAi({ ok: false, error: "invalid api key" }) });
    const res = await request(app).get("/diagnostics/preflight");
    expect(res.status).toBe(200);
    const aiItem = res.body.report.items.find((i: { name: string }) => i.name === "AI provider");
    expect(aiItem).toBeTruthy();
    expect(aiItem.ok).toBe(false);
    expect(aiItem.critical).toBe(true);
    expect(aiItem.detail).toContain("invalid api key");
    expect(res.body.report.anyCriticalFailed).toBe(true);
  });

  it("includes reachable enrichment provider (non-critical)", async () => {
    const enrich = fakeEnrich("MISP", true);
    const app = createApp(store, { aiTestProvider: () => fakeAi({ ok: true }), enrichmentProviders: [enrich] });
    const res = await request(app).get("/diagnostics/preflight");
    expect(res.status).toBe(200);
    const item = res.body.report.items.find((i: { name: string }) => i.name === "Enrichment: MISP");
    expect(item).toBeTruthy();
    expect(item.ok).toBe(true);
    expect(item.critical).toBe(false);
  });

  it("includes unreachable enrichment provider as non-critical failure", async () => {
    // AI passes so the only failure is the enrichment probe — anyCriticalFailed must stay false.
    const enrich = fakeEnrich("MISP", false);
    const app = createApp(store, { aiTestProvider: () => fakeAi({ ok: true }), enrichmentProviders: [enrich] });
    const res = await request(app).get("/diagnostics/preflight");
    expect(res.status).toBe(200);
    const item = res.body.report.items.find((i: { name: string }) => i.name === "Enrichment: MISP");
    expect(item).toBeTruthy();
    expect(item.ok).toBe(false);
    expect(item.critical).toBe(false);
    // Enrichment failure alone must not set anyCriticalFailed
    expect(res.body.report.anyCriticalFailed).toBe(false);
  });

  it("caches results within the TTL (second call returns same ranAt)", async () => {
    const app = createApp(store, { aiTestProvider: () => fakeAi({ ok: true }) });
    const r1 = await request(app).get("/diagnostics/preflight");
    const r2 = await request(app).get("/diagnostics/preflight");
    expect(r1.status).toBe(200);
    expect(r2.status).toBe(200);
    expect(r1.body.report.ranAt).toBe(r2.body.report.ranAt);
  });

  it("text blob contains Pre-Flight header", async () => {
    const app = createApp(store, {});
    const res = await request(app).get("/diagnostics/preflight");
    expect(res.body.text).toContain("Pre-Flight");
  });
});

describe("POST /diagnostics/preflight", () => {
  it("forces a fresh run (new ranAt)", async () => {
    const app = createApp(store, { aiTestProvider: () => fakeAi({ ok: true }) });
    const get1 = await request(app).get("/diagnostics/preflight");
    // Tiny wait so timestamps differ
    await new Promise((r) => setTimeout(r, 5));
    const post = await request(app).post("/diagnostics/preflight");
    expect(post.status).toBe(200);
    expect(post.body.report.ranAt).not.toBe(get1.body.report.ranAt);
  });

  it("returns a fresh report with the same shape as GET", async () => {
    const app = createApp(store, {});
    const res = await request(app).post("/diagnostics/preflight");
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.report.items)).toBe(true);
    expect(typeof res.body.text).toBe("string");
  });
});

describe("GET+POST /diagnostics/preflight/control", () => {
  it("GET returns disabled:false by default", async () => {
    const app = createApp(store, {});
    const res = await request(app).get("/diagnostics/preflight/control");
    expect(res.status).toBe(200);
    expect(res.body.disabled).toBe(false);
  });

  it("POST sets disabled:true and GET /preflight returns disabled report", async () => {
    const app = createApp(store, { aiTestProvider: () => fakeAi({ ok: true }) });
    const set = await request(app).post("/diagnostics/preflight/control").send({ disabled: true });
    expect(set.status).toBe(200);
    expect(set.body.disabled).toBe(true);

    const res = await request(app).get("/diagnostics/preflight");
    expect(res.status).toBe(200);
    expect(res.body.report.disabled).toBe(true);
    expect(res.body.report.items).toHaveLength(0);
    expect(res.body.report.anyCriticalFailed).toBe(false);
  });

  it("POST re-enables checks", async () => {
    const app = createApp(store, { aiTestProvider: () => fakeAi({ ok: true }) });
    await request(app).post("/diagnostics/preflight/control").send({ disabled: true });
    await request(app).post("/diagnostics/preflight/control").send({ disabled: false });

    const res = await request(app).get("/diagnostics/preflight");
    expect(res.body.report.disabled).toBeFalsy();
    expect(res.body.report.items.length).toBeGreaterThan(0);
  });

  it("POST rejects non-boolean disabled", async () => {
    const app = createApp(store, {});
    const res = await request(app).post("/diagnostics/preflight/control").send({ disabled: "yes" });
    expect(res.status).toBe(400);
  });
});
