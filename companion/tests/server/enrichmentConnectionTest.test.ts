import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import type { AppOptions } from "../../src/composition/appOptions.js";
import type { EnrichmentProvider, IocKind } from "../../src/enrichment/provider.js";

// "Test connection" for the two self-hosted THREAT-INTEL providers, YETI and OpenCTI.
//
// They are not push integrations, so they answer through a different route family
// (/enrichment/:id/reconnect) and a different probe: each already implements probe(), a real
// auth round-trip that sends NO indicator — which is exactly what a test button must do for a
// provider whose whole OPSEC promise is that indicators stay on the analyst's own box.
//
// THE RESULT IS RECORDED, NOT JUST DISPLAYED. The reachability gate caches each provider's
// health for ~60s and skips a provider it last saw down. A test that probed independently of
// that cache would leave the dashboard's up/down dot and the enrichment gate disagreeing with
// the answer the analyst is looking at for up to a minute, so the route probes THROUGH the
// cache after invalidating it.

function fakeProvider(name: string, probe?: () => Promise<void>): EnrichmentProvider {
  return {
    name,
    scope: "local",
    supports: (kind: IocKind) => kind !== "process",
    lookup: async () => null,
    probe,
  };
}

async function makeApp(opts: AppOptions = {}) {
  const root = await mkdtemp(join(tmpdir(), "dfir-enrich-test-"));
  return createApp(new CaseStore(root), opts);
}

// The route rebuilds the provider set from .env before probing (so a key saved in Settings
// applies without a restart); the hook stands in for that env-driven rebuild.
const rebuildTo = (...providers: EnrichmentProvider[]) => ({
  rebuildEnrichmentProviders: () => providers,
});

describe("POST /enrichment/:id/reconnect", () => {
  it("404s an id that is not one of the testable providers", async () => {
    const app = await makeApp({});
    expect((await request(app).post("/enrichment/virustotal/reconnect")).status).toBe(404);
    // A key that exists on Object.prototype must not resolve to a provider spec.
    expect((await request(app).post("/enrichment/constructor/reconnect")).status).toBe(404);
  });

  it.each([
    ["yeti", "YETI", /DFIR_YETI_URL/],
    ["opencti", "OpenCTI", /DFIR_OPENCTI_URL/],
  ])("reports %s not-configured when the rebuild yields no such provider", async (id, _name, key) => {
    const app = await makeApp(rebuildTo());
    const res = await request(app).post(`/enrichment/${id}/reconnect`);
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ configured: false, ok: false });
    expect(res.body.error).toMatch(key);
  });

  it.each([
    ["yeti", "YETI"],
    ["opencti", "OpenCTI"],
  ])("probes %s and reports ok", async (id, name) => {
    const app = await makeApp(rebuildTo(fakeProvider(name, async () => {})));
    const res = await request(app).post(`/enrichment/${id}/reconnect`);
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ configured: true, ok: true, provider: name });
  });

  it.each([
    ["yeti", "YETI", "YETI auth failed (check DFIR_YETI_KEY)"],
    ["opencti", "OpenCTI", "OpenCTI auth failed (check DFIR_OPENCTI_KEY)"],
  ])("surfaces %s's own error instead of a generic failure", async (id, name, message) => {
    const app = await makeApp(
      rebuildTo(
        fakeProvider(name, async () => {
          throw new Error(message);
        }),
      ),
    );
    const res = await request(app).post(`/enrichment/${id}/reconnect`);
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ configured: true, ok: false });
    expect(res.body.error).toBe(message);
  });

  it("records the verdict in the health gate rather than only showing it", async () => {
    const app = await makeApp(
      rebuildTo(
        fakeProvider("YETI", async () => {
          throw new Error("YETI auth HTTP 405");
        }),
      ),
    );
    await request(app).post("/enrichment/yeti/reconnect");
    const health = (await request(app).get("/enrich-health")).body.providers as {
      name: string;
      ok: boolean;
      detail?: string;
    }[];
    const yeti = health.find((p) => p.name === "YETI");
    expect(yeti).toMatchObject({ ok: false });
    expect(yeti?.detail).toMatch(/405/);
  });

  it("re-probes on every click instead of answering from the cached verdict", async () => {
    // The gate caches for ~60s. Clicking Test after fixing the instance must not replay the
    // stale "down" it recorded a moment ago, or the button would be unable to report a fix.
    let up = false;
    const app = await makeApp(
      rebuildTo(
        fakeProvider("YETI", async () => {
          if (!up) throw new Error("connection refused");
        }),
      ),
    );
    expect((await request(app).post("/enrichment/yeti/reconnect")).body.ok).toBe(false);
    up = true;
    expect((await request(app).post("/enrichment/yeti/reconnect")).body.ok).toBe(true);
  });
});
