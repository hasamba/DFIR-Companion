import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";

// GET /system/presidio-health answers the question the anonymization modal could not ask before:
// does the CONFIGURED analyzer actually answer? The modal's "Presidio is on" row was driven by
// presidioConfigured alone — DFIR_PRESIDIO_URL being non-empty — so a container that exited days
// ago still rendered as on, and the analyst only found out when an AI call failed closed.
//
// Same binding constraint as /system/presidio-test: a dead container is a normal, renderable
// outcome, never a server fault, so this route must answer 200 with reachable:false rather than
// 5xx. The modal renders a red "analyzer unreachable" row off that flag; a 5xx would land in the
// catch that means "endpoint missing" and tell the analyst the wrong thing.
let app: ReturnType<typeof createApp>;
const originalFetch = globalThis.fetch;
const originalUrl = process.env.DFIR_PRESIDIO_URL;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-presidiohealth-"));
  app = createApp(new CaseStore(root), {});
});

afterEach(() => {
  globalThis.fetch = originalFetch;
  if (originalUrl === undefined) delete process.env.DFIR_PRESIDIO_URL;
  else process.env.DFIR_PRESIDIO_URL = originalUrl;
});

describe("GET /system/presidio-health", () => {
  it("reports not configured — and opens no socket — when DFIR_PRESIDIO_URL is unset", async () => {
    delete process.env.DFIR_PRESIDIO_URL;
    let called = false;
    globalThis.fetch = async () => {
      called = true;
      throw new Error("should not probe");
    };
    const res = await request(app).get("/system/presidio-health");
    expect(res.status).toBe(200);
    expect(res.body.configured).toBe(false);
    expect(called).toBe(false);
  });

  it("treats a whitespace-only URL as not configured", async () => {
    process.env.DFIR_PRESIDIO_URL = "   ";
    const res = await request(app).get("/system/presidio-health");
    expect(res.status).toBe(200);
    expect(res.body.configured).toBe(false);
  });

  it("reports reachable when the analyzer answers", async () => {
    process.env.DFIR_PRESIDIO_URL = "http://localhost:5002";
    globalThis.fetch = (async () => ({
      ok: true,
      status: 200,
      json: async () => [{ entity_type: "PERSON", start: 0, end: 8, score: 0.95 }],
    })) as unknown as typeof fetch;
    const res = await request(app).get("/system/presidio-health");
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ configured: true, reachable: true, url: "http://localhost:5002" });
  });

  // The exact case in the bug report: the container exited days ago, the URL stayed configured.
  it("reports unreachable with the error, not a 5xx, when the connection fails", async () => {
    process.env.DFIR_PRESIDIO_URL = "http://localhost:5002";
    globalThis.fetch = async () => {
      throw new Error("fetch failed");
    };
    const res = await request(app).get("/system/presidio-health");
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ configured: true, reachable: false });
    expect(res.body.error).toMatch(/fetch failed/);
  });

  // A reachable port is not a working analyzer — something else on 5002, or an analyzer erroring
  // on every request, must read as unreachable rather than as a passing probe.
  it("reports unreachable when the analyzer answers with an HTTP error", async () => {
    process.env.DFIR_PRESIDIO_URL = "http://localhost:5002";
    globalThis.fetch = (async () => ({
      ok: false,
      status: 500,
      json: async () => ({}),
    })) as unknown as typeof fetch;
    const res = await request(app).get("/system/presidio-health");
    expect(res.status).toBe(200);
    expect(res.body.reachable).toBe(false);
    expect(res.body.error).toMatch(/500/);
  });

  it("trims the configured URL before probing it", async () => {
    process.env.DFIR_PRESIDIO_URL = "  http://localhost:5002  ";
    let seen = "";
    globalThis.fetch = (async (input: unknown) => {
      seen = String(input);
      return { ok: true, status: 200, json: async () => [] };
    }) as unknown as typeof fetch;
    const res = await request(app).get("/system/presidio-health");
    expect(res.body).toMatchObject({ configured: true, reachable: true, url: "http://localhost:5002" });
    expect(seen).toBe("http://localhost:5002/analyze");
  });
});
