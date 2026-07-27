import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { PRESIDIO_SAMPLE_TEXT } from "../../src/analysis/presidio.js";

// POST /system/presidio-test runs the FIXED synthetic sample text through the Presidio URL the
// analyst has TYPED (not necessarily saved yet), so they can tune the confidence floor before
// committing to Settings. It must never 5xx on a connection failure — a container that isn't
// reachable yet is a normal, renderable outcome, not a server fault (see the brief's binding
// constraint on this route).
let app: ReturnType<typeof createApp>;
const originalFetch = globalThis.fetch;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-presidiotest-"));
  const store = new CaseStore(root);
  app = createApp(store, {});
});

afterEach(() => {
  globalThis.fetch = originalFetch;
});

describe("POST /system/presidio-test", () => {
  it("rejects a missing url with 400", async () => {
    const res = await request(app).post("/system/presidio-test").send({});
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/url is required/);
  });

  it("rejects a blank (whitespace-only) url with 400", async () => {
    const res = await request(app).post("/system/presidio-test").send({ url: "   " });
    expect(res.status).toBe(400);
  });

  it("returns 200 with the sample text and mapped findings on success", async () => {
    globalThis.fetch = (async () => ({
      ok: true,
      status: 200,
      json: async () => [{ entity_type: "PERSON", start: 0, end: 8, score: 0.95 }],
    })) as unknown as typeof fetch;
    const res = await request(app).post("/system/presidio-test").send({ url: "http://localhost:5002" });
    expect(res.status).toBe(200);
    expect(res.body.sample).toBe(PRESIDIO_SAMPLE_TEXT);
    expect(res.body.findings).toEqual([
      { entityType: "PERSON", value: PRESIDIO_SAMPLE_TEXT.slice(0, 8), score: 0.95 },
    ]);
    expect(res.body.error).toBeUndefined();
  });

  // The binding requirement: a failed connection test is a normal outcome the panel renders,
  // not a server fault — so this must be 200, never 5xx, with the error carried in the body.
  it("returns 200 (NOT a 5xx) with an error string when the container is unreachable", async () => {
    globalThis.fetch = (async () => { throw new Error("fetch failed: ECONNREFUSED"); }) as unknown as typeof fetch;
    const res = await request(app).post("/system/presidio-test").send({ url: "http://localhost:5002" });
    expect(res.status).toBe(200);
    expect(res.body.sample).toBe(PRESIDIO_SAMPLE_TEXT);
    expect(res.body.error).toMatch(/ECONNREFUSED/);
    expect(res.body.findings).toBeUndefined();
  });

  it("returns 200 with an error string when Presidio responds with a non-ok HTTP status", async () => {
    globalThis.fetch = (async () => ({ ok: false, status: 500, json: async () => ({}) })) as unknown as typeof fetch;
    const res = await request(app).post("/system/presidio-test").send({ url: "http://localhost:5002" });
    expect(res.status).toBe(200);
    expect(res.body.error).toMatch(/500/);
  });

  it("trims the typed url and hits /analyze on it", async () => {
    let capturedUrl = "";
    globalThis.fetch = (async (url: unknown) => {
      capturedUrl = String(url);
      return { ok: true, status: 200, json: async () => [] };
    }) as unknown as typeof fetch;
    const res = await request(app).post("/system/presidio-test").send({ url: "  http://localhost:5002  " });
    expect(res.status).toBe(200);
    expect(capturedUrl).toBe("http://localhost:5002/analyze");
  });
});
