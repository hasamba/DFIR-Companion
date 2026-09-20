import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { fetchMock, jsonResponse } from "../helpers/fetchMock.js";

const originalSynthKey = process.env.DFIR_AI_SYNTH_KEY;
const originalReconcileKey = process.env.DFIR_AI_RECONCILE_KEY;

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-ai-models-route-"));
  return createApp(new CaseStore(root));
}

afterEach(() => {
  vi.unstubAllGlobals();
  if (originalSynthKey === undefined) delete process.env.DFIR_AI_SYNTH_KEY;
  else process.env.DFIR_AI_SYNTH_KEY = originalSynthKey;
  if (originalReconcileKey === undefined) delete process.env.DFIR_AI_RECONCILE_KEY;
  else process.env.DFIR_AI_RECONCILE_KEY = originalReconcileKey;
});

describe("POST /settings/ai-models", () => {
  it("validates the request body instead of asserting its wire shape", async () => {
    const app = await harness();
    const res = await request(app).post("/settings/ai-models").send({ provider: 42, role: [] });

    expect(res.status).toBe(400);
    expect(res.body.error).toContain("provider");
  });

  it("uses the saved role credential when the masked password field is left blank", async () => {
    process.env.DFIR_AI_SYNTH_KEY = "saved-synth-secret";
    const fetchFn = fetchMock(async () => jsonResponse({ data: [{ id: "gpt-4o" }] }));
    vi.stubGlobal("fetch", fetchFn);
    const app = await harness();

    const res = await request(app)
      .post("/settings/ai-models")
      .send({ provider: "openai", role: "synthesis" });

    expect(res.status).toBe(200);
    expect(res.body.models).toEqual(["gpt-4o"]);
    expect((fetchFn.mock.calls[0][1]?.headers as Record<string, string>).authorization).toBe(
      "Bearer saved-synth-secret",
    );
  });

  it("lists models for the 2nd-opinion referee role with its own saved key (#1466)", async () => {
    process.env.DFIR_AI_RECONCILE_KEY = "saved-referee-secret";
    const fetchFn = fetchMock(async () => jsonResponse({ data: [{ id: "o3" }] }));
    vi.stubGlobal("fetch", fetchFn);
    const app = await harness();

    const res = await request(app)
      .post("/settings/ai-models")
      .send({ provider: "openai", role: "reconcile" });

    expect(res.status).toBe(200);
    expect(res.body.models).toEqual(["o3"]);
    expect((fetchFn.mock.calls[0][1]?.headers as Record<string, string>).authorization).toBe(
      "Bearer saved-referee-secret",
    );
  });
});
