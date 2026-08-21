import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { fetchMock, jsonResponse } from "../helpers/fetchMock.js";

const originalSynthKey = process.env.DFIR_AI_SYNTH_KEY;

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-ai-models-route-"));
  return createApp(new CaseStore(root));
}

afterEach(() => {
  vi.unstubAllGlobals();
  if (originalSynthKey === undefined) delete process.env.DFIR_AI_SYNTH_KEY;
  else process.env.DFIR_AI_SYNTH_KEY = originalSynthKey;
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
});
