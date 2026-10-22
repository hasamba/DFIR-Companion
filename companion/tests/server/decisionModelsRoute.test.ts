import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import type { DecisionModelCatalog } from "../../src/analysis/ai/jev/decisionModels.js";

// #2224: the Settings picker's list of OpenRouter decision models, served by the companion because the
// dashboard's CSP keeps the browser off openrouter.ai.

async function app(catalog: DecisionModelCatalog) {
  const store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-decision-models-")));
  return createApp(store, { decisionModelCatalog: catalog });
}

describe("GET /settings/jev/models", () => {
  it("returns the catalog's decision models", async () => {
    const list = {
      models: [
        { id: "typesafe/jev-1.14", name: "TypeSafe: Jev 1.14", free: false, inputPerMillionUSD: 0.02 },
      ],
      fetchedAt: "2026-10-22T00:00:00.000Z",
      stale: false,
    };
    const res = await request(await app({ list: async () => list })).get("/settings/jev/models");
    expect(res.status).toBe(200);
    expect(res.body).toEqual(list);
  });

  it("answers 502 with a reason when the list cannot load", async () => {
    const failing: DecisionModelCatalog = {
      list: async () => {
        throw new Error("OpenRouter model list returned HTTP 503");
      },
    };
    const res = await request(await app(failing)).get("/settings/jev/models");
    expect(res.status).toBe(502);
    expect(res.body.error).toMatch(/decision model list.*503/i);
  });
});
