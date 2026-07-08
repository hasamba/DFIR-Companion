import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { emptyState } from "../../src/analysis/stateTypes.js";

async function tmp(): Promise<string> {
  return mkdtemp(join(tmpdir(), "dfir-ioc-exclude-"));
}

async function harness() {
  const root = await tmp();
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const app = createApp(store, { stateStore });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, stateStore };
}

describe("IOC exclude list routes (per-case)", () => {
  it("starts empty, adds a rule (purging matches now), lists it, and deletes it (without restoring)", async () => {
    const { app, stateStore } = await harness();
    await stateStore.save({
      ...emptyState("c1"),
      iocs: [
        { id: "i1", type: "domain", value: "CLIENT01.lan", firstSeen: "2026-01-01T00:00:00Z" },
        { id: "i2", type: "domain", value: "keep.example.com", firstSeen: "2026-01-01T00:00:00Z" },
      ],
    });
    expect((await request(app).get("/cases/c1/ioc-exclude")).body).toEqual([]);

    const add = await request(app).post("/cases/c1/ioc-exclude").send({ match: "suffix", pattern: "lan" });
    expect(add.status).toBe(201);
    expect(add.body.purged).toBe(1);
    expect(add.body.rule).toMatchObject({ match: "suffix", pattern: ".lan" });

    const state = await stateStore.load("c1");
    expect(state.iocs.map((i) => i.value)).toEqual(["keep.example.com"]);

    const list = await request(app).get("/cases/c1/ioc-exclude");
    expect(list.body).toHaveLength(1);

    const del = await request(app).delete(`/cases/c1/ioc-exclude/${add.body.rule.id}`);
    expect(del.status).toBe(200);
    expect((await request(app).get("/cases/c1/ioc-exclude")).body).toEqual([]);

    // deleting the rule does not resurrect the already-purged IOC
    const after = await stateStore.load("c1");
    expect(after.iocs.map((i) => i.value)).toEqual(["keep.example.com"]);
  });

  it("rejects an invalid rule (400) and a missing rule on delete (404)", async () => {
    const { app } = await harness();
    expect((await request(app).post("/cases/c1/ioc-exclude").send({ match: "regex", pattern: "(" })).status).toBe(400);
    expect((await request(app).post("/cases/c1/ioc-exclude").send({ match: "bogus", pattern: "x" })).status).toBe(400);
    expect((await request(app).delete("/cases/c1/ioc-exclude/ghost")).status).toBe(404);
  });

  it("scopes rules to the case they were added on", async () => {
    const { app } = await harness();
    await request(app).post("/cases").send({ caseId: "c2", name: "n", investigator: "i", aiProvider: null });
    await request(app).post("/cases/c1/ioc-exclude").send({ match: "suffix", pattern: "lan" });
    expect((await request(app).get("/cases/c1/ioc-exclude")).body).toHaveLength(1);
    expect((await request(app).get("/cases/c2/ioc-exclude")).body).toEqual([]);
  });

  it("returns 501 when no state store is configured", async () => {
    const store = new CaseStore(await tmp());
    const app = createApp(store);
    expect((await request(app).post("/cases/c1/ioc-exclude").send({ match: "exact", pattern: "x" })).status).toBe(501);
  });
});
