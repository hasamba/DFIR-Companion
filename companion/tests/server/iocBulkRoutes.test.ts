import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { TagsStore } from "../../src/analysis/tags.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import type { EnrichmentProvider, IocKind, EnrichmentResult } from "../../src/enrichment/provider.js";

async function freshStore(): Promise<CaseStore> {
  return new CaseStore(await mkdtemp(join(tmpdir(), "dfir-iocbulk-")));
}

// A local-scope provider is enabled by default (OPSEC default = local-only), so the case
// needs no enrich-control setup. It records which indicators it was asked about so the test
// can assert ONLY the selected subset was queried. No network — never calls fetch.
function recordingProvider(seen: string[]): EnrichmentProvider {
  return {
    name: "MockLocal",
    scope: "local",
    supports: (_kind: IocKind) => true,
    async lookup(_kind: IocKind, value: string): Promise<EnrichmentResult> {
      seen.push(value);
      return { source: "MockLocal", verdict: "malicious", score: "test" };
    },
  };
}

const threeIpState = (caseId: string) => ({
  ...emptyState(caseId),
  iocs: [
    { id: "i1", type: "ip" as const, value: "1.1.1.1", firstSeen: "2026-06-01T00:00:00Z" },
    { id: "i2", type: "ip" as const, value: "2.2.2.2", firstSeen: "2026-06-01T00:00:00Z" },
    { id: "i3", type: "ip" as const, value: "3.3.3.3", firstSeen: "2026-06-01T00:00:00Z" },
  ],
});

describe("POST /cases/:id/iocs/bulk-enrich", () => {
  it("enriches only the selected subset and leaves the rest untouched", async () => {
    const store = await freshStore();
    const stateStore = new StateStore(store);
    const seen: string[] = [];
    const app = createApp(store, { stateStore, enrichmentProviders: [recordingProvider(seen)], enrichDelayMs: 0 });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    await stateStore.save(threeIpState("c1"));

    const res = await request(app).post("/cases/c1/iocs/bulk-enrich").send({ iocIds: ["i1", "i3"] });
    expect(res.status).toBe(202);
    expect(res.body.accepted).toBe(true);
    expect(res.body.iocCount).toBe(2);

    // Enrichment runs in the background; poll until the two selected IOCs are marked checked.
    let iocs = (await stateStore.load("c1")).iocs;
    for (let n = 0; n < 50 && !iocs.find((i) => i.id === "i1")?.enrichedBy; n++) {
      await new Promise((r) => setTimeout(r, 20));
      iocs = (await stateStore.load("c1")).iocs;
    }
    const byId = Object.fromEntries(iocs.map((i) => [i.id, i]));
    expect(byId.i1.enrichedBy).toContain("MockLocal");
    expect(byId.i3.enrichedBy).toContain("MockLocal");
    expect(byId.i2.enrichedBy).toBeUndefined();             // not selected → untouched
    expect(seen.sort()).toEqual(["1.1.1.1", "3.3.3.3"]);    // only the selected values were queried
  });

  it("returns 400 when iocIds is empty", async () => {
    const store = await freshStore();
    const stateStore = new StateStore(store);
    const app = createApp(store, { stateStore, enrichmentProviders: [recordingProvider([])], enrichDelayMs: 0 });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    await stateStore.save(threeIpState("c1"));
    const res = await request(app).post("/cases/c1/iocs/bulk-enrich").send({ iocIds: [] });
    expect(res.status).toBe(400);
  });

  it("returns 404 when none of the ids match a case IOC", async () => {
    const store = await freshStore();
    const stateStore = new StateStore(store);
    const app = createApp(store, { stateStore, enrichmentProviders: [recordingProvider([])], enrichDelayMs: 0 });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    await stateStore.save(threeIpState("c1"));
    const res = await request(app).post("/cases/c1/iocs/bulk-enrich").send({ iocIds: ["ghost"] });
    expect(res.status).toBe(404);
  });

  it("returns 501 when no enrichment providers are configured", async () => {
    const store = await freshStore();
    const stateStore = new StateStore(store);
    const app = createApp(store, { stateStore });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    await stateStore.save(threeIpState("c1"));
    const res = await request(app).post("/cases/c1/iocs/bulk-enrich").send({ iocIds: ["i1"] });
    expect(res.status).toBe(501);
  });
});

describe("POST /cases/:id/iocs/bulk-tag", () => {
  it("tags every selected IOC and persists them", async () => {
    const store = await freshStore();
    const tagsStore = new TagsStore(store);
    const app = createApp(store, { tagsStore });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });

    const res = await request(app)
      .post("/cases/c1/iocs/bulk-tag")
      .send({ iocIds: ["i1", "i2"], label: "false-positive", author: "yaniv" });
    expect(res.status).toBe(200);
    expect(res.body).toHaveLength(2);

    const tags = await tagsStore.load("c1");
    expect(tags.map((t) => t.targetId).sort()).toEqual(["i1", "i2"]);
    expect(tags.every((t) => t.targetType === "ioc" && t.label === "false-positive")).toBe(true);
  });

  it("returns 400 when the label is missing", async () => {
    const store = await freshStore();
    const app = createApp(store, { tagsStore: new TagsStore(store) });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const res = await request(app).post("/cases/c1/iocs/bulk-tag").send({ iocIds: ["i1"], label: "  " });
    expect(res.status).toBe(400);
  });

  it("returns 400 when iocIds is empty", async () => {
    const store = await freshStore();
    const app = createApp(store, { tagsStore: new TagsStore(store) });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const res = await request(app).post("/cases/c1/iocs/bulk-tag").send({ iocIds: [], label: "x" });
    expect(res.status).toBe(400);
  });

  it("returns 501 when the tags store is not configured", async () => {
    const store = await freshStore();
    const app = createApp(store);
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const res = await request(app).post("/cases/c1/iocs/bulk-tag").send({ iocIds: ["i1"], label: "x" });
    expect(res.status).toBe(501);
  });
});
