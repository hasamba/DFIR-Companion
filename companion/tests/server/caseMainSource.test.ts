import { mkdtemp, readdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { beforeEach, describe, expect, it } from "vitest";
import { StateStore } from "../../src/analysis/stateStore.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import { createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";

// #2559: GET/PUT /cases/:id/main-source.

let store: CaseStore;
let app: ReturnType<typeof createApp>;

const ev = (id: string, sources: string[], batch: string): ForensicEvent => ({
  id,
  timestamp: "2026-01-01T00:00:00Z",
  description: "row",
  severity: "High",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
  sources,
  importBatchId: batch,
});

beforeEach(async () => {
  store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-mainsource-")));
  const stateStore = new StateStore(store);
  app = createApp(store, { stateStore });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const s = emptyState("c1");
  s.forensicTimeline.push(
    ...Array.from({ length: 14 }, (_, i) => ev(`c${i}`, ["CrowdStrike Falcon"], `cs${i}`)),
    ev("v1", ["Velociraptor"], "h"),
  );
  await stateStore.save(s);
});

describe("GET/PUT /cases/:id/main-source (#2559)", () => {
  it("returns the computed main source from file counts", async () => {
    const r = await request(app).get("/cases/c1/main-source");
    expect(r.status).toBe(200);
    expect(r.body.auto).toBe("crowdstrike");
    expect(r.body.effective).toBe("crowdstrike");
    expect(r.body.override).toBeNull();
    expect(r.body.counts[0]).toMatchObject({ family: "crowdstrike", files: 14, label: "CrowdStrike Falcon" });
    expect(r.body.totalFiles).toBe(15);
    expect(r.body.language).toMatchObject({ language: "cql", note: "" });
    expect(r.body.families.length).toBeGreaterThan(5);
  });

  it("PUT sets the override and GET returns it as effective; null goes back to automatic", async () => {
    const put = await request(app).put("/cases/c1/main-source").send({ override: "mixed" });
    expect(put.status).toBe(200);
    expect(put.body.effective).toBe("mixed");
    expect(put.body.language).toBeNull();
    expect((await request(app).get("/cases/c1/main-source")).body.override).toBe("mixed");
    const back = await request(app).put("/cases/c1/main-source").send({ override: null });
    expect(back.body.effective).toBe("crowdstrike");
  });

  it("rejects an unknown family, a wrong type and a missing field", async () => {
    expect((await request(app).put("/cases/c1/main-source").send({ override: "vql" })).status).toBe(400);
    expect((await request(app).put("/cases/c1/main-source").send({ override: 7 })).status).toBe(400);
    expect((await request(app).put("/cases/c1/main-source").send({})).status).toBe(400);
  });

  it("404s for a case that does not exist and creates nothing on disk", async () => {
    expect((await request(app).get("/cases/nope/main-source")).status).toBe(404);
    const put = await request(app).put("/cases/nope/main-source").send({ override: "splunk" });
    expect(put.status).toBe(404);
    expect(await readdir(store.casesRoot)).not.toContain("nope");
  });

  it("a garbage stored value reads as no override", async () => {
    await writeFile(join(store.stateDir("c1"), "main-source.json"), '{"override":"nonsense"}');
    const r = await request(app).get("/cases/c1/main-source");
    expect(r.body.override).toBeNull();
    await writeFile(join(store.stateDir("c1"), "main-source.json"), "{not json");
    expect((await request(app).get("/cases/c1/main-source")).body.override).toBeNull();
  });
});
