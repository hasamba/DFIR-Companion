import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { createApp } from "../../src/server.js";

let app: ReturnType<typeof createApp>;
let cases: CaseStore;
beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-anonroute-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  app = createApp(cases, { stateStore: new StateStore(cases) });
});

describe("/cases/:id/anon-control", () => {
  it("GET returns the default (enabled) control with screenshotWarning", async () => {
    const res = await request(app).get("/cases/c1/anon-control");
    expect(res.status).toBe(200);
    expect(res.body.enabled).toBe(true);
    expect(res.body.categories.IP).toBe(true);
    expect(typeof res.body.screenshotWarning).toBe("boolean");
  });
  it("POST persists changes", async () => {
    const res = await request(app).post("/cases/c1/anon-control").send({ enabled: false });
    expect(res.status).toBe(200);
    expect(res.body.enabled).toBe(false);
    expect((await request(app).get("/cases/c1/anon-control")).body.enabled).toBe(false);
  });
  it("POST coerces categories: a boolean false disables; a non-boolean keeps the current value", async () => {
    const res = await request(app).post("/cases/c1/anon-control").send({ categories: { IP: false, USER: null } });
    expect(res.status).toBe(200);
    expect(res.body.categories.IP).toBe(false);   // valid boolean applied
    expect(res.body.categories.USER).toBe(true);  // non-boolean ignored → kept at default (true)
    const reloaded = (await request(app).get("/cases/c1/anon-control")).body.categories;
    expect(reloaded.IP).toBe(false);
    expect(reloaded.USER).toBe(true);
  });
});

describe("/cases/:id/anon-entities", () => {
  it("GET returns auto + custom; POST replaces custom (sanitized, unknown cat → OTHER)", async () => {
    const get0 = await request(app).get("/cases/c1/anon-entities");
    expect(get0.status).toBe(200);
    expect(Array.isArray(get0.body.auto.hosts)).toBe(true);
    expect(get0.body.custom).toEqual([]);
    const post = await request(app).post("/cases/c1/anon-entities").send({ entities: [{ value: "DC9", category: "HOST" }, { value: "x", category: "bogus" }] });
    expect(post.status).toBe(200);
    expect(post.body.custom).toEqual([{ value: "DC9", category: "HOST" }, { value: "x", category: "OTHER" }]);
    expect((await request(app).get("/cases/c1/anon-entities")).body.custom.length).toBe(2);
  });

  it("GET surfaces OCR-discovered entities in the grouped auto set (by category)", async () => {
    const { DiscoveredEntitiesStore } = await import("../../src/analysis/anonDiscovered.js");
    const disc = new DiscoveredEntitiesStore(cases);
    await disc.addDiscovered("c1", [
      { value: "WIN11\\vagrant", category: "USER" },
      { value: "10.0.0.5", category: "IP" },
    ]);
    const res = await request(app).get("/cases/c1/anon-entities");
    expect(res.status).toBe(200);
    expect(res.body.auto.accounts).toContain("WIN11\\vagrant");
    expect(res.body.auto.ips).toContain("10.0.0.5");
  });

  it("suppress removes an entity (vetoes it) and unsuppress restores it; GET reflects the list", async () => {
    const s = await request(app).post("/cases/c1/anon-entities/suppress").send({ value: "config\\PowershellInfo.log" });
    expect(s.status).toBe(200);
    expect(s.body.suppressed).toEqual(["config\\powershellinfo.log"]);
    expect((await request(app).get("/cases/c1/anon-entities")).body.suppressed).toEqual(["config\\powershellinfo.log"]);

    const bad = await request(app).post("/cases/c1/anon-entities/suppress").send({});
    expect(bad.status).toBe(400);

    const u = await request(app).post("/cases/c1/anon-entities/unsuppress").send({ value: "config\\PowershellInfo.log" });
    expect(u.status).toBe(200);
    expect(u.body.suppressed).toEqual([]);
  });
});
