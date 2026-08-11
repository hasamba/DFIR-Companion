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
    const res = await request(app)
      .post("/cases/c1/anon-control")
      .send({ categories: { IP: false, USER: null } });
    expect(res.status).toBe(200);
    expect(res.body.categories.IP).toBe(false); // valid boolean applied
    expect(res.body.categories.USER).toBe(true); // non-boolean ignored → kept at default (true)
    const reloaded = (await request(app).get("/cases/c1/anon-control")).body.categories;
    expect(reloaded.IP).toBe(false);
    expect(reloaded.USER).toBe(true);
  });

  // The anonymization panel shows a "Real names (people)" row it cannot deliver on its own (PERSON
  // tokens are minted only from Presidio findings), so it needs to know whether the layer is wired.
  // Both verbs answer with the same shape — the panel re-reads the control from the POST response.
  it("reports presidioConfigured=false when DFIR_PRESIDIO_URL is unset", async () => {
    expect((await request(app).get("/cases/c1/anon-control")).body.presidioConfigured).toBe(false);
    const post = await request(app).post("/cases/c1/anon-control").send({ enabled: true });
    expect(post.body.presidioConfigured).toBe(false);
  });
  it("reports presidioConfigured=true when DFIR_PRESIDIO_URL is set", async () => {
    // Captured when the routes are registered — the same moment startServer decides whether to give
    // the pipeline a Presidio client — so the app must be built AFTER the variable is set.
    process.env.DFIR_PRESIDIO_URL = "http://127.0.0.1:5002";
    try {
      const withPresidio = createApp(cases, { stateStore: new StateStore(cases) });
      expect((await request(withPresidio).get("/cases/c1/anon-control")).body.presidioConfigured).toBe(true);
      const post = await request(withPresidio).post("/cases/c1/anon-control").send({ enabled: false });
      expect(post.body.presidioConfigured).toBe(true);
    } finally {
      delete process.env.DFIR_PRESIDIO_URL;
    }
  });
  it("treats a blank DFIR_PRESIDIO_URL as unset (an unset compose variable interpolates to '')", async () => {
    process.env.DFIR_PRESIDIO_URL = "   ";
    try {
      const blank = createApp(cases, { stateStore: new StateStore(cases) });
      expect((await request(blank).get("/cases/c1/anon-control")).body.presidioConfigured).toBe(false);
    } finally {
      delete process.env.DFIR_PRESIDIO_URL;
    }
  });
});

describe("/cases/:id/anon-entities", () => {
  it("GET returns auto + custom; POST replaces custom (sanitized, unknown cat → OTHER)", async () => {
    const get0 = await request(app).get("/cases/c1/anon-entities");
    expect(get0.status).toBe(200);
    expect(Array.isArray(get0.body.auto.hosts)).toBe(true);
    expect(get0.body.custom).toEqual([]);
    const post = await request(app)
      .post("/cases/c1/anon-entities")
      .send({
        entities: [
          { value: "DC9", category: "HOST" },
          { value: "x", category: "bogus" },
        ],
      });
    expect(post.status).toBe(200);
    expect(post.body.custom).toEqual([
      { value: "DC9", category: "HOST" },
      { value: "x", category: "OTHER" },
    ]);
    expect((await request(app).get("/cases/c1/anon-entities")).body.custom.length).toBe(2);
  });

  it("GET surfaces OCR-discovered entities in the grouped auto set (by category)", async () => {
    const { DiscoveredEntitiesStore } = await import("../../src/analysis/anonDiscovered.js");
    const disc = new DiscoveredEntitiesStore(cases);
    await disc.addDiscovered("c1", [
      { value: "WIN11\\vagrant", category: "USER" },
      { value: "10.0.0.5", category: "IP" },
      { value: "45.61.136.10", category: "EXTIP" },
    ]);
    const res = await request(app).get("/cases/c1/anon-entities");
    expect(res.status).toBe(200);
    expect(res.body.auto.accounts).toContain("WIN11\\vagrant");
    expect(res.body.auto.ips).toContain("10.0.0.5");
    // Public IPs auto-discovered from screenshots must be surfaced (and reachable by /suppress),
    // not silently dropped from the response the entities UI reads.
    expect(res.body.auto.extIps).toContain("45.61.136.10");
  });

  it("suppress removes an entity (vetoes it) and unsuppress restores it; GET reflects the list", async () => {
    const s = await request(app)
      .post("/cases/c1/anon-entities/suppress")
      .send({ value: "config\\PowershellInfo.log" });
    expect(s.status).toBe(200);
    expect(s.body.suppressed).toEqual(["config\\powershellinfo.log"]);
    expect((await request(app).get("/cases/c1/anon-entities")).body.suppressed).toEqual([
      "config\\powershellinfo.log",
    ]);

    const bad = await request(app).post("/cases/c1/anon-entities/suppress").send({});
    expect(bad.status).toBe(400);

    const u = await request(app)
      .post("/cases/c1/anon-entities/unsuppress")
      .send({ value: "config\\PowershellInfo.log" });
    expect(u.status).toBe(200);
    expect(u.body.suppressed).toEqual([]);
  });
});
