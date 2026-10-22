import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { beforeEach, describe, expect, it } from "vitest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, setServerLogger } from "../../src/server.js";
import { createConsoleLogger } from "../../src/logging/logger.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { bundledSigmaDir, ruleFiles } from "../../src/analysis/sigmaBundledRules.js";
import { SigmaRuleStore } from "../../src/analysis/sigmaRuleStore.js";
import { createZip } from "../../src/analysis/zipArchive.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// Settings → Sigma rules routes (#2204). File installs only: nothing here touches the network.

const BUNDLED = bundledSigmaDir() as string;
const zipBase64 = createZip(
  ruleFiles(BUNDLED).files.map((f) => ({ path: f.path, data: Buffer.from(`${f.text}\n# next\n`) })),
).toString("base64");

let store: CaseStore;
let sigma: SigmaRuleStore;

beforeEach(async () => {
  const dir = await mkdtemp(join(tmpdir(), "dfir-sigma-routes-"));
  store = new CaseStore(join(dir, "cases"));
  setServerLogger(createConsoleLogger("error"));
  sigma = new SigmaRuleStore(dir, BUNDLED, {});
  await sigma.init();
});

const app = (opts: Record<string, unknown> = {}) =>
  createApp(store, { stateStore: new StateStore(store), sigmaRuleStore: sigma, ...opts });

describe("Sigma rules routes", () => {
  it("reports the active release, settings and counts", async () => {
    const res = await request(app()).get("/sigma/status");
    expect(res.status).toBe(200);
    expect(res.body.active).toMatchObject({ id: "bundled", release: "r2026-07-01" });
    expect(res.body.settings.statuses).toEqual({
      statuses: ["stable", "test"],
      ignored: [],
      defaulted: true,
    });
    expect(res.body.settings.minLevel).toEqual({ level: "high" });
    expect(res.body.counts["aws-cloudtrail"].loaded).toBe(28);
  });

  it("lists the rules with outcomes", async () => {
    const res = await request(app()).get("/sigma/rules");
    expect(res.status).toBe(200);
    expect(res.body.rules.some((r: { outcome: string }) => r.outcome === "disabled")).toBe(true);
  });

  it("previews a file, installs it and rolls back", async () => {
    const a = app();
    const prev = await request(a)
      .post("/sigma/preview")
      .send({ source: "file", name: "rules.zip", zipBase64 });
    expect(prev.status).toBe(200);
    expect(prev.body.preview.diff.changed.length).toBeGreaterThan(0);
    expect(prev.body.preview.release).toMatchObject({ release: "file rules.zip", verified: false });

    const inst = await request(a).post("/sigma/install").send({ token: prev.body.preview.token });
    expect(inst.status).toBe(200);
    expect(inst.body.active.release).toBe("file rules.zip");

    const back = await request(a).post("/sigma/rollback").send({});
    expect(back.status).toBe(200);
    expect(back.body.active.id).toBe("bundled");
  });

  it("answers a bad archive with 422 and a sentence, and an unknown token with 404", async () => {
    const bad = await request(app())
      .post("/sigma/preview")
      .send({ source: "file", name: "x.zip", zipBase64: Buffer.from("nope").toString("base64") });
    expect(bad.status).toBe(422);
    expect(bad.body.error).toMatch(/zip/);
    const gone = await request(app()).post("/sigma/install").send({ token: "nope" });
    expect(gone.status).toBe(404);
  });

  it("turns a rule off and back on", async () => {
    const a = app();
    const id = "4f77e1d7-3982-4ee0-8489-abf2d6b75284";
    expect((await request(a).put("/sigma/disabled").send({ id, disabled: false })).status).toBe(200);
    const rules = (await request(a).get("/sigma/rules")).body.rules as { id: string; outcome: string }[];
    expect(rules.find((r) => r.id === id)?.outcome).toBe("loaded");
    expect((await request(a).put("/sigma/disabled").send({ id: "", disabled: true })).status).toBe(400);
  });

  it("refuses changes in the demo", async () => {
    const res = await request(app({ demoMode: true }))
      .post("/sigma/rollback")
      .send({});
    expect(res.status).toBe(403);
  });

  it("answers 501 without a store", async () => {
    const res = await request(createApp(store, { stateStore: new StateStore(store) })).get("/sigma/status");
    expect(res.status).toBe(501);
  });
});

// #2217: the per-case coverage card. Analyst-only and read-only: nothing here reaches an AI prompt.
describe("GET /cases/:id/sigma/coverage", () => {
  const ev = (id: string, origin?: string): ForensicEvent => ({
    id,
    timestamp: "2026-06-01T00:00:00Z",
    description: `event ${id}`,
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...(origin ? { sources: [origin] } : {}),
  });

  async function seeded() {
    await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const superTimelineStore = new SuperTimelineStore(store, 100000);
    await superTimelineStore.append("c1", [
      ev("a1", "AWS CloudTrail"),
      ev("a2", "AWS CloudTrail"),
      ev("w1", "Windows.EventLogs.Evtx"),
    ]);
    return superTimelineStore;
  }

  it("lists each origin with its Sigma sources and state", async () => {
    const res = await request(app({ superTimelineStore: await seeded() })).get("/cases/c1/sigma/coverage");
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ enabled: true, graded: 1, total: 2 });
    expect(res.body.rows[0]).toMatchObject({ origin: "AWS CloudTrail", events: 2, state: "covered" });
    expect(res.body.rows[0].sigmaSources[0]).toMatchObject({ id: "aws-cloudtrail", loaded: 28 });
    expect(res.body.rows[1]).toMatchObject({
      origin: "Windows.EventLogs.Evtx",
      events: 1,
      state: "not-graded",
    });
  });

  it("says sigma-off on every row when grading is switched off", async () => {
    const prev = process.env.DFIR_SIGMA_RULES;
    process.env.DFIR_SIGMA_RULES = "off";
    try {
      const res = await request(app({ superTimelineStore: await seeded() })).get("/cases/c1/sigma/coverage");
      expect(res.body.enabled).toBe(false);
      expect(res.body.rows.map((r: { state: string }) => r.state)).toEqual(["sigma-off", "sigma-off"]);
    } finally {
      if (prev === undefined) delete process.env.DFIR_SIGMA_RULES;
      else process.env.DFIR_SIGMA_RULES = prev;
    }
  });

  it("answers 404 for a case that does not exist", async () => {
    const res = await request(app({ superTimelineStore: new SuperTimelineStore(store, 10) })).get(
      "/cases/nope/sigma/coverage",
    );
    expect(res.status).toBe(404);
    expect(res.body.error).toMatch(/case nope not found/);
  });

  it("answers 501 without the Sigma store or the super-timeline store", async () => {
    expect((await request(app()).get("/cases/c1/sigma/coverage")).status).toBe(501);
    const noSigma = createApp(store, {
      stateStore: new StateStore(store),
      superTimelineStore: new SuperTimelineStore(store, 10),
    });
    expect((await request(noSigma).get("/cases/c1/sigma/coverage")).status).toBe(501);
  });
});
