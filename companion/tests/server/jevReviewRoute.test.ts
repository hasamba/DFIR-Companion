import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { createApp } from "../../src/server.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import { JevGradeStore } from "../../src/analysis/ai/jev/jevGradeRecord.js";

// The Jev review is OFF unless the analyst turns it on, and it reads the raw record — so the two
// properties worth pinning at the route are that an unconfigured install offers nothing, and that
// a configured one still writes no case state.

const raw = (id: string, description: string): ForensicEvent => ({
  id,
  timestamp: "2026-01-01T00:00:00Z",
  description,
  severity: "Info",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
});

const JEV_ENV = [
  "DFIR_JEV_ENABLED",
  "DFIR_JEV_KEY",
  "DFIR_JEV_PROVIDER",
  "DFIR_JEV_BASE_URL",
  "DFIR_JEV_MODEL",
] as const;

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-jev-route-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(cases);
  await stateStore.save(emptyState("c1"));
  const superTimelineStore = new SuperTimelineStore(cases);
  await superTimelineStore.append("c1", [
    raw("raw1", "certutil -urlcache -split -f http://h/a.txt"),
    raw("raw2", "routine update check"),
  ]);
  const app = createApp(cases, { stateStore, superTimelineStore });
  return { app, stateStore };
}

describe("the Jev review route", () => {
  const saved: Record<string, string | undefined> = {};
  beforeEach(() => {
    for (const k of JEV_ENV) {
      saved[k] = process.env[k];
      delete process.env[k];
    }
  });
  afterEach(() => {
    for (const k of JEV_ENV) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  });

  it("is off by default: status reports unconfigured, with a reason the analyst can act on", async () => {
    const { app } = await harness();
    const res = await request(app).get("/cases/c1/jev/status");
    expect(res.status).toBe(200);
    expect(res.body.configured).toBe(false);
    expect(String(res.body.reason)).toMatch(/\S/);
  });

  it("refuses to run when it is not configured, rather than failing mid-review", async () => {
    const { app } = await harness();
    const res = await request(app).post("/cases/c1/jev/review").send({});
    expect(res.status).toBe(501);
    expect(String(res.body.error)).toMatch(/\S/);
  });

  it("never names the API key in the status reason", async () => {
    process.env.DFIR_JEV_ENABLED = "1";
    process.env.DFIR_JEV_KEY = "jev-test-credential-NOTAREALKEY";
    const { app } = await harness();
    const res = await request(app).get("/cases/c1/jev/status");
    expect(JSON.stringify(res.body)).not.toContain("NOTAREALKEY");
  });

  it("leaves the forensic timeline empty when the service refuses the call", async () => {
    // A real endpoint that rejects, rather than a dead port: a refused connection is retried with
    // backoff and would make this a 15-second test for no extra coverage. 401 is not retried.
    const server = createServer((_req, res) => {
      res.writeHead(401, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: { message: "no credentials" } }));
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as AddressInfo).port;
    try {
      process.env.DFIR_JEV_ENABLED = "1";
      process.env.DFIR_JEV_KEY = "jev-test-credential-NOTAREALKEY";
      process.env.DFIR_JEV_BASE_URL = `http://127.0.0.1:${port}/decisions`;
      const { app, stateStore } = await harness();
      const res = await request(app).post("/cases/c1/jev/review").send({ limit: 2 });
      expect(res.status).toBe(502);
      expect(String(res.body.error)).not.toContain("NOTAREALKEY");
      expect((await stateStore.load("c1")).forensicTimeline).toEqual([]);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});

describe("what the analyst is told about coverage", () => {
  const saved: Record<string, string | undefined> = {};
  let jev: ReturnType<typeof createServer>;
  let jevUrl = "";

  beforeEach(async () => {
    for (const k of JEV_ENV) {
      saved[k] = process.env[k];
      delete process.env[k];
    }
    // A Jev stand-in that answers whatever it is asked, so the route's arithmetic is what is tested.
    jev = createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        const questions = JSON.parse(body).questions as Record<string, { type: string }>;
        const answers: Record<string, unknown> = {};
        for (const [id, q] of Object.entries(questions)) {
          answers[id] =
            q.type === "noul"
              ? { type: "noul", noul: 0 }
              : { type: "score", score: 1, legend: {}, probabilities: {}, confidence: 0.5 };
        }
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            model: "jev-stub",
            answers,
            usage: { input_tokens: 1, output_tokens: 1, cost: 0.000001 },
          }),
        );
      });
    });
    await new Promise<void>((resolve) => jev.listen(0, "127.0.0.1", resolve));
    process.env.DFIR_JEV_ENABLED = "1";
    process.env.DFIR_JEV_KEY = "jev-test-credential-NOTAREALKEY";
    jevUrl = `http://127.0.0.1:${(jev.address() as AddressInfo).port}/decisions`;
    process.env.DFIR_JEV_BASE_URL = jevUrl;
  });

  afterEach(async () => {
    for (const k of JEV_ENV) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
    await new Promise<void>((resolve) => jev.close(() => resolve()));
  });

  /** `archive` rows in the super-timeline, the first `analyzed` of them also in the forensic one. */
  async function caseRoot(archive: number, analyzed: number) {
    const root = await mkdtemp(join(tmpdir(), "dfir-jev-cov-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const stateStore = new StateStore(cases);
    const rows = Array.from({ length: archive }, (_, i) => raw(`r${i}`, `row ${i}`));
    await stateStore.save({ ...emptyState("c1"), forensicTimeline: rows.slice(0, analyzed) });
    const superTimelineStore = new SuperTimelineStore(cases);
    await superTimelineStore.append("c1", rows);
    return { cases, stateStore, superTimelineStore };
  }

  async function caseWith(archive: number, analyzed: number) {
    const { cases, stateStore, superTimelineStore } = await caseRoot(archive, analyzed);
    return createApp(cases, { stateStore, superTimelineStore });
  }

  it("does NOT blame the cap when the cap was never reached (#1540)", async () => {
    // The shipped bug: 1,344 matched against a 2,000 cap, 366 already analyzed, and the panel said
    // "the row cap stopped the read". The cap read everything; the shortfall was the skipped rows.
    const app = await caseWith(10, 4);
    const res = await request(app).post("/cases/c1/jev/review").send({});
    expect(res.status).toBe(200);
    expect(res.body.matched).toBe(10);
    expect(res.body.read).toBe(10);
    expect(res.body.alreadyAnalyzed).toBe(4);
    expect(res.body.graded).toBe(6);
    expect(res.body.capped).toBe(false);
  });

  it("does blame the cap when the cap really did hold rows back", async () => {
    const app = await caseWith(10, 0);
    const res = await request(app).post("/cases/c1/jev/review").send({ limit: 3 });
    expect(res.body.matched).toBe(10);
    expect(res.body.read).toBe(3);
    expect(res.body.graded).toBe(3);
    expect(res.body.capped).toBe(true);
  });

  it("accounts for every matching row: read + unread, and analyzed + graded", async () => {
    const app = await caseWith(10, 4);
    const { matched, read, alreadyAnalyzed, graded } = (
      await request(app).post("/cases/c1/jev/review").send({})
    ).body;
    expect(alreadyAnalyzed + graded).toBe(read);
    expect(read).toBeLessThanOrEqual(matched);
  });

  it("says nothing was graded, and why, when every matching row is already analyzed", async () => {
    const app = await caseWith(5, 5);
    const res = await request(app).post("/cases/c1/jev/review").send({});
    expect(res.body.graded).toBe(0);
    expect(res.body.alreadyAnalyzed).toBe(5);
    expect(res.body.capped).toBe(false);
    expect(res.body.rows).toEqual([]);
  });

  it("reads every matching row when the analyst asks for it, past the default cap", async () => {
    // The cap is a DEFAULT, not a ceiling. 2,500 rows against a 2,000 default: the normal press
    // stops at 2,000 and says so; `all` pages through the lot and claims full coverage honestly.
    const app = await caseWith(2500, 0);
    const capped = await request(app).post("/cases/c1/jev/review").send({});
    expect(capped.body.read).toBe(2000);
    expect(capped.body.capped).toBe(true);
    expect(capped.body.readAll).toBe(false);

    const full = await request(app).post("/cases/c1/jev/review").send({ all: true });
    expect(full.body.matched).toBe(2500);
    expect(full.body.read).toBe(2500);
    expect(full.body.graded).toBe(2500);
    expect(full.body.capped).toBe(false);
    expect(full.body.readAll).toBe(true);
  }, 60_000);

  it("pages past a single query's ceiling rather than silently stopping at one page", async () => {
    // One store query is ceilinged, so a full read that did not page would stop at a page boundary
    // and report `capped: false` — full coverage claimed over a slice, the exact lie to avoid.
    const app = await caseWith(2100, 0);
    const res = await request(app).post("/cases/c1/jev/review").send({ all: true });
    expect(res.body.read).toBe(2100);
    expect(res.body.capped).toBe(false);
  }, 60_000);

  it("still promotes nothing on an uncapped read", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-jev-all-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const stateStore = new StateStore(cases);
    await stateStore.save(emptyState("c1"));
    const superTimelineStore = new SuperTimelineStore(cases);
    await superTimelineStore.append(
      "c1",
      Array.from({ length: 50 }, (_, i) => raw(`r${i}`, `row ${i}`)),
    );
    const app = createApp(cases, { stateStore, superTimelineStore });
    await request(app).post("/cases/c1/jev/review").send({ all: true });
    expect((await stateStore.load("c1")).forensicTimeline).toEqual([]);
  });

  // #1578. The promote route writes a severity from the server's record of what a review graded,
  // never from the browser. So the review has to leave that record behind, before it answers.
  it("records every row it graded, with the model that graded it", async () => {
    const { cases, stateStore, superTimelineStore } = await caseRoot(5, 2);
    const app = createApp(cases, { stateStore, superTimelineStore });
    const res = await request(app).post("/cases/c1/jev/review").send({});
    expect(res.status).toBe(200);

    const record = await new JevGradeStore(cases).load("c1");
    // r0 and r1 are already analyzed, so the review never graded them and must not claim it did.
    expect([...record.keys()].sort()).toEqual(["r2", "r3", "r4"]);
    for (const graded of res.body.rows as { id: string; grade: string; confidence: number }[]) {
      expect(record.get(graded.id)).toMatchObject({
        grade: graded.grade,
        confidence: graded.confidence,
        model: res.body.model,
      });
    }
  });

  it("merges a second review into the record rather than replacing it", async () => {
    const { cases, stateStore, superTimelineStore } = await caseRoot(6, 0);
    const app = createApp(cases, { stateStore, superTimelineStore });
    expect((await request(app).post("/cases/c1/jev/review").send({ limit: 2 })).status).toBe(200);
    const first = await new JevGradeStore(cases).load("c1");
    expect([...first.keys()].sort()).toEqual(["r0", "r1"]);

    // A second review that reads further keeps the first review's rows and adds its own.
    expect((await request(app).post("/cases/c1/jev/review").send({ limit: 4 })).status).toBe(200);
    expect([...(await new JevGradeStore(cases).load("c1")).keys()].sort()).toEqual(["r0", "r1", "r2", "r3"]);
  });

  it("answers 500, not the grades, when it cannot record them", async () => {
    const { cases, stateStore, superTimelineStore } = await caseRoot(3, 0);
    const broken = new JevGradeStore(cases);
    broken.record = () => Promise.reject(new Error("disk full"));
    const app = createApp(cases, { stateStore, superTimelineStore, jevGradeStore: broken });

    const res = await request(app).post("/cases/c1/jev/review").send({});

    expect(res.status).toBe(500);
    expect(String(res.body.error)).toMatch(/could not be saved/i);
    expect(String(res.body.error)).toContain("disk full");
    expect(res.body.rows).toBeUndefined();
  });
});
