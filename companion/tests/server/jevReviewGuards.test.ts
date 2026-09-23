import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, readdir } from "node:fs/promises";
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

// Two guards on the paid Jev review: it never creates a case by being pointed at a typo (#1549),
// and it never runs twice at once for the same case, each run billing the analyst (#1551).

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

/** Jev's reply to every question, in the shape the grader reads. */
function answer(body: string): string {
  const questions = JSON.parse(body).questions as Record<string, { type: string }>;
  const answers: Record<string, unknown> = {};
  for (const [id, q] of Object.entries(questions)) {
    answers[id] =
      q.type === "noul"
        ? { type: "noul", noul: 0 }
        : { type: "score", score: 1, legend: {}, probabilities: {}, confidence: 0.5 };
  }
  return JSON.stringify({
    model: "jev-stub",
    answers,
    usage: { input_tokens: 1, output_tokens: 1, cost: 0.000001 },
  });
}

async function caseRoot(ids: string[]) {
  const root = await mkdtemp(join(tmpdir(), "dfir-jev-guard-"));
  const cases = new CaseStore(root);
  const stateStore = new StateStore(cases);
  const superTimelineStore = new SuperTimelineStore(cases);
  for (const caseId of ids) {
    await cases.createCase({ caseId, name: "n", investigator: "i", aiProvider: null });
    await stateStore.save(emptyState(caseId));
    await superTimelineStore.append(caseId, [
      raw(`${caseId}-a`, "certutil -urlcache"),
      raw(`${caseId}-b`, "update"),
    ]);
  }
  return { root, cases, stateStore, superTimelineStore };
}

describe("the Jev review's guards", () => {
  const saved: Record<string, string | undefined> = {};
  let jev: ReturnType<typeof createServer>;
  let calls = 0;
  let delayMs = 0;
  let status = 200;

  beforeEach(async () => {
    for (const k of JEV_ENV) {
      saved[k] = process.env[k];
      delete process.env[k];
    }
    calls = 0;
    delayMs = 0;
    status = 200;
    jev = createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        calls += 1;
        setTimeout(() => {
          res.writeHead(status, { "content-type": "application/json" });
          res.end(status === 200 ? answer(body) : JSON.stringify({ error: { message: "down" } }));
        }, delayMs);
      });
    });
    await new Promise<void>((resolve) => jev.listen(0, "127.0.0.1", resolve));
    process.env.DFIR_JEV_ENABLED = "1";
    process.env.DFIR_JEV_KEY = "jev-test-credential-NOTAREALKEY";
    process.env.DFIR_JEV_BASE_URL = `http://127.0.0.1:${(jev.address() as AddressInfo).port}/decisions`;
  });

  afterEach(async () => {
    for (const k of JEV_ENV) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
    await new Promise<void>((resolve) => jev.close(() => resolve()));
  });

  it("answers 404 for a case that does not exist, and creates nothing on disk (#1549)", async () => {
    const { root, cases, stateStore, superTimelineStore } = await caseRoot(["c1"]);
    const app = createApp(cases, { stateStore, superTimelineStore });
    // After createApp: the app writes its own instance secret into the root at startup.
    const before = [...(await readdir(root))].sort();
    const res = await request(app).post("/cases/typo-case/jev/review").send({});
    expect(res.status).toBe(404);
    expect(String(res.body.error)).toMatch(/not found/);
    expect([...(await readdir(root))].sort()).toEqual(before);
    expect(await readdir(root)).not.toContain("typo-case");
    expect(calls).toBe(0);
  });

  it("refuses a second run for the same case while the first is in flight (#1551)", async () => {
    const { cases, stateStore, superTimelineStore } = await caseRoot(["c1"]);
    const app = createApp(cases, { stateStore, superTimelineStore });
    const solo = await request(app).post("/cases/c1/jev/review").send({});
    expect(solo.status).toBe(200);
    const oneRun = calls;
    expect(oneRun).toBeGreaterThan(0);

    calls = 0;
    delayMs = 250;
    const [a, b] = await Promise.all([
      request(app).post("/cases/c1/jev/review").send({}),
      request(app).post("/cases/c1/jev/review").send({}),
    ]);
    expect([a.status, b.status].sort()).toEqual([200, 409]);
    const refused = a.status === 409 ? a : b;
    expect(String(refused.body.error)).toMatch(/already running/);
    expect(calls).toBe(oneRun);
  });

  it("lets the next run start once a run has finished, whether it succeeded or failed", async () => {
    const { cases, stateStore, superTimelineStore } = await caseRoot(["c1"]);
    const app = createApp(cases, { stateStore, superTimelineStore });
    expect((await request(app).post("/cases/c1/jev/review").send({})).status).toBe(200);
    expect((await request(app).post("/cases/c1/jev/review").send({})).status).toBe(200);

    // 401 rather than 500: a 5xx is retried with backoff, which makes this a 15-second test for no
    // extra coverage. Either way the route answers 502 and the run is over.
    status = 401;
    expect((await request(app).post("/cases/c1/jev/review").send({})).status).toBe(502);
    status = 200;
    expect((await request(app).post("/cases/c1/jev/review").send({})).status).toBe(200);
  });

  it("releases the case when the run throws before it reaches Jev", async () => {
    const { cases, stateStore, superTimelineStore } = await caseRoot(["c1"]);
    let failNext = true;
    const flaky = new Proxy(stateStore, {
      get(target, prop) {
        if (prop === "load" && failNext) {
          failNext = false;
          return () => Promise.reject(new Error("state store unavailable"));
        }
        const value = Reflect.get(target, prop) as unknown;
        return typeof value === "function" ? (value as (...a: unknown[]) => unknown).bind(target) : value;
      },
    });
    const app = createApp(cases, { stateStore: flaky, superTimelineStore });
    const first = await request(app).post("/cases/c1/jev/review").send({});
    expect(first.status).toBeGreaterThanOrEqual(500);
    const second = await request(app).post("/cases/c1/jev/review").send({});
    expect(second.status).toBe(200);
  });

  it("holds the lock per case: two different cases run at the same time", async () => {
    const { cases, stateStore, superTimelineStore } = await caseRoot(["c1", "c2"]);
    const app = createApp(cases, { stateStore, superTimelineStore });
    delayMs = 250;
    const [a, b] = await Promise.all([
      request(app).post("/cases/c1/jev/review").send({}),
      request(app).post("/cases/c2/jev/review").send({}),
    ]);
    expect(a.status).toBe(200);
    expect(b.status).toBe(200);
  });
});
