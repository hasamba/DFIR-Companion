// #1825 — the per-case AI budget (20/min) is spent only by requests that reach AI work. A request
// the route refuses first (a 400 for a malformed body, a 501, a 409 gate) or answers with a skip
// shape gets its slot back. Twenty malformed /import-log posts used to 429 the next /synthesize.

import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import express, { type Request, type Response } from "express";
import request from "supertest";
import {
  getAiLimiter,
  noteAiCallStarted,
  markAiBudgetUnspent,
  resetLimiters,
} from "../../src/http/rateLimiter.js";
import { mountAiRateLimit } from "../../src/composition/aiRateLimit.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SecondOpinionStore } from "../../src/analysis/secondOpinionStore.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../src/providers/provider.js";
import { emptyState } from "../../src/analysis/stateTypes.js";

const SYNTH = JSON.stringify({
  findings: [],
  iocs: [],
  mitreTechniques: [],
  threadsOpened: [],
  threadsClosed: [],
  timelineNote: "",
  summary: "s",
  forensicEvents: [],
  attackerPath: "",
  keyQuestions: [],
  nextSteps: [],
});

class CountingProvider implements AIProvider {
  readonly name = "counting";
  calls = 0;
  constructor(readonly model: string) {}
  async analyze(_req: AnalyzeRequest): Promise<AnalyzeResult> {
    this.calls += 1;
    return { rawText: SYNTH };
  }
}

async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-ai-refund-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const secondOpinionStore = new SecondOpinionStore(store);
  const a = new CountingProvider("model-a");
  const b = new CountingProvider("model-b");
  const pipeline = buildRuntimePipeline({
    provider: a,
    synthesisProvider: a,
    stateStore,
    store,
    secondOpinionProvider: b,
    secondOpinionStore,
    synthesisModelLabel: "model-A",
    secondOpinionModelLabel: "model-B",
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, {
    pipeline,
    stateStore,
    aiConfigured: true,
    secondOpinionStore,
    secondOpinionEnabled: true,
    jobManager: new JobManager({ perCaseConcurrency: 1 }),
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
  return { app, a, stateStore, pipeline };
}

async function seedEvent(stateStore: StateStore): Promise<void> {
  const state = emptyState("c1");
  state.forensicTimeline.push({
    id: "e1",
    timestamp: "2026-06-10T00:00:00.000Z",
    description: "beaconing to 203.0.113.7",
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
  });
  await stateStore.save(state);
}

/** True when the case still has its whole 20-request budget. Consumes it, so call it last. */
function budgetIsWhole(caseId: string): boolean {
  const limiter = getAiLimiter();
  for (let i = 0; i < 20; i++) if (!limiter.tryAcquire(caseId)) return false;
  return true;
}

beforeEach(() => resetLimiters());

describe("per-case AI budget refunds (#1825)", () => {
  it("malformed /import-log posts do not use the budget; real synthesis runs still do", async () => {
    const { app, a, stateStore } = await makeApp();
    for (let i = 0; i < 25; i++) {
      const res = await request(app).post("/cases/c1/import-log").send({ text: "" });
      expect(res.status).toBe(400);
    }
    await seedEvent(stateStore);
    const statuses: number[] = [];
    for (let i = 0; i < 21; i++)
      statuses.push((await request(app).post("/cases/c1/synthesize").send({})).status);
    expect(statuses.slice(0, 20)).toEqual(Array(20).fill(200));
    expect(statuses[20]).toBe(429);
    expect(a.calls).toBeGreaterThanOrEqual(20);
  });

  it("an empty-timeline synthesize skip gives its slot back", async () => {
    const { app, a } = await makeApp();
    for (let i = 0; i < 25; i++) {
      const res = await request(app).post("/cases/c1/synthesize").send({});
      expect(res.status).toBe(200);
      expect(res.body.skipped).toBe("empty-timeline");
    }
    expect(a.calls).toBe(0);
    expect(budgetIsWhole("c1")).toBe(true);
  });

  it("an empty-timeline second-opinion skip gives its slot back", async () => {
    const { app } = await makeApp();
    for (let i = 0; i < 25; i++) {
      const res = await request(app).post("/cases/c1/second-opinion").send({});
      expect(res.body.skipped).toBe("empty-timeline");
    }
    expect(budgetIsWhole("c1")).toBe(true);
  });
});

describe("the AI gate's refund rule (#1825)", () => {
  // A bare app with the real gate in front of stub AI routes, so each answer shape is tested alone.
  function stubApp(handler: (req: Request, res: Response) => void) {
    const app = express();
    mountAiRateLimit(app);
    app.post("/cases/:id/synthesize", handler);
    return app;
  }

  async function fire(app: express.Express, n: number): Promise<number[]> {
    const out: number[] = [];
    for (let i = 0; i < n; i++) out.push((await request(app).post("/cases/k/synthesize")).status);
    return out;
  }

  it.each([400, 404, 409, 501])("refunds a %i refusal", async (code) => {
    await fire(
      stubApp((_req, res) => void res.status(code).json({})),
      25,
    );
    expect(budgetIsWhole("k")).toBe(true);
  });

  it.each([200, 202, 499, 500])("keeps a %i answer charged", async (code) => {
    const statuses = await fire(
      stubApp((_req, res) => void res.status(code).json({})),
      21,
    );
    expect(statuses[20]).toBe(429);
  });

  it("refunds a 200 the route marked unspent", async () => {
    await fire(
      stubApp((_req, res) => {
        markAiBudgetUnspent(res);
        res.status(200).json({ skipped: "empty-timeline" });
      }),
      25,
    );
    expect(budgetIsWhole("k")).toBe(true);
  });

  it("keeps a 409 charged when a model call went out before it", async () => {
    const statuses = await fire(
      stubApp(async (_req, res) => {
        await new Promise((resolve) => setTimeout(resolve, 1));
        noteAiCallStarted(); // what the model-call chokepoint does, after an await in the route
        res.status(409).json({ error: "host_merge_decision_required" });
      }),
      21,
    );
    expect(statuses[20]).toBe(429);
  });

  // The deep-pass shape: real model calls, then a refusal at the end. The provider call itself must
  // pin the charge — no route has to remember to.
  it("a real provider call pins the charge even when the route then answers 409", async () => {
    const { a, stateStore, pipeline } = await makeApp();
    await seedEvent(stateStore);
    const statuses = await fire(
      stubApp(async (_req, res) => {
        await pipeline.synthesize("c1", { force: true });
        res.status(409).json({ error: "host_merge_decision_required" });
      }),
      21,
    );
    expect(a.calls).toBeGreaterThanOrEqual(20);
    expect(statuses[20]).toBe(429);
  });

  it("the 429 itself still carries Retry-After", async () => {
    const statuses = await fire(
      stubApp((_req, res) => void res.status(200).json({})),
      20,
    );
    expect(statuses.every((s) => s === 200)).toBe(true);
    const res = await request(stubApp((_req, r) => void r.status(200).json({}))).post("/cases/k/synthesize");
    expect(res.status).toBe(429);
    expect(Number(res.headers["retry-after"])).toBeGreaterThanOrEqual(1);
  });
});

// #1832 — non-AI routes are off the AI gate, and a gated route that answered without reaching a
// model gives its slot back. A real model call on the same routes still counts.
describe("answers that made no model call leave the AI budget alone (#1832)", () => {
  async function fire25(app: express.Express, path: string, body: object = {}): Promise<number[]> {
    const out: number[] = [];
    for (let i = 0; i < 25; i++) out.push((await request(app).post(`/cases/c1${path}`).send(body)).status);
    return out;
  }

  it.each([
    ["/velociraptor/suggest-hunts", {}], // nothing to pivot on in an empty case
    ["/timeline-gaps/hypothesize", {}], // no gaps
    ["/memory/next-steps", {}], // no memory evidence
  ])("%s on an empty case: 200, no model call, budget whole", async (path, body) => {
    const { app, a } = await makeApp();
    const statuses = await fire25(app, path, body);
    expect(statuses).toEqual(Array(25).fill(200));
    expect(a.calls).toBe(0);
    expect(budgetIsWhole("c1")).toBe(true);
  });

  it("/false-positive/suggest without ai: 200, budget whole", async () => {
    const { app, a, stateStore } = await makeApp();
    await seedEvent(stateStore);
    const statuses = await fire25(app, "/false-positive/suggest", { kind: "event", ref: "e1" });
    expect(statuses).toEqual(Array(25).fill(200));
    expect(a.calls).toBe(0);
    expect(budgetIsWhole("c1")).toBe(true);
  });

  it("/anon-control is not metered at all", async () => {
    const { app } = await makeApp();
    const statuses = await fire25(app, "/anon-control", { enabled: true });
    expect(statuses).toEqual(Array(25).fill(200));
    expect(budgetIsWhole("c1")).toBe(true);
  });

  it("a real model call on one of those routes still uses the budget", async () => {
    const { app, a } = await makeApp();
    const statuses: number[] = [];
    for (let i = 0; i < 21; i++)
      statuses.push(
        (await request(app).post("/cases/c1/adversary-hints/hunt-technique").send({ techniqueId: "T1059" }))
          .status,
      );
    expect(a.calls).toBeGreaterThanOrEqual(20);
    expect(statuses.slice(0, 20).every((s) => s !== 429)).toBe(true);
    expect(statuses[20]).toBe(429);
  });
});
