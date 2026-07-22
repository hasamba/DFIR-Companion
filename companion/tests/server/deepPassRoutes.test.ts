import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ActivityLogStore } from "../../src/analysis/activityLog.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { emptyState, type ForensicEvent, type Severity } from "../../src/analysis/stateTypes.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../src/providers/provider.js";

class ScriptedProvider implements AIProvider {
  readonly name = "scripted";
  readonly model = "mock-model";
  // When true, every batch (observation) call fails — the partial-coverage path under test.
  constructor(private readonly failBatches = false) {}
  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    if (/ONE SLICE/i.test(req.systemPrompt)) {
      if (this.failBatches) throw new Error("Bad control character in string literal in JSON");
      return { rawText: JSON.stringify({ observations: [{ summary: "s", eventIds: ["c0"], whyItMatters: "w" }] }) };
    }
    return {
      rawText: JSON.stringify({
        findings: [], iocs: [], mitreTechniques: [], attackerPath: "", summary: "s",
        forensicEvents: [], threadsOpened: [], threadsClosed: [], timelineNote: "",
      }),
    };
  }
}

// Letters, not numbers: patternKey normalizes bare numbers to <n>, so numbered descriptions would all
// collapse into one grouped row and the counts under test would be meaningless.
function title(i: number): string {
  const a = "abcdefghijklmnopqrstuvwxyz";
  return `${a[Math.floor(i / 26) % 26]}${a[i % 26]}`;
}

function events(): ForensicEvent[] {
  const mk = (n: number, sev: Severity, p: string): ForensicEvent[] =>
    Array.from({ length: n }, (_, i) => ({
      id: `${p}${i}`,
      timestamp: `2026-05-20T${String(i % 24).padStart(2, "0")}:${String(i % 60).padStart(2, "0")}:00Z`,
      description: `${p} detection ${title(i)}`,
      severity: sev,
      mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [],
    }));
  return [
    ...mk(10, "Critical", "c"), ...mk(40, "High", "h"), ...mk(60, "Medium", "m"),
    ...mk(90, "Low", "l"), ...mk(20, "Info", "i"),
  ];
}

async function makeApp(opts: { aiConfigured?: boolean; failBatches?: boolean } = {}) {
  const root = await mkdtemp(join(tmpdir(), "dfir-deeppass-routes-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const provider = new ScriptedProvider(opts.failBatches === true);
  // hasSynthesisProvider() is `synthesisProvider ?? provider`, so an "AI not configured" pipeline must
  // omit BOTH — leaving the vision provider in place would still satisfy the gate.
  const pipeline = buildRuntimePipeline({
    ...(opts.aiConfigured === false ? {} : { provider, synthesisProvider: provider }),
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, {
    pipeline, stateStore, aiConfigured: opts.aiConfigured !== false,
    activityLogStore: new ActivityLogStore(store),
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
  await stateStore.save({ ...emptyState("c1"), forensicTimeline: events() });
  return { app, stateStore };
}

describe("deep-pass routes", () => {
  beforeEach(() => {
    process.env.DFIR_AI_SYNTH_MAX_EVENTS = "100";
    delete process.env.DFIR_DEEP_PASS_MAX_BATCHES;
  });

  it("GET .../deep-pass/preview returns one row per floor, most severe first", async () => {
    const { app } = await makeApp();

    const res = await request(app).get("/cases/c1/deep-pass/preview");

    expect(res.status).toBe(200);
    expect(res.body.floors.map((f: { floor: string }) => f.floor)).toEqual(["Critical", "High", "Medium", "Low"]);
    for (const f of res.body.floors) {
      expect(f).toHaveProperty("events");
      expect(f).toHaveProperty("rows");
      expect(f).toHaveProperty("batches");
      expect(f).toHaveProperty("estimatedInputTokens");
    }
  });

  it("preview never counts Info events, which never reach a prompt", async () => {
    const { app } = await makeApp();

    const res = await request(app).get("/cases/c1/deep-pass/preview");

    const low = res.body.floors.find((f: { floor: string }) => f.floor === "Low");
    expect(low.events).toBe(200);   // 10 + 40 + 60 + 90, the 20 Info excluded
  });

  it("POST .../deep-pass rejects an unparseable minSeverity rather than defaulting", async () => {
    const { app } = await makeApp();

    const res = await request(app).post("/cases/c1/deep-pass").send({ minSeverity: "banana" });

    expect(res.status).toBe(400);   // must NOT silently fall back to reading everything
  });

  it("POST .../deep-pass runs the pass and returns its summary", async () => {
    const { app } = await makeApp();

    const res = await request(app).post("/cases/c1/deep-pass").send({ minSeverity: "High" });

    expect(res.status).toBe(200);
    expect(res.body.floor).toBe("High");
    expect(res.body.batches).toBeGreaterThan(0);
    expect(res.body.aborted).toBe(false);
  });

  it("refusing an over-ceiling run is a 400 that names the problem, not a 500", async () => {
    const { app } = await makeApp();
    process.env.DFIR_DEEP_PASS_MAX_BATCHES = "1";

    const res = await request(app).post("/cases/c1/deep-pass").send({ minSeverity: "Low" });

    expect(res.status).toBe(400);
    expect(String(res.body.error)).toMatch(/batches/i);
  });

  it("501s when no synthesis provider is configured", async () => {
    const { app } = await makeApp({ aiConfigured: false });

    const res = await request(app).post("/cases/c1/deep-pass").send({ minSeverity: "High" });

    expect(res.status).toBe(501);
  });

  // A deep pass ends in a forced synthesize() that REWRITES the case conclusions. /synthesize itself
  // refuses that on a closed or archived case (423); without the same guard here the dashboard's Run
  // button would be a way to spend many minutes and hundreds of thousands of tokens rewriting a case
  // the analyst has already signed off.
  it("423s on a closed case rather than re-writing its conclusions", async () => {
    const { app } = await makeApp();
    await request(app).patch("/cases/c1/status").send({ status: "closed" });

    const res = await request(app).post("/cases/c1/deep-pass").send({ minSeverity: "High" });

    expect(res.status).toBe(423);
    expect(String(res.body.error)).toMatch(/closed/i);
  });

  it("423s on an archived case", async () => {
    const { app } = await makeApp();
    await request(app).patch("/cases/c1/status").send({ status: "closed" });
    await request(app).post("/cases/c1/archive").send({ removeFromList: true });

    const res = await request(app).post("/cases/c1/deep-pass").send({ minSeverity: "High" });

    expect(res.status).toBe(423);
  });

  // A run whose batches failed read LESS than it appears to. The HTTP body is transient — the
  // activity log is the durable record an analyst re-reads days later, so partial coverage has to
  // survive there too, or an incomplete read is silently filed as a complete one.
  it("records failed batches in the activity log, not just in the response body", async () => {
    const { app } = await makeApp({ failBatches: true });

    const res = await request(app).post("/cases/c1/deep-pass").send({ minSeverity: "High" });
    expect(res.status).toBe(200);
    expect(res.body.batchesFailed).toBeGreaterThan(0);

    const log = await request(app).get("/cases/c1/activity-log");
    const entry = log.body.find((e: { action: string }) => e.action === "deep-pass");
    expect(entry).toBeTruthy();
    expect(String(entry.detail)).toMatch(/fail/i);
  });

  // The dashboard must be able to DISABLE the Run button up front instead of letting the analyst
  // click into a 501. /health.aiEnabled is the VISION gate (hasAiProvider) and answers the wrong
  // question here — deep pass runs on the synthesis provider.
  it("/health reports whether a SYNTHESIS provider is configured", async () => {
    const { app } = await makeApp();

    const res = await request(app).get("/health");

    expect(res.body.synthesisEnabled).toBe(true);
  });

  it("/health reports synthesisEnabled false with no provider", async () => {
    const { app } = await makeApp({ aiConfigured: false });

    const res = await request(app).get("/health");

    expect(res.body.synthesisEnabled).toBe(false);
  });

  it("says nothing about failures when every batch succeeded", async () => {
    const { app } = await makeApp();

    await request(app).post("/cases/c1/deep-pass").send({ minSeverity: "High" });

    const log = await request(app).get("/cases/c1/activity-log");
    const entry = log.body.find((e: { action: string }) => e.action === "deep-pass");
    expect(String(entry.detail)).not.toMatch(/fail/i);
  });
});
