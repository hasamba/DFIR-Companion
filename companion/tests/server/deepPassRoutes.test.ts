import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { emptyState, type ForensicEvent, type Severity } from "../../src/analysis/stateTypes.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../src/providers/provider.js";

class ScriptedProvider implements AIProvider {
  readonly name = "scripted";
  readonly model = "mock-model";
  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    if (/ONE SLICE/i.test(req.systemPrompt)) {
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

async function makeApp(opts: { aiConfigured?: boolean } = {}) {
  const root = await mkdtemp(join(tmpdir(), "dfir-deeppass-routes-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const provider = new ScriptedProvider();
  // hasSynthesisProvider() is `synthesisProvider ?? provider`, so an "AI not configured" pipeline must
  // omit BOTH — leaving the vision provider in place would still satisfy the gate.
  const pipeline = buildRuntimePipeline({
    ...(opts.aiConfigured === false ? {} : { provider, synthesisProvider: provider }),
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, { pipeline, stateStore, aiConfigured: opts.aiConfigured !== false });
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
});
