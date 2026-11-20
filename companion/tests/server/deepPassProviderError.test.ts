// #2766: the deep pass used to tell its own "too many batches" refusal apart from everything else by
// searching the error text for "batches". A provider failure whose text happened to say "batches"
// (a 429 "too many batches queued") was then reported as a budget refusal: a 400, a job marked not
// retryable, and a pill telling the analyst to raise the severity floor. The refusal is now a typed
// error, so a provider failure stays a retryable provider failure whatever its text says.
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
import { JobLedgerStore } from "../../src/analysis/jobLedgerStore.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import { enableCaseAi } from "../helpers/enableCaseAi.js";
import { DeepPassBudgetError } from "../../src/analysis/ai/deepPassRun.js";

const PROVIDER_429 = "HTTP 429: too many batches queued for this key";

/** Answers every batch read, then fails the final synthesis call the way a busy provider does. */
class BusyProvider implements AIProvider {
  readonly name = "busy";
  readonly model = "mock-model";
  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    if (/ONE SLICE/i.test(req.systemPrompt)) {
      return {
        rawText: JSON.stringify({ observations: [{ summary: "s", eventIds: ["h0"], whyItMatters: "w" }] }),
      };
    }
    throw new Error(PROVIDER_429);
  }
}

function events(): ForensicEvent[] {
  const letters = "abcdefghijklmnopqrstuvwxyz";
  const mk = (n: number, sev: Severity, p: string): ForensicEvent[] =>
    Array.from({ length: n }, (_, i) => ({
      id: `${p}${i}`,
      timestamp: `2026-05-20T${String(i % 24).padStart(2, "0")}:${String(i % 60).padStart(2, "0")}:00Z`,
      description: `${p} detection ${letters[Math.floor(i / 26) % 26]}${letters[i % 26]}`,
      severity: sev,
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
    }));
  return [...mk(10, "Critical", "c"), ...mk(40, "High", "h"), ...mk(150, "Low", "l")];
}

async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-deeppass-provider-error-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const provider = new BusyProvider();
  const jobManager = new JobManager({ ledger: new JobLedgerStore(store) });
  const aiStatus: { status: string; detail?: string }[] = [];
  const app = createApp(store, {
    pipeline: buildRuntimePipeline({
      provider,
      synthesisProvider: provider,
      stateStore,
      store,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    }),
    stateStore,
    aiConfigured: true,
    jobManager,
    onAiStatus: (_caseId, evt) => void aiStatus.push(evt),
  });
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
  await enableCaseAi(store, "c1");
  await stateStore.save({ ...emptyState("c1"), forensicTimeline: events() });
  const deepPassJob = () => jobManager.list("c1").find((j) => j.kind === "deep-pass");
  return { app, aiStatus, deepPassJob };
}

describe("deep pass: budget refusal vs provider failure (#2766)", () => {
  beforeEach(() => {
    process.env.DFIR_AI_SYNTH_MAX_EVENTS = "100";
    delete process.env.DFIR_DEEP_PASS_MAX_BATCHES;
  });

  it("reports a provider failure that mentions batches as a retryable provider error", async () => {
    const { app, aiStatus, deepPassJob } = await makeApp();

    const res = await request(app).post("/cases/c1/deep-pass").send({ minSeverity: "High" });

    expect(res.status).toBe(500);
    const job = deepPassJob();
    expect(job?.status).toBe("failed");
    expect(job?.failure).toMatchObject({ code: "deep_pass_failed", retryable: true });
    expect(aiStatus.at(-1)?.status).toBe("error");
    expect(aiStatus.some((e) => /raise the severity floor/i.test(String(e.detail)))).toBe(false);
  });

  it("still refuses an over-ceiling run as a non-retryable budget refusal", async () => {
    const { app, aiStatus, deepPassJob } = await makeApp();
    process.env.DFIR_DEEP_PASS_MAX_BATCHES = "1";

    const res = await request(app).post("/cases/c1/deep-pass").send({ minSeverity: "Low" });

    expect(res.status).toBe(400);
    expect(String(res.body.error)).toMatch(/batches, above the 1 limit/);
    const job = deepPassJob();
    expect(job?.failure).toMatchObject({ code: "budget_exceeded", retryable: false });
    expect(aiStatus.at(-1)).toMatchObject({
      status: "idle",
      detail: "deep pass not started — raise the severity floor",
    });
  });

  it("the budget refusal is a typed error that keeps its Error message", () => {
    const err = new DeepPassBudgetError("deep pass needs 3 batches, above the 1 limit. ");
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe("DeepPassBudgetError");
    expect(err.message).toMatch(/3 batches/);
  });
});
