// The Re-synthesize button, held by the merge gate.
//
// THIS IS THE PATH THE FIRST FIX MISSED. `pipeline.synthesize()` throws the gate and five callers
// catch it; the first version of the change fixed only the post-import background path, so pressing
// "Re-synthesize" — precisely what an analyst does when they notice analysis is stuck — still
// produced a red "AI: error", a `failed` synthesis job, and an activity-log row with
// `outcome: "error"`. Every one of those told them the AI was broken when it was waiting on them.
//
// The route's catch also has an `if (aborted)` branch that returns 499 BEFORE the status is emitted,
// which is why the gate check has to come first; the last test here pins that ordering.
import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AssetOverridesStore } from "../../src/analysis/assetOverrides.js";
import { HostDuplicateDismissalStore } from "../../src/analysis/hostDuplicateDismissals.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import { SecondOpinionStore } from "../../src/analysis/secondOpinionStore.js";
import { createApp, type AiStatusEvent } from "../../src/server.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

function ev(id: string, asset: string): ForensicEvent {
  return {
    id,
    timestamp: "2026-04-22T11:41:00Z",
    description: "suspicious logon",
    severity: "High",
    mitreTechniques: ["T1078"],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset,
    sources: ["Sysmon"],
  };
}

let app: ReturnType<typeof createApp>;
let jobManager: JobManager;
let statusEvents: AiStatusEvent[];

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-synthgate-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(cases);
  const s = emptyState("c1");
  // The two spellings of one machine — what the gate exists to catch.
  s.forensicTimeline.push(ev("a", "WIN11"), ev("b", "WIN11.windomain.local"));
  await stateStore.save(s);

  const assetOverridesStore = new AssetOverridesStore(cases);
  const hostDuplicateDismissalStore = new HostDuplicateDismissalStore(cases);
  jobManager = new JobManager({ perCaseConcurrency: 1 });
  statusEvents = [];

  const pipeline = new AnalysisPipeline({
    stateStore,
    assetOverridesStore,
    hostDuplicateDismissalStore,
    // secondOpinion() checks for BOTH of these before it calls synthesize(). Without them it throws
    // its own "not configured" error and answers 500, never reaching the gate — which is how the
    // first version of this test passed while proving nothing about the second-opinion path.
    secondOpinionStore: new SecondOpinionStore(cases),
    secondOpinionProvider: {
      name: "fake-b",
      analyze: async () => {
        throw new Error("model B must not be called while a merge decision is pending");
      },
    } as never,
    // Never reached: the gate throws before a prompt is built. That is the whole point — the run
    // did not fail, it never started.
    synthesisProvider: {
      name: "fake",
      analyze: async () => {
        throw new Error("the model must not be called while a merge decision is pending");
      },
    } as never,
    imageLoader: async () => ({ data: Buffer.from(""), mediaType: "image/png" }) as never,
  });

  app = createApp(cases, {
    pipeline,
    stateStore,
    assetOverridesStore,
    hostDuplicateDismissalStore,
    jobManager,
    // Without this the /second-opinion route answers 501 before reaching the gate, and its test
    // below would pass by asserting nothing at all.
    secondOpinionEnabled: true,
    onAiStatus: (_caseId, event) => statusEvents.push(event),
  });
});

const synthesisJobs = () => jobManager.list("c1").filter((job) => job.kind === "synthesis");

describe("POST /cases/:id/synthesize with an unresolved duplicate host", () => {
  it("answers 409 with the pending pair rather than 500", async () => {
    const res = await request(app).post("/cases/c1/synthesize").send({});
    expect(res.status).toBe(409);
    expect(res.body.error).toBe("host_merge_decision_required");
    expect(res.body.pairs[0]).toMatchObject({ canonical: "win11.windomain.local", other: "win11" });
  });

  it("broadcasts blocked, and never error", async () => {
    await request(app).post("/cases/c1/synthesize").send({});
    const terminal = statusEvents.filter((e) => e.status !== "analyzing");
    expect(terminal.map((e) => e.status)).toContain("blocked");
    expect(statusEvents.map((e) => e.status)).not.toContain("error");
  });

  it("leaves no failed synthesis job for the cockpit to report", async () => {
    await request(app).post("/cases/c1/synthesize").send({});
    expect(synthesisJobs().map((job) => job.status)).not.toContain("failed");
  });

  // Resolving the pair must actually release the route — otherwise "blocked" would just be a nicer
  // word for permanently stuck. The model stub throws, so a 409 here would mean still gated while
  // anything else means the gate let the run through to the provider.
  it("stops gating once the pair is merged", async () => {
    await request(app)
      .post("/cases/c1/host-duplicates/merge")
      .send({ canonical: "win11.windomain.local", other: "win11" });
    const res = await request(app).post("/cases/c1/synthesize").send({});
    expect(res.status).not.toBe(409);
  });
});

describe("POST /cases/:id/second-opinion with an unresolved duplicate host", () => {
  it("reports the hold rather than a failed second opinion", async () => {
    const res = await request(app).post("/cases/c1/second-opinion").send({});
    // Asserted, not tolerated: a 501 here would mean the route never reached the gate and the two
    // status assertions below were vacuous.
    expect(res.status, "the route must actually run, not short-circuit on configuration").not.toBe(501);
    expect(res.status).toBe(409);
    expect(statusEvents.map((e) => e.status)).toContain("blocked");
    expect(statusEvents.map((e) => e.status)).not.toContain("error");
  });
});
