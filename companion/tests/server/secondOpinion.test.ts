import { describe, it, expect, beforeEach } from "vitest";
import { resetLimiters } from "../../src/http/rateLimiter.js";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SecondOpinionStore } from "../../src/analysis/secondOpinionStore.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../src/providers/provider.js";
import { emptyState, type InvestigationState } from "../../src/analysis/stateTypes.js";

// A provider that returns the synthesis delta for the Pass-1 (synthesis) call and the reconcile
// JSON for the Pass-2 (reconcile) call — distinguished by the RECONCILE system prompt marker.
class ScriptedProvider implements AIProvider {
  readonly name = "scripted";
  reconcileCalls = 0; // how many times THIS provider was asked to referee (#1466)
  lastReconcilePrompt = "";
  constructor(
    private readonly synth: string,
    private readonly reconcile: string,
    readonly model = "mock-model",
  ) {}
  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    if (/RECONCILING/i.test(req.systemPrompt)) {
      this.reconcileCalls += 1;
      this.lastReconcilePrompt = req.userPrompt;
      return { rawText: this.reconcile };
    }
    return { rawText: this.synth };
  }
}

// Model A (primary synthesis) and model B (second opinion) produce DIFFERENT analyses. The second
// opinion re-synthesizes A first (Pass 0) then dry-runs B, so the two providers must be distinct for
// a disagreement to exist. Both are valid deltaSchema shapes.
const SYNTH_A = JSON.stringify({
  findings: [
    {
      id: "f1",
      severity: "High",
      confidence: 80,
      title: "Shared finding",
      description: "d",
      relatedIocs: [],
      mitreTechniques: ["T1078"],
      status: "open",
      relatedEventIds: [],
    },
    {
      id: "f2",
      severity: "Medium",
      confidence: 60,
      title: "A only finding",
      description: "A keeps this",
      relatedIocs: [],
      mitreTechniques: [],
      status: "open",
      relatedEventIds: [],
    },
  ],
  iocs: [],
  mitreTechniques: [{ id: "T1078", name: "Valid Accounts" }],
  threadsOpened: [],
  threadsClosed: [],
  timelineNote: "",
  summary: "A's summary",
  forensicEvents: [],
  attackerPath: "",
  keyQuestions: [],
  nextSteps: [],
});

const SYNTH_B = JSON.stringify({
  findings: [
    {
      id: "g1",
      severity: "High",
      confidence: 80,
      title: "Shared finding",
      description: "d",
      relatedIocs: [],
      mitreTechniques: ["T1071"],
      status: "open",
      relatedEventIds: [],
    },
    {
      id: "g3",
      severity: "Critical",
      confidence: 90,
      title: "B only finding",
      description: "B found a C2 beacon",
      relatedIocs: [],
      mitreTechniques: [],
      status: "open",
      relatedEventIds: ["e1"],
    },
  ],
  iocs: [],
  mitreTechniques: [{ id: "T1071", name: "Application Layer Protocol" }],
  threadsOpened: [],
  threadsClosed: [],
  timelineNote: "",
  summary: "B's summary",
  forensicEvents: [],
  attackerPath: "",
  keyQuestions: [],
  nextSteps: [],
});

const RECONCILE = JSON.stringify({
  summary: "Model B surfaces a C2 finding A missed.",
  verdicts: [
    { id: "b_only:b-finding-only", rationale: "Supported by event e1.", recommendation: "accept_b" },
  ],
});

// Only the timeline is seeded; model A's findings/MITRE come from the Pass-0 primary re-synthesis.
function seededState(): InvestigationState {
  const s = emptyState("c1");
  s.forensicTimeline.push({
    id: "e1",
    timestamp: "2026-06-10T00:00:00.000Z",
    description: "beaconing to 1.2.3.4",
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
  });
  return s;
}

// Every provider can answer a reconcile call, so which one ACTUALLY referees is observable (#1466):
// model A by default, model B or a third model when `referee` says so.
async function makeApp(opts: { enabled: boolean; referee?: "b" | "c" }) {
  const root = await mkdtemp(join(tmpdir(), "dfir-secopinion-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const secondOpinionStore = new SecondOpinionStore(store);
  const aProvider = new ScriptedProvider(SYNTH_A, RECONCILE, "model-a");
  const bProvider = new ScriptedProvider(SYNTH_B, RECONCILE, "model-b");
  const cProvider = new ScriptedProvider(SYNTH_A, RECONCILE, "model-c");
  const referee =
    opts.referee === "b"
      ? { provider: bProvider, label: "model-B" }
      : opts.referee === "c"
        ? { provider: cProvider, label: "model-C" }
        : undefined;
  const pipeline = buildRuntimePipeline({
    provider: aProvider,
    synthesisProvider: aProvider,
    stateStore,
    store,
    secondOpinionProvider: opts.enabled ? bProvider : undefined,
    secondOpinionStore,
    synthesisModelLabel: "model-A",
    secondOpinionModelLabel: "model-B",
    referee,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, {
    pipeline,
    stateStore,
    aiConfigured: true,
    secondOpinionStore,
    secondOpinionEnabled: opts.enabled,
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
  await stateStore.save(seededState());
  return { app, stateStore, aProvider, bProvider, cProvider };
}

// The AI limiter is process-wide (20 calls / 60 s); this file now runs enough second opinions to
// trip it, so each test starts from a clean window.
beforeEach(() => resetLimiters());

describe("who referees the verdicts (#1466)", () => {
  it("model A referees by default — model B never judges its own disagreements", async () => {
    const { app, aProvider, bProvider } = await makeApp({ enabled: true });
    const res = await request(app).post("/cases/c1/second-opinion").send({});
    expect(res.status).toBe(200);
    expect(res.body.referee).toBe("model-A");
    expect(aProvider.reconcileCalls).toBe(1);
    expect(bProvider.reconcileCalls).toBe(0);
  });

  it("'same-as-b' hands the whistle to model B", async () => {
    const { app, aProvider, bProvider } = await makeApp({ enabled: true, referee: "b" });
    const res = await request(app).post("/cases/c1/second-opinion").send({});
    expect(res.body.referee).toBe("model-B");
    expect(bProvider.reconcileCalls).toBe(1);
    expect(aProvider.reconcileCalls).toBe(0);
  });

  it("a third model referees when configured, and neither A nor B is asked", async () => {
    const { app, aProvider, bProvider, cProvider } = await makeApp({ enabled: true, referee: "c" });
    const res = await request(app).post("/cases/c1/second-opinion").send({});
    expect(res.body.referee).toBe("model-C");
    expect(cProvider.reconcileCalls).toBe(1);
    expect(aProvider.reconcileCalls + bProvider.reconcileCalls).toBe(0);
  });

  it("the referee is shown the forensic events the disputed finding cites", async () => {
    const { app, aProvider } = await makeApp({ enabled: true });
    await request(app).post("/cases/c1/second-opinion").send({});
    // SYNTH_B's B-only finding cites e1; the seeded timeline holds e1's description.
    expect(aProvider.lastReconcilePrompt).toMatch(/\[e1\] .*\[(Critical|High|Medium|Low|Info)\]/);
  });
});

describe("Second opinion routes (#116)", () => {
  it("runs an independent re-synthesis + reconcile and returns the disagreement deltas", async () => {
    const { app } = await makeApp({ enabled: true });
    const res = await request(app).post("/cases/c1/second-opinion").send({});
    expect(res.status).toBe(200);
    expect(res.body.modelA).toBe("model-A");
    expect(res.body.modelB).toBe("model-B");
    expect(res.body.agreementCount).toBe(1); // "Shared finding"
    const kinds = res.body.deltas.map((d: { kind: string }) => d.kind).sort();
    expect(kinds).toEqual(["a_only", "b_only", "mitre_added", "mitre_removed"]);
    const bOnly = res.body.deltas.find((d: { kind: string }) => d.kind === "b_only");
    expect(bOnly.title).toBe("B only finding");
    expect(bOnly.rationale).toBe("Supported by event e1.");
    expect(bOnly.recommendation).toBe("accept_b");
    expect(bOnly.status).toBe("pending");
  });

  it("re-synthesizes the primary (model A) first, so a stale saved finding is refreshed out before comparing", async () => {
    const { app, stateStore } = await makeApp({ enabled: true });
    // Inject a stale finding the fresh primary synthesis (SYNTH_A) does NOT reproduce.
    const s = await stateStore.load("c1");
    s.findings.push({
      id: "stale",
      severity: "Low",
      title: "Stale leftover finding",
      description: "",
      relatedIocs: [],
      sourceScreenshots: [],
      mitreTechniques: [],
      firstSeen: "2026-06-01T00:00:00.000Z",
      lastUpdated: "2026-06-01T00:00:00.000Z",
      status: "open",
    });
    await stateStore.save(s);
    await request(app).post("/cases/c1/second-opinion").send({});
    // Pass 0 re-synthesized A (findings replaced by SYNTH_A), so the stale finding is gone from the
    // case and never surfaces as a phantom "only in A" delta.
    const rec = await request(app)
      .get("/cases/c1/second-opinion")
      .then((r) => r.body);
    expect(rec.deltas.some((d: { title: string }) => d.title === "Stale leftover finding")).toBe(false);
    expect((await stateStore.load("c1")).findings.some((f) => f.title === "Stale leftover finding")).toBe(
      false,
    );
  });

  it("accepting a b_only delta adds the finding to the case (durably) and records the decision", async () => {
    const { app, stateStore } = await makeApp({ enabled: true });
    await request(app).post("/cases/c1/second-opinion").send({});
    const res = await request(app)
      .post("/cases/c1/second-opinion/apply")
      .send({ deltaId: "b_only:b-finding-only", accept: true });
    expect(res.status).toBe(200);
    expect(res.body.deltas.find((d: { id: string }) => d.id === "b_only:b-finding-only").status).toBe(
      "accepted",
    );
    const state = await stateStore.load("c1");
    expect(state.findings.find((f) => f.title === "B only finding")?.id).toBe("so:b-only-finding");
  });

  it("rejecting a delta records the decision without changing the case", async () => {
    const { app, stateStore } = await makeApp({ enabled: true });
    await request(app).post("/cases/c1/second-opinion").send({});
    const before = (await stateStore.load("c1")).findings.length;
    const res = await request(app)
      .post("/cases/c1/second-opinion/apply")
      .send({ deltaId: "b_only:b-finding-only", accept: false });
    expect(res.status).toBe(200);
    expect(res.body.deltas.find((d: { id: string }) => d.id === "b_only:b-finding-only").status).toBe(
      "rejected",
    );
    expect((await stateStore.load("c1")).findings).toHaveLength(before);
  });

  it("accept-all applies every pending delta in one call", async () => {
    const { app, stateStore } = await makeApp({ enabled: true });
    await request(app).post("/cases/c1/second-opinion").send({});
    const res = await request(app).post("/cases/c1/second-opinion/apply-all").send({ accept: true });
    expect(res.status).toBe(200);
    expect(res.body.deltas.every((d: { status: string }) => d.status === "accepted")).toBe(true);
    expect((await stateStore.load("c1")).findings.some((f) => f.title === "B only finding")).toBe(true);
  });

  it("reject-all records the decisions without changing the case", async () => {
    const { app, stateStore } = await makeApp({ enabled: true });
    await request(app).post("/cases/c1/second-opinion").send({});
    const before = (await stateStore.load("c1")).findings.length;
    const res = await request(app).post("/cases/c1/second-opinion/apply-all").send({ accept: false });
    expect(res.status).toBe(200);
    expect(res.body.deltas.every((d: { status: string }) => d.status === "rejected")).toBe(true);
    expect((await stateStore.load("c1")).findings).toHaveLength(before);
  });

  it("apply-all leaves an already-decided delta untouched", async () => {
    const { app } = await makeApp({ enabled: true });
    await request(app).post("/cases/c1/second-opinion").send({});
    await request(app)
      .post("/cases/c1/second-opinion/apply")
      .send({ deltaId: "a_only:finding-only", accept: false });
    const res = await request(app).post("/cases/c1/second-opinion/apply-all").send({ accept: true });
    const byId = (id: string) => res.body.deltas.find((d: { id: string }) => d.id === id).status;
    expect(byId("a_only:finding-only")).toBe("rejected");
    expect(
      res.body.deltas
        .filter((d: { id: string }) => d.id !== "a_only:finding-only")
        .every((d: { status: string }) => d.status === "accepted"),
    ).toBe(true);
  });

  it("GET returns the stored record after a run", async () => {
    const { app } = await makeApp({ enabled: true });
    await request(app).post("/cases/c1/second-opinion").send({});
    const res = await request(app).get("/cases/c1/second-opinion");
    expect(res.status).toBe(200);
    expect(res.body.deltas.length).toBe(4);
  });

  it("GET returns null before any run", async () => {
    const { app } = await makeApp({ enabled: true });
    const res = await request(app).get("/cases/c1/second-opinion");
    expect(res.status).toBe(200);
    expect(res.body).toBeNull();
  });

  it("apply 404s an unknown delta id", async () => {
    const { app } = await makeApp({ enabled: true });
    await request(app).post("/cases/c1/second-opinion").send({});
    const res = await request(app)
      .post("/cases/c1/second-opinion/apply")
      .send({ deltaId: "b_only:nope", accept: true });
    expect(res.status).toBe(404);
  });

  it("501s when no second-opinion model is configured", async () => {
    const { app } = await makeApp({ enabled: false });
    const res = await request(app).post("/cases/c1/second-opinion").send({});
    expect(res.status).toBe(501);
  });
});
