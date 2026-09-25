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
import { FalsePositiveStore } from "../../src/analysis/falsePositive.js";
import { PresidioApprovalRequired } from "../../src/analysis/presidio.js";
import { SynthMetaStore } from "../../src/analysis/synthMeta.js";
import { ProviderError } from "../../src/providers/provider.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../src/providers/provider.js";
import { emptyState, type InvestigationState } from "../../src/analysis/stateTypes.js";

// A provider that returns the synthesis delta for the Pass-1 (synthesis) call and the reconcile
// JSON for the Pass-2 (reconcile) call — distinguished by the RECONCILE system prompt marker.
class ScriptedProvider implements AIProvider {
  readonly name = "scripted";
  reconcileCalls = 0; // how many times THIS provider was asked to referee (#1466)
  lastReconcilePrompt = "";
  failReconcile = false;
  synthCalls = 0; // how many synthesis passes THIS provider ran (a referee-only re-run must add none)
  reconcileThrows?: Error; // throw this instead of "referee down" (e.g. the Presidio gate)
  reconcileReply?: string; // answer this instead of the scripted reconcile JSON
  reconcileGate?: Promise<void>; // hold the referee call open until the test releases it
  constructor(
    private readonly synth: string,
    private readonly reconcile: string,
    readonly model = "mock-model",
  ) {}
  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    if (/RECONCILING/i.test(req.systemPrompt)) {
      this.reconcileCalls += 1;
      this.lastReconcilePrompt = req.userPrompt;
      if (this.reconcileGate) await this.reconcileGate;
      if (this.reconcileThrows) throw this.reconcileThrows;
      if (this.failReconcile) throw new Error("referee down");
      return { rawText: this.reconcileReply ?? this.reconcile };
    }
    this.synthCalls += 1;
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
    { id: "a_only:finding-only", rationale: "A's finding stands.", recommendation: "keep_a" },
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
async function makeApp(opts: { enabled: boolean; referee?: "b" | "c"; synthA?: string }) {
  const root = await mkdtemp(join(tmpdir(), "dfir-secopinion-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const secondOpinionStore = new SecondOpinionStore(store);
  const aProvider = new ScriptedProvider(opts.synthA ?? SYNTH_A, RECONCILE, "model-a");
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
  return { app, stateStore, store, aProvider, bProvider, cProvider, pipeline };
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

  it("an analyst-marked false positive never reaches the referee, even when a finding cites it", async () => {
    const { app, store, aProvider } = await makeApp({ enabled: true });
    await new FalsePositiveStore(store).save("c1", [
      {
        id: "event:e1",
        kind: "event",
        ref: "e1",
        reason: "known-good-tool",
        note: "",
        markedAt: "2026-06-11T00:00:00.000Z",
        markedBy: "analyst",
      },
    ]);
    await request(app).post("/cases/c1/second-opinion").send({});
    expect(aProvider.reconcileCalls).toBe(1);
    expect(aProvider.lastReconcilePrompt).not.toContain("[e1]");
    expect(aProvider.lastReconcilePrompt).toMatch(/no cited events/);
  });

  it("a failed verdict pass leaves referee '' — nobody is credited with verdicts that were never written", async () => {
    const { app, aProvider } = await makeApp({ enabled: true });
    aProvider.failReconcile = true;
    const res = await request(app).post("/cases/c1/second-opinion").send({});
    expect(res.status).toBe(200);
    expect(res.body.referee).toBe("");
    expect(res.body.deltas.every((d: { rationale: string }) => d.rationale === "")).toBe(true);
  });
});

// #1587 — a failed referee used to look exactly like a referee that chose to say nothing.
describe("a failed referee pass is recorded, shown and re-runnable (#1587)", () => {
  async function failedRun(opts: { referee?: "b" | "c" } = {}) {
    const made = await makeApp({ enabled: true, ...opts });
    // "auth" is not retried, so the failure lands on the first attempt instead of after backoff.
    made.aProvider.reconcileThrows = new ProviderError("referee down: Codex CLI not found", "auth");
    const res = await request(made.app).post("/cases/c1/second-opinion").send({});
    made.aProvider.reconcileThrows = undefined;
    return { ...made, res };
  }

  it("the saved record names the referee that failed and why, and keeps every delta", async () => {
    const { app, res } = await failedRun();
    expect(res.status).toBe(200);
    expect(res.body.referee).toBe(""); // #1466: nobody is credited with verdicts never written
    expect(res.body.refereeError).toMatchObject({
      referee: "model-A",
      message: expect.stringMatching(/referee down/),
    });
    expect(Date.parse(res.body.refereeError.at)).not.toBeNaN();
    expect(res.body.deltas).toHaveLength(4);
    // Survives the store's schema round trip — a field the loader drops is a field nobody sees.
    const saved = await request(app).get("/cases/c1/second-opinion");
    expect(saved.body.refereeError.referee).toBe("model-A");
    expect(typeof saved.body.refereePrompt).toBe("string");
  });

  it("a successful run carries no failure and no saved prompt", async () => {
    const { app } = await makeApp({ enabled: true });
    const res = await request(app).post("/cases/c1/second-opinion").send({});
    expect(res.body.refereeError).toBeUndefined();
    expect(res.body.refereePrompt).toBeUndefined();
  });

  it("a referee answer that matches no disagreement is a failure, not an empty success", async () => {
    const { app, aProvider } = await makeApp({ enabled: true });
    aProvider.reconcileReply = JSON.stringify({
      summary: "ok",
      verdicts: [{ id: "nope", rationale: "x", recommendation: "keep_a" }],
    });
    const res = await request(app).post("/cases/c1/second-opinion").send({});
    expect(res.body.referee).toBe("");
    expect(res.body.refereeError.message).toMatch(/no verdict/i);
  });

  it("the error message is flattened and capped before it is saved", async () => {
    const { app, aProvider } = await makeApp({ enabled: true });
    aProvider.reconcileThrows = new ProviderError(`line one\n\tline two\u0007 ${"x".repeat(2000)}`, "auth");
    const res = await request(app).post("/cases/c1/second-opinion").send({});
    const msg: string = res.body.refereeError.message;
    expect(msg.startsWith("line one line two")).toBe(true);
    expect(msg).not.toMatch(/[\u0000-\u001f]/);
    expect(msg.length).toBeLessThanOrEqual(300);
  });

  it("re-running only the referee fills the verdicts, clears the failure, and re-runs no synthesis", async () => {
    const { app, aProvider, bProvider } = await failedRun();
    const synthBefore = aProvider.synthCalls + bProvider.synthCalls;
    const res = await request(app).post("/cases/c1/second-opinion/referee").send({});
    expect(res.status).toBe(200);
    expect(res.body.referee).toBe("model-A");
    expect(res.body.refereeError).toBeUndefined();
    expect(res.body.refereePrompt).toBeUndefined();
    expect(res.body.summary).toBe("Model B surfaces a C2 finding A missed.");
    const bOnly = res.body.deltas.find((d: { kind: string }) => d.kind === "b_only");
    expect(bOnly.recommendation).toBe("accept_b");
    expect(aProvider.synthCalls + bProvider.synthCalls).toBe(synthBefore);
    const saved = await request(app).get("/cases/c1/second-opinion");
    expect(saved.body.refereeError).toBeUndefined();
    expect(saved.body.referee).toBe("model-A");
  });

  it("the re-run replays the exact prompt the failed attempt was given", async () => {
    const { app, aProvider, stateStore } = await failedRun();
    const firstPrompt = aProvider.lastReconcilePrompt;
    // Evidence changes after the failure; the re-run must still judge the saved comparison.
    const s = await stateStore.load("c1");
    await stateStore.save({ ...s, forensicTimeline: [] });
    await request(app).post("/cases/c1/second-opinion/referee").send({});
    expect(aProvider.lastReconcilePrompt).toBe(firstPrompt);
  });

  it("an analyst decision made while the referee is thinking survives the re-run", async () => {
    const { app, aProvider } = await failedRun();
    let release!: () => void;
    aProvider.reconcileGate = new Promise((r) => (release = r));
    const rerun = request(app)
      .post("/cases/c1/second-opinion/referee")
      .send({})
      .then((r) => r);
    await new Promise((r) => setTimeout(r, 50)); // let the re-run reach the held referee call
    const applied = await request(app)
      .post("/cases/c1/second-opinion/apply")
      .send({ deltaId: "a_only:finding-only", accept: false });
    expect(applied.status).toBe(200);
    release();
    const res = await rerun;
    expect(res.status).toBe(200);
    const aOnly = res.body.deltas.find((d: { id: string }) => d.id === "a_only:finding-only");
    expect(aOnly.status).toBe("rejected");
    expect(aOnly.recommendation).toBe("keep_a");
  });

  it("a re-run whose comparison was replaced by a newer run refuses to write", async () => {
    const { app, aProvider, store } = await failedRun();
    let release!: () => void;
    aProvider.reconcileGate = new Promise((r) => (release = r));
    const rerun = request(app)
      .post("/cases/c1/second-opinion/referee")
      .send({})
      .then((r) => r);
    await new Promise((r) => setTimeout(r, 50));
    const soStore = new SecondOpinionStore(store);
    const current = (await soStore.load("c1"))!;
    await soStore.save("c1", { ...current, generatedAt: "2099-01-01T00:00:00.000Z" });
    release();
    const res = await rerun;
    expect(res.status).toBe(409);
    expect(res.body.error).toMatch(/newer second opinion/i);
    expect((await soStore.load("c1"))!.generatedAt).toBe("2099-01-01T00:00:00.000Z");
  });

  it("a second re-run while one is in flight is refused, and the first one still lands", async () => {
    const { app, aProvider } = await failedRun();
    let release!: () => void;
    aProvider.reconcileGate = new Promise((r) => (release = r));
    const first = request(app)
      .post("/cases/c1/second-opinion/referee")
      .send({})
      .then((r) => r);
    await new Promise((r) => setTimeout(r, 50));
    const second = await request(app).post("/cases/c1/second-opinion/referee").send({});
    expect(second.status).toBe(409);
    expect(second.body.error).toMatch(/already running/);
    release();
    const res = await first;
    expect(res.status).toBe(200);
    expect(res.body.referee).toBe("model-A");
    expect(aProvider.reconcileCalls).toBe(2); // the failed full-run attempt + the one re-run
  });

  it("a re-run that fails again answers 502 with the record and a fresh failure time", async () => {
    const { app, aProvider, res: first } = await failedRun();
    aProvider.reconcileThrows = new ProviderError("referee down again", "auth");
    await new Promise((r) => setTimeout(r, 5));
    const res = await request(app).post("/cases/c1/second-opinion/referee").send({});
    expect(res.status).toBe(502);
    expect(res.body.error).toMatch(/referee down/);
    expect(res.body.record.refereeError.referee).toBe("model-A");
    expect(res.body.record.refereeError.at > first.body.refereeError.at).toBe(true);
    expect(res.body.record.deltas).toHaveLength(4);
  });

  it("the Presidio gate is passed to the analyst, not recorded as a broken referee", async () => {
    const { app, aProvider } = await failedRun();
    aProvider.reconcileThrows = new PresidioApprovalRequired([]);
    const res = await request(app).post("/cases/c1/second-opinion/referee").send({});
    expect(res.status).toBe(409);
    expect(res.body.error).toBe("presidio_approval_required");
  });

  it("refuses a re-run when there is no record, or nothing failed", async () => {
    const { app } = await makeApp({ enabled: true });
    expect((await request(app).post("/cases/c1/second-opinion/referee").send({})).status).toBe(409);
    await request(app).post("/cases/c1/second-opinion").send({});
    const res = await request(app).post("/cases/c1/second-opinion/referee").send({});
    expect(res.status).toBe(409);
    expect(res.body.error).toMatch(/did not fail/i);
  });

  it("a successful re-run updates the referee in the agreement telemetry", async () => {
    const { app, store } = await failedRun();
    await request(app).post("/cases/c1/second-opinion/referee").send({});
    const meta = await new SynthMetaStore(store).load("c1");
    expect(meta?.secondOpinionPerf?.referee).toBe("model-A");
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

  it("follow-referee accepts accept_b, rejects keep_a, and leaves review deltas pending", async () => {
    const { app, stateStore } = await makeApp({ enabled: true });
    await request(app).post("/cases/c1/second-opinion").send({});
    const res = await request(app).post("/cases/c1/second-opinion/apply-all").send({ followReferee: true });
    expect(res.status).toBe(200);
    const byId = (id: string) => res.body.deltas.find((d: { id: string }) => d.id === id);
    expect(byId("b_only:b-finding-only").status).toBe("accepted");
    expect(byId("a_only:finding-only").status).toBe("rejected");
    const rest = res.body.deltas.filter(
      (d: { id: string }) => d.id !== "b_only:b-finding-only" && d.id !== "a_only:finding-only",
    );
    expect(rest.length).toBeGreaterThan(0);
    expect(rest.every((d: { status: string }) => d.status === "pending")).toBe(true);
    expect((await stateStore.load("c1")).findings.some((f) => f.title === "B only finding")).toBe(true);
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

// #1590 — an accepted decision follows its finding by identity, survives a later second-opinion
// run, and is reported when it no longer matches any finding.
describe("accepted decisions survive re-synthesis and later runs (#1590)", () => {
  // Model A's second finding cites e1 and carries a technique, so it has identity evidence.
  function synthA(title: string, technique: string, severity = "Medium"): string {
    const base = JSON.parse(SYNTH_A);
    base.findings[1] = {
      ...base.findings[1],
      title,
      severity,
      mitreTechniques: [technique],
      relatedEventIds: ["e1"],
    };
    return JSON.stringify(base);
  }
  // Model B agrees on "A only finding" except for its severity, so the run yields a severity delta.
  function synthBWithSeverity(title: string, technique: string): string {
    const base = JSON.parse(SYNTH_B);
    base.findings.push({ ...JSON.parse(synthA(title, technique, "Low")).findings[1], id: "g9" });
    return JSON.stringify(base);
  }
  const setSynth = (p: ScriptedProvider, text: string): void => {
    (p as unknown as { synth: string }).synth = text;
  };
  const f2 = async (stateStore: StateStore) =>
    (await stateStore.load("c1")).findings.find((f) => f.id === "f2");

  it("a dismissal stays applied after a re-synthesis retitles and retags the finding", async () => {
    const { app, stateStore, aProvider, pipeline } = await makeApp({ enabled: true });
    setSynth(aProvider, synthA("A only finding", "T1219"));
    const run = await request(app).post("/cases/c1/second-opinion").send({});
    const dismissal = run.body.deltas.find((d: { kind: string }) => d.kind === "a_only");
    await request(app).post("/cases/c1/second-opinion/apply").send({ deltaId: dismissal.id, accept: true });
    expect((await f2(stateStore))?.status).toBe("dismissed");

    setSynth(aProvider, synthA("Remote tooling staged in a user profile", "T1105"));
    await pipeline.synthesize("c1", { force: true });
    const after = await f2(stateStore);
    expect(after?.title).toBe("Remote tooling staged in a user profile");
    expect(after?.status).toBe("dismissed");
  });

  it("a severity change still applies after a second second-opinion run and a re-synthesis", async () => {
    const { app, stateStore, aProvider, bProvider, pipeline } = await makeApp({ enabled: true });
    setSynth(aProvider, synthA("A only finding", "T1219"));
    setSynth(bProvider, synthBWithSeverity("A only finding", "T1219"));
    const run = await request(app).post("/cases/c1/second-opinion").send({});
    const sev = run.body.deltas.find((d: { kind: string }) => d.kind === "severity");
    expect(sev).toBeDefined();
    await request(app).post("/cases/c1/second-opinion/apply").send({ deltaId: sev.id, accept: true });
    expect((await f2(stateStore))?.severity).toBe("Low");

    // Model B now agrees with A — the second run has no severity delta of its own.
    setSynth(bProvider, SYNTH_B);
    const second = await request(app).post("/cases/c1/second-opinion").send({});
    const carried = second.body.deltas.find((d: { id: string }) => d.id === sev.id);
    expect(carried.status).toBe("accepted");
    expect(carried.carriedFrom).toBe(run.body.generatedAt);

    setSynth(aProvider, synthA("A only finding", "T1046"));
    await pipeline.synthesize("c1", { force: true });
    expect((await f2(stateStore))?.severity).toBe("Low");
  });

  it("a decision whose finding is really gone is listed as unapplied, not dropped", async () => {
    const { app, aProvider, pipeline } = await makeApp({ enabled: true });
    setSynth(aProvider, synthA("A only finding", "T1219"));
    const run = await request(app).post("/cases/c1/second-opinion").send({});
    const dismissal = run.body.deltas.find((d: { kind: string }) => d.kind === "a_only");
    await request(app).post("/cases/c1/second-opinion/apply").send({ deltaId: dismissal.id, accept: true });

    const gone = JSON.parse(SYNTH_A);
    gone.findings = [gone.findings[0]];
    setSynth(aProvider, JSON.stringify(gone));
    await pipeline.synthesize("c1", { force: true });

    const rec = await request(app).get("/cases/c1/second-opinion");
    const d = rec.body.deltas.find((x: { id: string }) => x.id === dismissal.id);
    expect(d.status).toBe("accepted");
    expect(d.unapplied).toBe("missing");
    // Response-only: the stored record never carries the flag.
    expect(rec.body.deltas.filter((x: { unapplied?: string }) => x.unapplied)).toHaveLength(1);
  });
});

// #1596 — the referee may not quietly dismiss the only finding that answers an open thread.
describe("the referee's dismissal guard (#1596)", () => {
  // Model A's A-only finding is the only one that cites e1, and an open thread asks about 1.2.3.4.
  const synthA = JSON.stringify({
    ...JSON.parse(SYNTH_A),
    findings: JSON.parse(SYNTH_A).findings.map((f: { id: string }) =>
      f.id === "f2" ? { ...f, relatedEventIds: ["e1"] } : f,
    ),
    threadsOpened: [{ id: "t6", description: "What is the host 1.2.3.4?" }],
  });
  const dismiss = JSON.stringify({
    summary: "",
    verdicts: [
      { id: "a_only:finding-only", rationale: "Already covered elsewhere.", recommendation: "accept_b" },
    ],
  });

  it("shows the referee the open thread, flags the dismissal, and follow-referee leaves it pending", async () => {
    const { app, aProvider, stateStore } = await makeApp({ enabled: true, synthA });
    aProvider.reconcileReply = dismiss;
    const run = await request(app).post("/cases/c1/second-opinion").send({});
    expect(run.status).toBe(200);
    // The prompt goes through the anonymizer, so the address itself shows as a placeholder there.
    expect(aProvider.lastReconcilePrompt).toContain("[t6] (open thread) What is the host ");
    expect(aProvider.lastReconcilePrompt).toMatch(/! may be the only evidence for t6/);
    const flagged = run.body.deltas.find((d: { id: string }) => d.id === "a_only:finding-only");
    expect(flagged.refereeFlags).toEqual([
      { kind: "answers_open_item", itemId: "t6", itemKind: "thread", text: "What is the host 1.2.3.4?" },
      { kind: "unquoted_reason" },
    ]);

    const follow = await request(app)
      .post("/cases/c1/second-opinion/apply-all")
      .send({ followReferee: true });
    expect(follow.body.deltas.find((d: { id: string }) => d.id === "a_only:finding-only").status).toBe(
      "pending",
    );
    const all = await request(app).post("/cases/c1/second-opinion/apply-all").send({ accept: true });
    expect(all.body.deltas.find((d: { id: string }) => d.id === "a_only:finding-only").status).toBe(
      "pending",
    );
    expect((await stateStore.load("c1")).findings.find((f) => f.id === "f2")?.status).toBe("open");

    // The analyst can still decide it by hand.
    const one = await request(app)
      .post("/cases/c1/second-opinion/apply")
      .send({ deltaId: "a_only:finding-only", accept: true });
    const decided = one.body.deltas.find((d: { id: string }) => d.id === "a_only:finding-only");
    expect(decided.status).toBe("accepted");
    expect(decided.refereeFlags).toBeUndefined();
  });

  it("a bulk accept re-checks the hold against the case as it is now", async () => {
    const { app, aProvider, stateStore } = await makeApp({ enabled: true, synthA });
    aProvider.reconcileReply = JSON.stringify({
      summary: "",
      verdicts: [
        {
          id: "a_only:finding-only",
          rationale: 'Same as "beaconing to 1.2.3.4".',
          recommendation: "accept_b",
        },
      ],
    });
    const run = await request(app).post("/cases/c1/second-opinion").send({});
    const held = run.body.deltas.find((d: { id: string }) => d.id === "a_only:finding-only");
    expect(held.refereeFlags).toEqual([expect.objectContaining({ itemId: "t6" })]);

    // The analyst closes t6: nothing is left for the dismissal to take away.
    const s = await stateStore.load("c1");
    await stateStore.save({
      ...s,
      openThreads: s.openThreads.map((t) => ({ ...t, status: "closed" as const })),
    });
    const follow = await request(app)
      .post("/cases/c1/second-opinion/apply-all")
      .send({ followReferee: true });
    const after = follow.body.deltas.find((d: { id: string }) => d.id === "a_only:finding-only");
    expect(after.status).toBe("accepted");
    expect((await stateStore.load("c1")).findings.find((f) => f.id === "f2")?.status).toBe("dismissed");
  });
});
