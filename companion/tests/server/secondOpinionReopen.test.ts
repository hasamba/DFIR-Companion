import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SecondOpinionStore } from "../../src/analysis/secondOpinionStore.js";
import type { SecondOpinion } from "../../src/analysis/secondOpinion.js";
import { emptyState, type Finding } from "../../src/analysis/stateTypes.js";
import type { AIProvider, AnalyzeResult } from "../../src/providers/provider.js";

// #1972: the panel record marks a reopened decision, and POST /second-opinion/reopened keeps or
// drops it.

class NoopProvider implements AIProvider {
  readonly name = "noop";
  readonly model = "noop";
  async analyze(): Promise<AnalyzeResult> {
    return { rawText: "{}" };
  }
}

const finding = {
  id: "f1",
  severity: "Medium",
  title: "Advanced IP Scanner executed",
  description: "",
  relatedIocs: [],
  sourceScreenshots: [],
  mitreTechniques: [],
  firstSeen: "",
  lastUpdated: "",
  status: "open",
  relatedEventIds: ["e1"],
} as Finding;

const RECORD: SecondOpinion = {
  generatedAt: "2026-10-06T09:00:00.000Z",
  modelA: "a",
  modelB: "b",
  referee: "",
  summary: "",
  agreementCount: 0,
  deltas: [
    {
      id: "severity:f1",
      kind: "severity",
      title: finding.title,
      aSeverity: "High",
      bSeverity: "Medium",
      finding: { ...finding, severity: "High" },
      rationale: "",
      recommendation: "review",
      status: "accepted",
    },
  ],
};

async function makeApp(primary: Finding["severity"]) {
  const store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-so-reopen-route-")));
  const stateStore = new StateStore(store);
  const secondOpinionStore = new SecondOpinionStore(store);
  const provider = new NoopProvider();
  const pipeline = buildRuntimePipeline({
    provider,
    synthesisProvider: provider,
    stateStore,
    store,
    secondOpinionStore,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, { pipeline, stateStore, aiConfigured: true, secondOpinionStore });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
  const state = emptyState("c1");
  state.findings = [{ ...finding, primaryCall: { severity: primary, status: "open" } } as Finding];
  await stateStore.save(state);
  await secondOpinionStore.save("c1", RECORD);
  return { app, stateStore, secondOpinionStore };
}

describe("second-opinion reopened decisions over HTTP (#1972)", () => {
  it("GET marks the decision the primary's new call reopened", async () => {
    const { app } = await makeApp("Critical");
    const res = await request(app).get("/cases/c1/second-opinion");
    expect(res.status).toBe(200);
    expect(res.body.deltas[0].reopened).toBe("Critical");
  });

  it("Keep records the new call and stores no response-only mark", async () => {
    const { app, secondOpinionStore } = await makeApp("Critical");
    const res = await request(app)
      .post("/cases/c1/second-opinion/reopened")
      .send({ deltaId: "severity:f1", keep: true });
    expect(res.status).toBe(200);
    expect(res.body.deltas[0]).toMatchObject({ status: "accepted", aSeverity: "Critical" });
    expect(res.body.deltas[0].reopened).toBeUndefined();
    expect((await secondOpinionStore.load("c1"))?.deltas[0].reopened).toBeUndefined();
  });

  it("Drop rejects the decision and puts the finding on the primary's call", async () => {
    const { app, stateStore } = await makeApp("Critical");
    const res = await request(app)
      .post("/cases/c1/second-opinion/reopened")
      .send({ deltaId: "severity:f1", keep: false });
    expect(res.status).toBe(200);
    expect(res.body.deltas[0].status).toBe("rejected");
    expect((await stateStore.load("c1")).findings[0].severity).toBe("Critical");
  });

  it("answers 409 for a decision that is not reopened, 404 for an unknown one, 400 without an id", async () => {
    const { app } = await makeApp("High");
    const post = (body: object) => request(app).post("/cases/c1/second-opinion/reopened").send(body);
    expect((await post({ deltaId: "severity:f1", keep: false })).status).toBe(409);
    expect((await post({ deltaId: "severity:f1", keep: true })).status).toBe(409);
    expect((await post({ deltaId: "nope", keep: true })).status).toBe(404);
    expect((await post({ keep: true })).status).toBe(400);
  });
});
