import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SecondOpinionStore } from "../../src/analysis/secondOpinionStore.js";
import { FindingSeverityRestoreStore, type SeverityCap } from "../../src/analysis/findingSeverityRestore.js";
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

function makeApp(primary: Finding["severity"]) {
  return setup(
    [{ ...finding, primaryCall: { severity: primary, status: "open" } } as Finding],
    RECORD.deltas,
  );
}

async function setup(findings: Finding[], deltas: SecondOpinion["deltas"]) {
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
  state.findings = findings;
  await stateStore.save(state);
  await secondOpinionStore.save("c1", { ...RECORD, deltas });
  return { app, store, stateStore, secondOpinionStore };
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

// Code review on #1972: Keep and Drop must not re-apply accepted severities ungraded. A grading gate
// capped the accepted call; writing the raw accepted severity back bypasses that cap.
describe("second-opinion reopened decisions keep the graded state (#1972 review)", () => {
  const cap = (from: Finding["severity"], to: Finding["severity"]): SeverityCap => ({
    from,
    to,
    gates: ["lateral-unconfirmed"],
  });
  // f1: A said Critical, the analyst accepted High, a gate capped it to Medium. The primary now
  // grades Low, which differs from both, so the decision is reopened.
  const f1 = {
    ...finding,
    severity: "Medium",
    severityCap: cap("High", "Medium"),
    primaryCall: { severity: "Low", status: "open" },
  } as Finding;
  // f2: an unrelated accepted decision (A High, accepted Critical) that a gate capped to High.
  const f2 = {
    ...finding,
    id: "f2",
    title: "Mimikatz credential dump",
    relatedEventIds: ["e2"],
    severity: "High",
    severityCap: cap("Critical", "High"),
    primaryCall: { severity: "High", status: "open" },
  } as Finding;
  const delta = (
    f: Finding,
    a: Finding["severity"],
    b: Finding["severity"],
  ): SecondOpinion["deltas"][number] => ({
    id: `severity:${f.id}`,
    kind: "severity",
    title: f.title,
    aSeverity: a,
    bSeverity: b,
    finding: { ...f, severity: a },
    rationale: "",
    recommendation: "review",
    status: "accepted",
  });
  const post = (app: Parameters<typeof request>[0], keep: boolean) =>
    request(app).post("/cases/c1/second-opinion/reopened").send({ deltaId: "severity:f1", keep });
  const byId = async (stateStore: StateStore, id: string) =>
    (await stateStore.load("c1")).findings.find((f) => f.id === id);

  it("Keep on a capped finding leaves its graded severity and cap unchanged", async () => {
    const { app, stateStore } = await setup([f1], [delta(f1, "Critical", "High")]);
    const before = JSON.stringify(await byId(stateStore, "f1"));
    expect((await post(app, true)).status).toBe(200);
    expect(JSON.stringify(await byId(stateStore, "f1"))).toBe(before);
  });

  it("Drop changes only its own finding; another accepted decision's finding stays byte-identical", async () => {
    const { app, stateStore } = await setup(
      [f1, f2],
      [delta(f1, "Critical", "High"), delta(f2, "High", "Critical")],
    );
    const before = JSON.stringify(await byId(stateStore, "f2"));
    expect((await post(app, false)).status).toBe(200);
    expect(JSON.stringify(await byId(stateStore, "f2"))).toBe(before);
    expect((await byId(stateStore, "f1"))?.severity).toBe("Low");
  });

  it("Drop on a capped primary call ends graded, and a severity restore (#1973) lifts the cap", async () => {
    const capped = {
      ...f1,
      primaryCall: { severity: "Medium", status: "open", cap: cap("High", "Medium") },
    } as Finding;
    const graded = await setup([capped], [delta(capped, "Critical", "Low")]);
    expect((await post(graded.app, false)).status).toBe(200);
    const g = (await byId(graded.stateStore, "f1")) as Finding & { severityCap?: SeverityCap };
    expect(g.severity).toBe("Medium");
    expect(g.severityCap).toEqual(cap("High", "Medium"));

    const restored = await setup([capped], [delta(capped, "Critical", "Low")]);
    await new FindingSeverityRestoreStore(restored.store).restore("c1", "f1", {
      semanticKey: "",
      by: "analyst",
    });
    expect((await post(restored.app, false)).status).toBe(200);
    expect((await byId(restored.stateStore, "f1"))?.severity).toBe("High");
  });
});
