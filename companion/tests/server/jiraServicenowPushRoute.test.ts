import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { JiraExportStore } from "../../src/integrations/jira/jiraExportStore.js";
import { ServiceNowExportStore } from "../../src/integrations/servicenow/servicenowExportStore.js";
import type { JiraClientLike } from "../../src/integrations/jira/jiraPush.js";
import type { ServiceNowClientLike } from "../../src/integrations/servicenow/servicenowPush.js";
import type { Finding, InvestigationState } from "../../src/analysis/stateTypes.js";

const sampleFinding: Finding = {
  id: "finding-1",
  title: "Test finding",
  description: "A test finding for ticket push.",
  severity: "high",
  confidence: 80,
  relatedIocs: ["ioc-1"],
  relatedEventIds: ["evt-1"],
  sourceScreenshots: [],
  mitreTechniques: ["T1059"],
  firstSeen: "2026-07-24T10:00:00Z",
} as Finding;

// A second finding, so a bulk push has an actual batch to work through.
const otherFinding: Finding = { ...sampleFinding, id: "finding-2", title: "Persistence via Run key" };

function mockJiraClient(): JiraClientLike {
  let n = 0;
  return {
    me: async () => ({ id: "u1", displayName: "Analyst" }),
    createIssue: async () => { n += 1; return { id: `issue-10${n}`, key: n === 1 ? "IR-42" : `IR-${42 + n}`, url: `https://jira.example.com/browse/IR-${n === 1 ? 42 : 42 + n}` }; },
    updateIssue: async (idOrKey) => ({ id: "", key: idOrKey, url: undefined }),
  };
}

function mockServiceNowClient(): ServiceNowClientLike {
  let n = 0;
  return {
    me: async () => ({ userId: "admin", userName: "admin" }),
    createIncident: async () => { n += 1; return { id: `sys-10${n}`, number: n === 1 ? "INC0012345" : `INC001234${5 + n}`, url: `https://snow.example.com/incident.do?sys_id=sys-10${n}` }; },
    updateIncident: async (sysId) => ({ id: sysId, number: "INC0012345", url: `https://snow.example.com/incident.do?sys_id=${sysId}` }),
  };
}

async function makeApp(opts: { jiraClient?: JiraClientLike; servicenowClient?: ServiceNowClientLike } = {}) {
  const root = await mkdtemp(join(tmpdir(), "dfir-ticket-push-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const jiraExportStore = new JiraExportStore(store);
  const servicenowExportStore = new ServiceNowExportStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined, synthesisProvider: undefined, stateStore, store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, {
    pipeline,
    stateStore,
    jiraClient: opts.jiraClient,
    jiraExportStore,
    jiraOptions: { projectKey: "IR", issueType: "Bug" },
    servicenowClient: opts.servicenowClient,
    servicenowExportStore,
    servicenowOptions: { caller: "admin", category: "Security", subcategory: "IR" },
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "Ransomware FS01", investigator: "i", aiProvider: null });
  // Seed a minimal state with one finding.
  const state: InvestigationState = {
    caseId: "c1",
    findings: [sampleFinding, otherFinding],
    iocs: [],
    events: [],
    timeline: [],
    forensicTimeline: [],
    attackerPath: [],
    assets: [],
    summary: "",
    executiveSummary: "",
    recommendations: [],
    questions: [],
    nextSteps: [],
    createdAt: "2026-07-24T10:00:00Z",
    updatedAt: "2026-07-24T10:00:00Z",
    stats: { events: 0, iocs: 0, findings: 2, assets: 0 },
  } as unknown as InvestigationState;
  await stateStore.save(state);
  return app;
}

describe("Jira / ServiceNow ticket push routes (#272)", () => {
  it("GET /jira/status reflects configuration", async () => {
    const app = await makeApp({ jiraClient: mockJiraClient() });
    const res = await request(app).get("/jira/status");
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ configured: true, projectKey: "IR", issueType: "Bug" });
  });

  it("POST /cases/:id/push/jira creates a Jira issue for a finding", async () => {
    const app = await makeApp({ jiraClient: mockJiraClient() });
    const res = await request(app).post("/cases/c1/push/jira").send({ findingId: "finding-1" });
    expect(res.status).toBe(200);
    expect(res.body.issue.key).toBe("IR-42");
  });

  it("POST /cases/:id/push/jira 404s for a missing finding", async () => {
    const app = await makeApp({ jiraClient: mockJiraClient() });
    const res = await request(app).post("/cases/c1/push/jira").send({ findingId: "missing" });
    expect(res.status).toBe(404);
  });

  it("POST /cases/:id/push/jira 501s when not configured", async () => {
    const app = await makeApp();
    const res = await request(app).post("/cases/c1/push/jira").send({ findingId: "finding-1" });
    expect(res.status).toBe(501);
  });

  it("GET /servicenow/status reflects configuration", async () => {
    const app = await makeApp({ servicenowClient: mockServiceNowClient() });
    const res = await request(app).get("/servicenow/status");
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ configured: true, caller: "admin", category: "Security", subcategory: "IR" });
  });

  it("POST /cases/:id/push/servicenow creates an incident for a finding", async () => {
    const app = await makeApp({ servicenowClient: mockServiceNowClient() });
    const res = await request(app).post("/cases/c1/push/servicenow").send({ findingId: "finding-1" });
    expect(res.status).toBe(200);
    expect(res.body.incident.number).toBe("INC0012345");
  });

  it("POST /cases/:id/push/servicenow 404s for a missing finding", async () => {
    const app = await makeApp({ servicenowClient: mockServiceNowClient() });
    const res = await request(app).post("/cases/c1/push/servicenow").send({ findingId: "missing" });
    expect(res.status).toBe(404);
  });

  it("POST /cases/:id/push/servicenow 501s when not configured", async () => {
    const app = await makeApp();
    const res = await request(app).post("/cases/c1/push/servicenow").send({ findingId: "finding-1" });
    expect(res.status).toBe(501);
  });
});

describe("Jira / ServiceNow bulk push routes (#297)", () => {
  it("POST /cases/:id/push/jira/bulk files an issue per selected finding", async () => {
    const app = await makeApp({ jiraClient: mockJiraClient() });
    const res = await request(app).post("/cases/c1/push/jira/bulk").send({ findingIds: ["finding-1", "finding-2"] });
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ created: 2, updated: 0, skipped: 0 });
    expect(res.body.issues.map((i: { findingId: string }) => i.findingId)).toEqual(["finding-1", "finding-2"]);
  });

  it("POST /cases/:id/push/jira/bulk re-push UPDATES instead of duplicating", async () => {
    const app = await makeApp({ jiraClient: mockJiraClient() });
    await request(app).post("/cases/c1/push/jira/bulk").send({ findingIds: ["finding-1", "finding-2"] });
    const res = await request(app).post("/cases/c1/push/jira/bulk").send({ findingIds: ["finding-1", "finding-2"] });
    expect(res.body).toMatchObject({ created: 0, updated: 2, skipped: 0 });
  });

  it("POST /cases/:id/push/jira/bulk skips an unknown finding rather than failing the batch", async () => {
    const app = await makeApp({ jiraClient: mockJiraClient() });
    const res = await request(app).post("/cases/c1/push/jira/bulk").send({ findingIds: ["finding-1", "missing"] });
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ created: 1, skipped: 1 });
    expect(res.body.warnings.join(" ")).toContain("missing");
  });

  it("POST /cases/:id/push/jira/bulk 400s without any finding ids", async () => {
    const app = await makeApp({ jiraClient: mockJiraClient() });
    expect((await request(app).post("/cases/c1/push/jira/bulk").send({})).status).toBe(400);
    expect((await request(app).post("/cases/c1/push/jira/bulk").send({ findingIds: [] })).status).toBe(400);
  });

  it("POST /cases/:id/push/jira/bulk 501s when not configured", async () => {
    const app = await makeApp();
    const res = await request(app).post("/cases/c1/push/jira/bulk").send({ findingIds: ["finding-1"] });
    expect(res.status).toBe(501);
  });

  it("POST /cases/:id/push/servicenow/bulk opens an incident per selected finding", async () => {
    const app = await makeApp({ servicenowClient: mockServiceNowClient() });
    const res = await request(app).post("/cases/c1/push/servicenow/bulk").send({ findingIds: ["finding-1", "finding-2"] });
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ created: 2, updated: 0, skipped: 0 });
    expect(res.body.incidents.map((i: { findingId: string }) => i.findingId)).toEqual(["finding-1", "finding-2"]);
  });

  it("POST /cases/:id/push/servicenow/bulk re-push UPDATES instead of duplicating", async () => {
    const app = await makeApp({ servicenowClient: mockServiceNowClient() });
    await request(app).post("/cases/c1/push/servicenow/bulk").send({ findingIds: ["finding-1", "finding-2"] });
    const res = await request(app).post("/cases/c1/push/servicenow/bulk").send({ findingIds: ["finding-1", "finding-2"] });
    expect(res.body).toMatchObject({ created: 0, updated: 2, skipped: 0 });
  });

  it("POST /cases/:id/push/servicenow/bulk skips an unknown finding rather than failing the batch", async () => {
    const app = await makeApp({ servicenowClient: mockServiceNowClient() });
    const res = await request(app).post("/cases/c1/push/servicenow/bulk").send({ findingIds: ["finding-1", "missing"] });
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ created: 1, skipped: 1 });
    expect(res.body.warnings.join(" ")).toContain("missing");
  });

  it("POST /cases/:id/push/servicenow/bulk 400s without any finding ids", async () => {
    const app = await makeApp({ servicenowClient: mockServiceNowClient() });
    expect((await request(app).post("/cases/c1/push/servicenow/bulk").send({})).status).toBe(400);
  });

  it("POST /cases/:id/push/servicenow/bulk 501s when not configured", async () => {
    const app = await makeApp();
    const res = await request(app).post("/cases/c1/push/servicenow/bulk").send({ findingIds: ["finding-1"] });
    expect(res.status).toBe(501);
  });
});
