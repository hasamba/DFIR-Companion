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

function mockJiraClient(): JiraClientLike {
  return {
    me: async () => ({ id: "u1", displayName: "Analyst" }),
    createIssue: async (body) => ({ id: "issue-100", key: "IR-42", url: "https://jira.example.com/browse/IR-42" }),
  };
}

function mockServiceNowClient(): ServiceNowClientLike {
  return {
    me: async () => ({ userId: "admin", userName: "admin" }),
    createIncident: async (body) => ({ id: "sys-100", number: "INC0012345", url: "https://snow.example.com/incident.do?sys_id=sys-100" }),
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
    findings: [sampleFinding],
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
    stats: { events: 0, iocs: 0, findings: 1, assets: 0 },
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
