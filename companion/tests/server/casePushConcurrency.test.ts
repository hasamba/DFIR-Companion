import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import type { Express } from "express";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ReportWriter } from "../../src/reports/reportWriter.js";
import { IrisExportStore } from "../../src/integrations/iris/irisExportStore.js";
import { JiraExportStore } from "../../src/integrations/jira/jiraExportStore.js";
import { ServiceNowExportStore } from "../../src/integrations/servicenow/servicenowExportStore.js";
import { emptyState, type Finding } from "../../src/analysis/stateTypes.js";
import { stubServerClients } from "../helpers/serverClientsStub.js";
import { createPushGuard } from "../../src/routes/pushGuard.js";
import type { IrisClient } from "../../src/integrations/iris/irisClient.js";
import type { MispPushClientLike } from "../../src/integrations/misp/mispPushClient.js";
import type { JiraClientLike } from "../../src/integrations/jira/jiraClient.js";
import type { ServiceNowClientLike } from "../../src/integrations/servicenow/servicenowClient.js";

// #2775: every push does find-then-create against the remote, and the pair is not atomic. Two
// overlapping pushes of the same case (or finding) both missed and both created — a duplicate MISP
// event, IRIS case, Jira issue or ServiceNow incident. The second push is now refused with 409.

/**
 * A gate the mocked remote call waits on. `entered` resolves when the first caller reaches it.
 * A second caller reaching it opens the gate at once, so a missing guard shows as two creates
 * rather than as a hung test.
 */
function gate() {
  let open!: () => void;
  let markEntered!: () => void;
  const opened = new Promise<void>((r) => (open = r));
  const entered = new Promise<void>((r) => (markEntered = r));
  let callers = 0;
  return {
    open,
    entered,
    async wait(): Promise<void> {
      callers += 1;
      markEntered();
      if (callers > 1) open();
      await opened;
    },
  };
}

function finding(id: string): Finding {
  return {
    id,
    title: `Finding ${id}`,
    description: "d",
    severity: "High",
    confidence: 80,
    relatedIocs: [],
    relatedEventIds: [],
    sourceScreenshots: [],
    mitreTechniques: [],
    firstSeen: "2026-07-24T10:00:00Z",
    lastUpdated: "2026-07-24T10:00:00Z",
    status: "open",
  };
}

async function seed() {
  const store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-push-race-")));
  const stateStore = new StateStore(store);
  await store.createCase({ caseId: "c1", name: "c1", investigator: "tester", aiProvider: null });
  const state = emptyState("c1");
  state.findings.push(finding("f1"), finding("f2"));
  await stateStore.save(state);
  return { store, stateStore, reportWriter: new ReportWriter(store, stateStore) };
}

/** Start a request now (supertest only sends once thenned) and hand back its promise. */
function start(app: Express, path: string, body: object = {}) {
  return new Promise<request.Response>((resolve, reject) => {
    request(app).post(path).send(body).then(resolve, reject);
  });
}

function mispClient(g: { wait(): Promise<void> } | null, opts: { failOnce?: boolean } = {}) {
  let creates = 0;
  let failed = false;
  const client: MispPushClientLike = {
    async ping() {},
    async findEventByTag() {
      if (g) await g.wait();
      if (opts.failOnce && !failed) {
        failed = true;
        throw new Error("MISP down");
      }
      return null;
    },
    async createEvent() {
      creates += 1;
      return String(creates);
    },
    async addTagToEvent() {},
    async listAttributes() {
      return [];
    },
    async addAttribute() {},
  };
  return { client, creates: () => creates };
}

function irisClient(g: { wait(): Promise<void> }) {
  let creates = 0;
  const none = async () => [];
  const one = async () => 1;
  const map = async () => new Map<string, number>([["to do", 1]]);
  const client = {
    async ping() {},
    async findCaseByName() {
      await g.wait();
      return null;
    },
    async createCase(body: { case_name: string }) {
      creates += 1;
      return { caseId: 100 + creates, caseName: body.case_name };
    },
    async setSummary() {},
    iocTypeMap: map,
    assetTypeMap: map,
    eventCategoryMap: map,
    taskStatusMap: map,
    listAssets: none,
    addAsset: one,
    listIocs: none,
    addIoc: one,
    listEvents: none,
    addEvent: one,
    listTasks: none,
    addTask: one,
    listDirectories: none,
    addDirectory: one,
    async deleteDirectory() {},
    addNote: one,
  };
  return { client: client as unknown as IrisClient, creates: () => creates };
}

function jiraClient(g: { wait(): Promise<void> }) {
  let creates = 0;
  const client: JiraClientLike = {
    me: async () => ({ id: "u1", displayName: "Analyst" }),
    createIssue: async () => {
      await g.wait();
      creates += 1;
      return { id: `i${creates}`, key: `IR-${creates}`, url: undefined };
    },
    updateIssue: async (key) => ({ id: "", key, url: undefined }),
  };
  return { client, creates: () => creates };
}

function snowClient(g: { wait(): Promise<void> }) {
  let creates = 0;
  const client: ServiceNowClientLike = {
    me: async () => ({ userId: "admin", userName: "admin" }),
    createIncident: async () => {
      await g.wait();
      creates += 1;
      return { id: `s${creates}`, number: `INC${creates}`, url: "" };
    },
    updateIncident: async (id) => ({ id, number: "INC1", url: "" }),
  };
  return { client, creates: () => creates };
}

describe("createPushGuard (#2775)", () => {
  it("refuses a held key, takes all-or-nothing, and frees keys on release", () => {
    const guard = createPushGuard();
    const release = guard.tryAcquire(["a", "b"]);
    expect(release).not.toBeNull();
    expect(guard.tryAcquire(["b", "c"])).toBeNull();
    // The refused call took nothing — "c" is still free.
    const c = guard.tryAcquire(["c"]);
    expect(c).not.toBeNull();
    release!();
    release!(); // idempotent
    expect(guard.tryAcquire(["a", "a"])).not.toBeNull();
  });
});

describe("concurrent pushes are refused instead of duplicated (#2775)", () => {
  it("MISP: second push of the same case is a 409, one event created, lock freed after", async () => {
    const { store, stateStore, reportWriter } = await seed();
    const g = gate();
    const misp = mispClient(g);
    const app = createApp(store, { stateStore, reportWriter, mispPushClient: misp.client });
    const first = start(app, "/cases/c1/push/misp");
    await g.entered;
    const second = await request(app).post("/cases/c1/push/misp").send({});
    expect(second.status).toBe(409);
    expect(second.body.error).toMatch(/MISP push for this case is already running/);
    g.open();
    expect((await first).status).toBe(200);
    expect(misp.creates()).toBe(1);
    expect((await request(app).post("/cases/c1/push/misp").send({})).status).toBe(200);
  });

  it("MISP: a failed push releases the lock", async () => {
    const { store, stateStore, reportWriter } = await seed();
    const misp = mispClient(null, { failOnce: true });
    const app = createApp(store, { stateStore, reportWriter, mispPushClient: misp.client });
    expect((await request(app).post("/cases/c1/push/misp").send({})).status).toBe(502);
    expect((await request(app).post("/cases/c1/push/misp").send({})).status).toBe(200);
  });

  it("DFIR-IRIS: second push of the same case is a 409, one case created", async () => {
    const { store, stateStore, reportWriter } = await seed();
    const g = gate();
    const iris = irisClient(g);
    const app = createApp(store, {
      stateStore,
      reportWriter,
      serverClients: stubServerClients({ iris: iris.client }),
      irisExportStore: new IrisExportStore(store),
    });
    const first = start(app, "/cases/c1/push/iris");
    await g.entered;
    const second = await request(app).post("/cases/c1/push/iris").send({});
    expect(second.status).toBe(409);
    g.open();
    expect((await first).status).toBe(200);
    expect(iris.creates()).toBe(1);
  });

  it("Jira: same finding is a 409, a different finding goes through, bulk overlapping is a 409", async () => {
    const { store, stateStore } = await seed();
    const g = gate();
    const jira = jiraClient(g);
    const app = createApp(store, {
      stateStore,
      jiraClient: jira.client,
      jiraExportStore: new JiraExportStore(store),
      jiraOptions: { projectKey: "IR", issueType: "Bug" },
    });
    const first = start(app, "/cases/c1/push/jira", { findingId: "f1" });
    await g.entered;
    const same = await request(app).post("/cases/c1/push/jira").send({ findingId: "f1" });
    expect(same.status).toBe(409);
    const bulk = await request(app)
      .post("/cases/c1/push/jira/bulk")
      .send({ findingIds: ["f2", "f1"] });
    expect(bulk.status).toBe(409);
    // f2 was not left held by the refused bulk request.
    const other = start(app, "/cases/c1/push/jira", { findingId: "f2" });
    g.open();
    expect((await first).status).toBe(200);
    expect((await other).status).toBe(200);
    expect(jira.creates()).toBe(2);
  });

  it("Jira bulk: a repeated id in one body is not refused by its own request", async () => {
    const { store, stateStore } = await seed();
    const g = gate();
    g.open();
    const jira = jiraClient(g);
    const app = createApp(store, {
      stateStore,
      jiraClient: jira.client,
      jiraExportStore: new JiraExportStore(store),
      jiraOptions: { projectKey: "IR", issueType: "Bug" },
    });
    const res = await request(app)
      .post("/cases/c1/push/jira/bulk")
      .send({ findingIds: ["f1", "f1"] });
    expect(res.status).toBe(200);
  });

  it("ServiceNow: same finding is a 409, one incident opened; bulk overlapping is a 409", async () => {
    const { store, stateStore } = await seed();
    const g = gate();
    const snow = snowClient(g);
    const app = createApp(store, {
      stateStore,
      servicenowClient: snow.client,
      servicenowExportStore: new ServiceNowExportStore(store),
      servicenowOptions: { caller: "admin", category: "Security", subcategory: "IR" },
    });
    const first = start(app, "/cases/c1/push/servicenow", { findingId: "f1" });
    await g.entered;
    expect((await request(app).post("/cases/c1/push/servicenow").send({ findingId: "f1" })).status).toBe(409);
    const bulk = await request(app)
      .post("/cases/c1/push/servicenow/bulk")
      .send({ findingIds: ["f1"] });
    expect(bulk.status).toBe(409);
    g.open();
    expect((await first).status).toBe(200);
    expect(snow.creates()).toBe(1);
  });
});
