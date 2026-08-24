import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import type { AppOptions } from "../../src/composition/appOptions.js";
import type { NotionClient } from "../../src/integrations/notion/notionClient.js";
import type { ClickUpClient } from "../../src/integrations/clickup/clickupClient.js";
import type { JiraClientLike } from "../../src/integrations/jira/jiraClient.js";
import type { ServiceNowClientLike } from "../../src/integrations/servicenow/servicenowClient.js";

// Settings -> Integrations grew a "Test connection" control for every integration, not only
// DFIR-IRIS. Each control needs a route that answers the same three states the IRIS one does,
// because that tri-state is what the analyst actually reads:
//
//   not configured  - the keys are missing, so nothing was even attempted
//   configured, ok  - the credentials reached the remote and it answered
//   configured, !ok - the credentials are there and the remote refused / is down
//
// Notion and ClickUp are settable from the dashboard, so their routes RECONNECT: re-read .env,
// rebuild the client, then ping - the same "no restart needed" contract as /iris/reconnect.
// Jira and ServiceNow are deliberately read-only in Settings (the dashboard must not be able to
// move DFIR_*_INSECURE), so theirs only PING the live client and say so when it is absent.

const failing = (msg: string) => async (): Promise<never> => {
  throw new Error(msg);
};

const mockNotion = (me: () => Promise<{ id?: string; name?: string }>): NotionClient =>
  ({ me }) as unknown as NotionClient;
const mockClickUp = (me: () => Promise<{ id?: string; username?: string }>): ClickUpClient =>
  ({ me }) as unknown as ClickUpClient;
const mockJira = (me: JiraClientLike["me"]): JiraClientLike => ({ me }) as unknown as JiraClientLike;
const mockSnow = (me: ServiceNowClientLike["me"]): ServiceNowClientLike =>
  ({ me }) as unknown as ServiceNowClientLike;

async function makeApp(opts: AppOptions = {}) {
  const root = await mkdtemp(join(tmpdir(), "dfir-conn-test-"));
  return createApp(new CaseStore(root), opts);
}

describe("POST /notion/reconnect", () => {
  it("reports not-configured when the rebuild yields no client", async () => {
    const app = await makeApp({ rebuildNotionClient: () => undefined });
    const res = await request(app).post("/notion/reconnect");
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ configured: false, ok: false });
    expect(res.body.error).toMatch(/DFIR_NOTION_TOKEN/);
  });

  it("pings the rebuilt client and reports ok", async () => {
    const app = await makeApp({
      rebuildNotionClient: () => mockNotion(async () => ({ id: "bot-1", name: "DFIR bot" })),
    });
    const res = await request(app).post("/notion/reconnect");
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ configured: true, ok: true, user: "DFIR bot" });
  });

  it("reports a reachability failure without claiming success", async () => {
    const app = await makeApp({
      rebuildNotionClient: () => mockNotion(failing("Notion HTTP 401 on /v1/users/me")),
    });
    const res = await request(app).post("/notion/reconnect");
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ configured: true, ok: false });
    expect(res.body.error).toMatch(/401/);
  });

  it("swaps in the rebuilt client so /notion/status then reports configured", async () => {
    const app = await makeApp({
      rebuildNotionClient: () => mockNotion(async () => ({ id: "bot-1" })),
    });
    expect((await request(app).get("/notion/status")).body.configured).toBe(false);
    await request(app).post("/notion/reconnect");
    expect((await request(app).get("/notion/status")).body.configured).toBe(true);
  });
});

describe("POST /clickup/reconnect", () => {
  it("reports not-configured when the rebuild yields no client", async () => {
    const app = await makeApp({ rebuildClickupClient: () => undefined });
    const res = await request(app).post("/clickup/reconnect");
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ configured: false, ok: false });
    expect(res.body.error).toMatch(/DFIR_CLICKUP_TOKEN/);
  });

  it("pings the rebuilt client and reports ok", async () => {
    const app = await makeApp({
      rebuildClickupClient: () => mockClickUp(async () => ({ id: "42", username: "ir-bot" })),
    });
    const res = await request(app).post("/clickup/reconnect");
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ configured: true, ok: true, user: "ir-bot" });
  });

  it("reports a reachability failure without claiming success", async () => {
    const app = await makeApp({
      rebuildClickupClient: () => mockClickUp(failing("ClickUp HTTP 401 on /user")),
    });
    const res = await request(app).post("/clickup/reconnect");
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ configured: true, ok: false });
    expect(res.body.error).toMatch(/401/);
  });

  it("swaps in the rebuilt client so /clickup/status then reports configured", async () => {
    const app = await makeApp({
      rebuildClickupClient: () => mockClickUp(async () => ({ id: "42" })),
    });
    expect((await request(app).get("/clickup/status")).body.configured).toBe(false);
    await request(app).post("/clickup/reconnect");
    expect((await request(app).get("/clickup/status")).body.configured).toBe(true);
  });
});

describe("POST /jira/test", () => {
  it("reports not-configured when no client is wired", async () => {
    const app = await makeApp({});
    const res = await request(app).post("/jira/test");
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ configured: false, ok: false });
    expect(res.body.error).toMatch(/DFIR_JIRA_URL/);
  });

  it("pings the live client and reports ok", async () => {
    const app = await makeApp({
      jiraClient: mockJira(async () => ({ id: "1", displayName: "IR Bot" })),
    });
    const res = await request(app).post("/jira/test");
    expect(res.body).toMatchObject({ configured: true, ok: true, user: "IR Bot" });
  });

  it("reports a reachability failure without claiming success", async () => {
    const app = await makeApp({ jiraClient: mockJira(failing("Jira HTTP 403 on /myself")) });
    const res = await request(app).post("/jira/test");
    expect(res.body).toMatchObject({ configured: true, ok: false });
    expect(res.body.error).toMatch(/403/);
  });
});

describe("POST /servicenow/test", () => {
  it("reports not-configured when no client is wired", async () => {
    const app = await makeApp({});
    const res = await request(app).post("/servicenow/test");
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ configured: false, ok: false });
    expect(res.body.error).toMatch(/DFIR_SERVICENOW_URL/);
  });

  it("pings the live client and reports ok", async () => {
    const app = await makeApp({
      servicenowClient: mockSnow(async () => ({ userId: "9", userName: "ir.bot" })),
    });
    const res = await request(app).post("/servicenow/test");
    expect(res.body).toMatchObject({ configured: true, ok: true, user: "ir.bot" });
  });

  it("reports a reachability failure without claiming success", async () => {
    const app = await makeApp({
      servicenowClient: mockSnow(failing("ServiceNow HTTP 401 on /api/now/table/sys_user")),
    });
    const res = await request(app).post("/servicenow/test");
    expect(res.body).toMatchObject({ configured: true, ok: false });
    expect(res.body.error).toMatch(/401/);
  });
});
