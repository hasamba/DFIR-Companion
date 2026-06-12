import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { PlaybookStore } from "../../src/analysis/playbookStore.js";
import { PlaybookControlStore } from "../../src/analysis/playbookControl.js";
import { MockProvider } from "../../src/providers/provider.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import { VelociraptorClient, type VqlRunner, type VelociraptorApiConfig } from "../../src/integrations/velociraptor/velociraptorApi.js";

// Canned model reply: one endpoint-related hunt for the finding-derived task, scoped to WEB01.
const cannedPlaybookHunts = JSON.stringify({
  suggestions: [
    { taskId: "finding:f1", endpointRelated: true, title: "Enumerate webshell on WEB01",
      rationale: "collect web roots", vql: "SELECT FullPath FROM glob(globs='C:/inetpub/wwwroot/**/*.aspx')",
      targetHost: "WEB01", severity: "High", mitreTechniques: ["T1505.003"] },
  ],
});

const veloCfg: VelociraptorApiConfig = {
  apiConfigPath: "/x/api.yaml", binary: "velociraptor", timeoutMs: 5000, maxRows: 1000, maxOutputBytes: 1024 * 1024,
  guiUrl: "https://velo.example/",
};

// A runner for collect-host: resolve the client (FROM clients) then launch the collection flow.
const collectRunner: VqlRunner = async (statements) => {
  const p = statements[0];
  if (p.includes("collect_client(")) return { rows: [{ Flow: { flow_id: "F.123" } }], raw: "" };
  if (p.includes("FROM clients(")) return { rows: [{ ClientId: "C.web01", OsInfo: { hostname: "web01" }, LastSeen: 1 }], raw: "" };
  return { rows: [], raw: "" };
};

async function makeApp(opts: { provider?: MockProvider; velociraptorClient?: VelociraptorClient } = {}) {
  const root = await mkdtemp(join(tmpdir(), "dfir-pbhunt-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const playbookStore = new PlaybookStore(store);
  const playbookControlStore = new PlaybookControlStore(store);
  const pipeline = buildRuntimePipeline({
    provider: opts.provider, synthesisProvider: opts.provider, stateStore, store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, {
    pipeline, stateStore, playbookStore, playbookControlStore,
    velociraptorClient: opts.velociraptorClient, aiConfigured: Boolean(opts.provider),
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: opts.provider ? "mock" : null });
  return { app, stateStore };
}

// Seed a Critical finding (→ syncPlaybook derives the `finding:f1` task), optionally with a forensic
// event on a host so the task resolves to a single observed endpoint.
async function seed(stateStore: StateStore, withHostEvent: boolean) {
  const s = emptyState("c1");
  s.findings.push({ id: "f1", severity: "Critical", title: "Webshell on WEB01", description: "ASPX webshell",
    relatedIocs: [], mitreTechniques: ["T1505.003"], sourceScreenshots: [], firstSeen: "", lastUpdated: "", status: "open" });
  if (withHostEvent) {
    const e: ForensicEvent = { id: "e1", timestamp: "2026-06-01T00:00:00Z", description: "webshell write",
      severity: "High", mitreTechniques: [], relatedFindingIds: ["f1"], sourceScreenshots: [], asset: "WEB01" };
    s.forensicTimeline.push(e);
  }
  await stateStore.save(s);
}

describe("POST /cases/:id/playbook/suggest-hunts", () => {
  it("deploys as a COLLECTION when the task is tied to one observed endpoint", async () => {
    const { app, stateStore } = await makeApp({ provider: new MockProvider("mock", cannedPlaybookHunts) });
    await seed(stateStore, true);   // event on WEB01 → known endpoint
    const res = await request(app).post("/cases/c1/playbook/suggest-hunts").send({});
    expect(res.status).toBe(200);
    expect(res.body.suggestions).toHaveLength(1);
    expect(res.body.suggestions[0].mode).toBe("collection");
    expect(res.body.suggestions[0].targetHost).toBe("WEB01");
  });

  it("clamps to a fleet HUNT when the target host is not an observed endpoint", async () => {
    const { app, stateStore } = await makeApp({ provider: new MockProvider("mock", cannedPlaybookHunts) });
    await seed(stateStore, false);  // no events → WEB01 is not a known endpoint
    const res = await request(app).post("/cases/c1/playbook/suggest-hunts").send({});
    expect(res.status).toBe(200);
    expect(res.body.suggestions[0].mode).toBe("hunt");
    expect(res.body.suggestions[0].targetHost).toBeUndefined();
  });

  it("returns [] (no AI spend) when the playbook is empty", async () => {
    const { app, stateStore } = await makeApp({ provider: new MockProvider("mock", cannedPlaybookHunts) });
    await stateStore.save(emptyState("c1"));   // no findings → no tasks
    const res = await request(app).post("/cases/c1/playbook/suggest-hunts").send({});
    expect(res.status).toBe(200);
    expect(res.body.suggestions).toEqual([]);
  });

  it("501s when no AI provider is configured", async () => {
    const { app, stateStore } = await makeApp({});
    await seed(stateStore, true);
    const res = await request(app).post("/cases/c1/playbook/suggest-hunts").send({});
    expect(res.status).toBe(501);
  });
});

describe("POST /velociraptor/collect-host", () => {
  it("launches a single-endpoint collection and returns the flow + deep link", async () => {
    const { app } = await makeApp({ velociraptorClient: new VelociraptorClient(veloCfg, collectRunner) });
    const res = await request(app).post("/velociraptor/collect-host")
      .send({ hostname: "WEB01", vql: "SELECT 1", description: "collect" });
    expect(res.status).toBe(200);
    expect(res.body.flowId).toBe("F.123");
    expect(res.body.clientId).toBe("C.web01");
    expect(res.body.guiUrl).toContain("#/collected/C.web01/F.123");
  });

  it("400s when hostname or vql is missing", async () => {
    const { app } = await makeApp({ velociraptorClient: new VelociraptorClient(veloCfg, collectRunner) });
    expect((await request(app).post("/velociraptor/collect-host").send({ vql: "SELECT 1" })).status).toBe(400);
    expect((await request(app).post("/velociraptor/collect-host").send({ hostname: "WEB01" })).status).toBe(400);
  });

  it("502s when no client matches the host", async () => {
    const emptyRunner: VqlRunner = async () => ({ rows: [], raw: "" });
    const { app } = await makeApp({ velociraptorClient: new VelociraptorClient(veloCfg, emptyRunner) });
    const res = await request(app).post("/velociraptor/collect-host").send({ hostname: "GHOST", vql: "SELECT 1", description: "x" });
    expect(res.status).toBe(502);
    expect(res.body.error).toMatch(/No enrolled Velociraptor client/);
  });

  it("501s when the Velociraptor API is not configured", async () => {
    const { app } = await makeApp({});
    const res = await request(app).post("/velociraptor/collect-host").send({ hostname: "WEB01", vql: "SELECT 1" });
    expect(res.status).toBe(501);
  });
});
