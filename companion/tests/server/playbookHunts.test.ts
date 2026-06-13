import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { PlaybookStore } from "../../src/analysis/playbookStore.js";
import { PlaybookHuntStore } from "../../src/analysis/playbookHuntStore.js";
import { PlaybookControlStore } from "../../src/analysis/playbookControl.js";
import { MockProvider } from "../../src/providers/provider.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import { VelociraptorClient, type VqlRunner, type VelociraptorApiConfig } from "../../src/integrations/velociraptor/velociraptorApi.js";
import { VelociraptorClientStore } from "../../src/analysis/velociraptorClientStore.js";

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

// A runner for collect-host: list the fleet (FROM clients) then launch the collection flow. The app
// in these tests wires the velociraptorClient WITHOUT the inventory store, so the route falls back to
// collectFromHost (live listClients + match + collectOnClient).
const collectRunner: VqlRunner = async (statements) => {
  const p = statements[0];
  if (p.includes("collect_client(")) return { rows: [{ Flow: { flow_id: "F.123" } }], raw: "" };
  if (p.includes("FROM clients(")) return { rows: [{ client_id: "C.web01", os_info: { hostname: "web01" } }], raw: "" };
  return { rows: [], raw: "" };
};

async function makeApp(opts: { provider?: MockProvider; velociraptorProvider?: MockProvider; velociraptorClient?: VelociraptorClient; velociraptorClientStore?: VelociraptorClientStore } = {}) {
  const root = await mkdtemp(join(tmpdir(), "dfir-pbhunt-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const playbookStore = new PlaybookStore(store);
  const playbookHuntStore = new PlaybookHuntStore(store);
  const playbookControlStore = new PlaybookControlStore(store);
  const pipeline = buildRuntimePipeline({
    provider: opts.provider, synthesisProvider: opts.provider, velociraptorProvider: opts.velociraptorProvider, stateStore, store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, {
    pipeline, stateStore, playbookStore, playbookHuntStore, playbookControlStore,
    velociraptorClient: opts.velociraptorClient, velociraptorClientStore: opts.velociraptorClientStore,
    aiConfigured: Boolean(opts.provider),
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

  it("persists suggestions (survive a refresh) and drops them once the task changes", async () => {
    const { app, stateStore } = await makeApp({ provider: new MockProvider("mock", cannedPlaybookHunts) });
    await seed(stateStore, true);
    const gen = await request(app).post("/cases/c1/playbook/suggest-hunts").send({});
    expect(gen.body.suggestions).toHaveLength(1);

    // "page refresh" → GET /playbook returns the persisted suggestion for the unchanged task.
    const refresh = await request(app).get("/cases/c1/playbook");
    expect(refresh.body.huntSuggestions).toHaveLength(1);
    expect(refresh.body.huntSuggestions[0].taskId).toBe("finding:f1");

    // Reword the finding → the derived task's text changes → the suggestion is now stale → dropped.
    const s = emptyState("c1");
    s.findings.push({ id: "f1", severity: "Critical", title: "Webshell REWORDED on WEB02", description: "a different description",
      relatedIocs: [], mitreTechniques: ["T1505.003"], sourceScreenshots: [], firstSeen: "", lastUpdated: "", status: "open" });
    await stateStore.save(s);
    const afterEdit = await request(app).get("/cases/c1/playbook");
    expect(afterEdit.body.huntSuggestions).toHaveLength(0);
  });

  it("generates INCREMENTALLY — re-pressing generates nothing new, but a changed task is regenerated", async () => {
    const { app, stateStore } = await makeApp({ provider: new MockProvider("mock", cannedPlaybookHunts) });
    await seed(stateStore, true);
    // First generate covers finding:f1.
    const first = await request(app).post("/cases/c1/playbook/suggest-hunts").send({});
    expect(first.body.generated).toBe(1);
    expect(first.body.suggestions).toHaveLength(1);
    // Press again with NO changes → nothing new generated, the existing suggestion is kept.
    const again = await request(app).post("/cases/c1/playbook/suggest-hunts").send({});
    expect(again.body.generated).toBe(0);
    expect(again.body.suggestions).toHaveLength(1);
    // Reword the finding → its task changes → that one is regenerated on the next press.
    const s = emptyState("c1");
    s.findings.push({ id: "f1", severity: "Critical", title: "Webshell REWORDED", description: "new text",
      relatedIocs: [], mitreTechniques: ["T1505.003"], sourceScreenshots: [], firstSeen: "", lastUpdated: "", status: "open" });
    await stateStore.save(s);
    const afterEdit = await request(app).post("/cases/c1/playbook/suggest-hunts").send({});
    expect(afterEdit.body.generated).toBe(1);          // the changed task WAS regenerated
    expect(afterEdit.body.suggestions).toHaveLength(1);
  });

  it("force:true regenerates everything", async () => {
    const { app, stateStore } = await makeApp({ provider: new MockProvider("mock", cannedPlaybookHunts) });
    await seed(stateStore, true);
    await request(app).post("/cases/c1/playbook/suggest-hunts").send({});
    const forced = await request(app).post("/cases/c1/playbook/suggest-hunts").send({ force: true });
    expect(forced.body.generated).toBe(1);   // ignored the covered set, regenerated
  });

  it("uses the dedicated Velociraptor provider over the synthesis model when set", async () => {
    const veloReply = JSON.stringify({ suggestions: [
      { taskId: "finding:f1", endpointRelated: true, title: "FROM VELO MODEL", rationale: "r", vql: "SELECT * FROM pslist()", targetHost: "", severity: "High", mitreTechniques: [] },
    ] });
    const { app, stateStore } = await makeApp({
      provider: new MockProvider("mock", cannedPlaybookHunts),          // synthesis/main model
      velociraptorProvider: new MockProvider("velo", veloReply),        // dedicated VQL model
    });
    await seed(stateStore, true);
    const res = await request(app).post("/cases/c1/playbook/suggest-hunts").send({});
    expect(res.status).toBe(200);
    expect(res.body.suggestions[0].title).toBe("FROM VELO MODEL");      // the velo model's output, not the synth one
  });

  it("refreshes the Velociraptor client inventory when generating suggestions (clients enrolled mid-investigation)", async () => {
    const file = join(await mkdtemp(join(tmpdir(), "dfir-pbinv-")), "velociraptor", "clients.json");
    const inventory = new VelociraptorClientStore(file);
    // The fleet now has a client that wasn't enrolled when the case started.
    const runner: VqlRunner = async (s) => s[0].includes("FROM clients(")
      ? { rows: [{ client_id: "C.web01", os_info: { hostname: "web01", fqdn: "web01.corp.local" } }], raw: "" }
      : { rows: [], raw: "" };
    const { app, stateStore } = await makeApp({
      provider: new MockProvider("mock", cannedPlaybookHunts),
      velociraptorClient: new VelociraptorClient(veloCfg, runner),
      velociraptorClientStore: inventory,
    });
    await seed(stateStore, true);
    expect((await inventory.load()).clients).toHaveLength(0);   // empty before
    const res = await request(app).post("/cases/c1/playbook/suggest-hunts").send({});
    expect(res.status).toBe(200);
    const after = await inventory.load();                       // refreshed by the suggest call
    expect(after.clients.map((c) => c.clientId)).toContain("C.web01");
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
