import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { MockProvider } from "../../src/providers/provider.js";
import { emptyState } from "../../src/analysis/stateTypes.js";

const cannedSuggestions = JSON.stringify({
  suggestions: [
    { title: "Hunt ASPX webshells fleet-wide", rationale: "spread check", vql: "SELECT FullPath FROM glob(globs='C:/inetpub/wwwroot/**/*.aspx')", severity: "High", mitreTechniques: ["T1505.003"], relatedFindingIds: ["f1"] },
  ],
});

async function makeApp(provider: MockProvider | undefined) {
  const root = await mkdtemp(join(tmpdir(), "dfir-suggest-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const pipeline = buildRuntimePipeline({
    provider, synthesisProvider: provider, stateStore, store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, { pipeline, stateStore, aiConfigured: Boolean(provider) });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: provider ? "mock" : null });
  return { app, stateStore };
}

async function seedFinding(stateStore: StateStore) {
  const s = emptyState("c1");
  s.findings.push({ id: "f1", severity: "Critical", title: "Webshell on WEB01", description: "ASPX webshell",
    relatedIocs: [], mitreTechniques: ["T1505.003"], sourceScreenshots: [], firstSeen: "", lastUpdated: "", status: "open" });
  await stateStore.save(s);
}

describe("POST /cases/:id/velociraptor/suggest-hunts", () => {
  it("returns AI-suggested fleet hunts when an AI provider is configured", async () => {
    const { app, stateStore } = await makeApp(new MockProvider("mock", cannedSuggestions));
    await seedFinding(stateStore);
    const res = await request(app).post("/cases/c1/velociraptor/suggest-hunts").send({});
    expect(res.status).toBe(200);
    expect(res.body.suggestions).toHaveLength(1);
    expect(res.body.suggestions[0].vql).toContain("glob");
  });

  it("returns [] (no AI spend) on a case with no findings or events", async () => {
    const { app, stateStore } = await makeApp(new MockProvider("mock", cannedSuggestions));
    await stateStore.save(emptyState("c1"));
    const res = await request(app).post("/cases/c1/velociraptor/suggest-hunts").send({});
    expect(res.status).toBe(200);
    expect(res.body.suggestions).toEqual([]);
  });

  it("501s when no AI provider is configured", async () => {
    const { app, stateStore } = await makeApp(undefined);
    await seedFinding(stateStore);
    const res = await request(app).post("/cases/c1/velociraptor/suggest-hunts").send({});
    expect(res.status).toBe(501);
  });
});
