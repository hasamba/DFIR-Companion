import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { PlaybookControlStore } from "../../src/analysis/playbookControl.js";
import { PlaybookHuntStore } from "../../src/analysis/playbookHuntStore.js";
import { PlaybookStore } from "../../src/analysis/playbookStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { AIProvider, AnalyzeRequest } from "../../src/providers/provider.js";
import { buildRuntimePipeline, createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { enableCaseAi } from "../helpers/enableCaseAi.js";

// #2667: a case whose evidence came from Wazuh gets its hunts in Wazuh dashboard search (DQL), on the
// fleet route and the playbook route, through the real routes with a mocked model.

const DQL = "data.win.eventdata.image:*loader.exe and agent.name:WS01";

class WazuhModel implements AIProvider {
  name = "mock";
  model = "m";
  userPrompts: string[] = [];
  async analyze(req: AnalyzeRequest) {
    this.userPrompts.push(req.userPrompt);
    const taskIds = [...new Set(req.userPrompt.match(/finding:[a-z]+\d+/g) ?? [])];
    const common = { title: "Loader on Wazuh agents", rationale: "r", severity: "High", mitreTechniques: [] };
    const suggestions = taskIds.length
      ? taskIds.map((taskId) => ({ ...common, taskId, relevant: true, platform: "wazuh-dql", query: DQL }))
      : [{ ...common, platform: "wazuh", query: DQL, relatedFindingIds: ["f1"] }];
    return { rawText: JSON.stringify({ suggestions }) };
  }
}

async function makeApp() {
  const store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-wazuh-")));
  const stateStore = new StateStore(store);
  const provider = new WazuhModel();
  const pipeline = buildRuntimePipeline({
    provider,
    synthesisProvider: provider,
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, {
    pipeline,
    stateStore,
    playbookStore: new PlaybookStore(store),
    playbookHuntStore: new PlaybookHuntStore(store),
    playbookControlStore: new PlaybookControlStore(store),
    aiConfigured: true,
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
  await enableCaseAi(store, "c1");
  const s = emptyState("c1");
  s.findings.push({
    id: "f1",
    severity: "Critical",
    title: "Loader on WS01",
    description: "loader.exe",
    relatedIocs: [],
    relatedEventIds: ["e1"],
    mitreTechniques: [],
    sourceScreenshots: [],
    firstSeen: "",
    lastUpdated: "",
    status: "open",
  });
  const e: ForensicEvent = {
    id: "e1",
    timestamp: "2026-06-01T00:00:00Z",
    description: "loader.exe ran",
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: ["f1"],
    sourceScreenshots: [],
    asset: "WS01",
    sources: ["Wazuh"],
    importBatchId: "b1",
  };
  s.forensicTimeline.push(e);
  await stateStore.save(s);
  return { app, provider };
}

describe("a Wazuh case hunts in Wazuh dashboard search (#2667)", () => {
  it("reports Wazuh as the main source and its language", async () => {
    const { app } = await makeApp();
    const r = await request(app).get("/cases/c1/main-source");
    expect(r.body.effective).toBe("wazuh");
    expect(r.body.language).toMatchObject({
      language: "wazuh-dql",
      label: "Wazuh dashboard search",
      note: "",
    });
    expect(r.body.families.map((f: { family: string }) => f.family)).toContain("wazuh");
  });

  it("fleet hunts come back as wazuh-dql, grounded in the Wazuh schema hint", async () => {
    const { app, provider } = await makeApp();
    const r = await request(app).post("/cases/c1/velociraptor/suggest-hunts").send({});
    expect(r.status).toBe(200);
    expect(r.body.languageHunts).toEqual([
      expect.objectContaining({ language: "wazuh-dql", platform: "wazuh", query: DQL }),
    ]);
    expect(provider.userPrompts.join("\n")).toMatch(/TARGET LANGUAGE: wazuh-dql — Wazuh dashboard search/);
    expect(provider.userPrompts.join("\n")).toContain("data.win.eventdata");
  });

  it("playbook hunts come back as wazuh-dql, and a regenerate for that language is accepted", async () => {
    const { app } = await makeApp();
    const gen = await request(app).post("/cases/c1/playbook/suggest-hunts").send({});
    expect(gen.status).toBe(200);
    expect(gen.body.languageSuggestions).toEqual([
      expect.objectContaining({ taskId: "finding:f1", language: "wazuh-dql", platform: "wazuh" }),
    ]);
    const regen = await request(app)
      .post("/cases/c1/playbook/suggest-hunts")
      .send({ taskId: "finding:f1", language: "wazuh-dql", excludeQuery: "rule.level:15" });
    expect(regen.status).toBe(200);
    expect((await request(app).get("/cases/c1/playbook")).body.languageHuntSuggestions).toHaveLength(1);
  });
});
