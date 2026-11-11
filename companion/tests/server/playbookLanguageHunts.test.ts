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

// #2559: playbook hunts in the case's main-source language (CrowdStrike → CQL), persisted beside the
// VQL ones, and retired when the main source changes.

const cqlReply = JSON.stringify({
  suggestions: [
    {
      taskId: "finding:f1",
      relevant: true,
      title: "Find the loader on every host",
      rationale: "scope it",
      query: "#event_simpleName=ProcessRollup2 | ImageFileName=/loader\\.exe/i",
      severity: "High",
      mitreTechniques: ["T1204.002"],
    },
  ],
});

class Recording implements AIProvider {
  name = "mock";
  model = "m";
  systemPrompts: string[] = [];
  async analyze(req: AnalyzeRequest) {
    this.systemPrompts.push(req.systemPrompt);
    return { rawText: cqlReply };
  }
}

async function makeApp() {
  const store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-pblang-")));
  const stateStore = new StateStore(store);
  const provider = new Recording();
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
    sources: ["CrowdStrike Falcon"],
    importBatchId: "b1",
  };
  s.forensicTimeline.push(e);
  await stateStore.save(s);
  return { app, provider };
}

describe("playbook hunts in the main-source language (#2559)", () => {
  it("writes CQL for a CrowdStrike case, persists it, and returns it on GET /playbook", async () => {
    const { app, provider } = await makeApp();
    const gen = await request(app).post("/cases/c1/playbook/suggest-hunts").send({});
    expect(gen.status).toBe(200);
    expect(gen.body.suggestions).toEqual([]); // no VQL card for a CQL task
    expect(gen.body.languageSuggestions).toEqual([
      expect.objectContaining({ taskId: "finding:f1", language: "cql", platform: "crowdstrike" }),
    ]);
    expect(gen.body.languageSuggestions[0]).not.toHaveProperty("vql");
    expect(provider.systemPrompts).toHaveLength(1);

    const read = await request(app).get("/cases/c1/playbook");
    expect(read.body.languageHuntSuggestions).toHaveLength(1);

    // A second press sends nothing new: the task was already seen in CQL.
    await request(app).post("/cases/c1/playbook/suggest-hunts").send({});
    expect(provider.systemPrompts).toHaveLength(1);
  });

  it("retires the CQL card when the analyst switches the main source", async () => {
    const { app } = await makeApp();
    await request(app).post("/cases/c1/playbook/suggest-hunts").send({});
    await request(app).put("/cases/c1/main-source").send({ override: "splunk" });
    const read = await request(app).get("/cases/c1/playbook");
    expect(read.body.languageHuntSuggestions).toBeUndefined();
  });

  it("an other-cloud override gives no hunt and a note", async () => {
    const { app, provider } = await makeApp();
    await request(app).put("/cases/c1/main-source").send({ override: "cloud-other" });
    const gen = await request(app).post("/cases/c1/playbook/suggest-hunts").send({});
    expect(provider.systemPrompts).toHaveLength(0);
    expect(gen.body.suggestions).toEqual([]);
    expect(gen.body.notes.join(" ")).toMatch(/Query Translator/);
  });
});
