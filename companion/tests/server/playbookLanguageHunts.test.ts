import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { afterEach, describe, expect, it } from "vitest";
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

// Answers every task id named in the prompt: CQL for a language-hunt call, VQL for the VQL path.
class EchoAll implements AIProvider {
  name = "mock";
  model = "m";
  userPrompts: string[] = [];
  async analyze(req: AnalyzeRequest) {
    this.userPrompts.push(req.userPrompt);
    const ids = [...new Set(req.userPrompt.match(/finding:[a-z]+\d+/g) ?? [])];
    const isLanguage = /Propose the per-task .+ queries/.test(req.userPrompt);
    const suggestions = ids.map((taskId) =>
      isLanguage
        ? {
            taskId,
            relevant: true,
            title: `Hunt ${taskId}`,
            rationale: "r",
            query: `#event_simpleName=X | t="${taskId}"`,
            severity: "High",
            mitreTechniques: [],
          }
        : {
            taskId,
            endpointRelated: true,
            title: `Hunt ${taskId}`,
            rationale: "r",
            vql: "SELECT * FROM info()",
            targetHost: "WS01",
            severity: "High",
            mitreTechniques: [],
          },
    );
    return { rawText: JSON.stringify({ suggestions }) };
  }
}

const finding = (id: string) => ({
  id,
  severity: "Critical" as const,
  title: `Loader ${id} on WS01`,
  description: "loader.exe",
  relatedIocs: [],
  relatedEventIds: [`e-${id}`],
  mitreTechniques: [],
  sourceScreenshots: [],
  firstSeen: "",
  lastUpdated: "",
  status: "open" as const,
});

const eventFor = (id: string, source: string): ForensicEvent => ({
  id: `e-${id}`,
  timestamp: "2026-06-01T00:00:00Z",
  description: `loader ${id} ran`,
  severity: "High",
  mitreTechniques: [],
  relatedFindingIds: [id],
  sourceScreenshots: [],
  asset: "WS01",
  sources: [source],
  importBatchId: "b1",
});

/** A case with `cql` CrowdStrike findings and `vql` Velociraptor findings, answered by EchoAll. */
async function makeEchoApp(cql: number, vql = 0) {
  const store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-pblang-")));
  const stateStore = new StateStore(store);
  const provider = new EchoAll();
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
  for (let i = 1; i <= cql; i++) {
    s.findings.push(finding(`f${i}`));
    s.forensicTimeline.push(eventFor(`f${i}`, "CrowdStrike Falcon"));
  }
  for (let i = 1; i <= vql; i++) {
    s.findings.push(finding(`v${i}`));
    s.forensicTimeline.push(eventFor(`v${i}`, "Velociraptor"));
  }
  await stateStore.save(s);
  return { app, provider };
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

  describe("the per-generation cap", () => {
    const savedMax = process.env.DFIR_PBHUNT_SUGGEST_MAX;
    afterEach(() => {
      if (savedMax === undefined) delete process.env.DFIR_PBHUNT_SUGGEST_MAX;
      else process.env.DFIR_PBHUNT_SUGGEST_MAX = savedMax;
    });

    const cqlIds = (body: { languageSuggestions?: Array<{ taskId: string }> }) =>
      new Set((body.languageSuggestions ?? []).map((h) => h.taskId));

    it("a capped CQL batch reports more and leaves the unanswered tasks for the next press", async () => {
      process.env.DFIR_PBHUNT_SUGGEST_MAX = "30";
      const { app, provider } = await makeEchoApp(40);
      const first = await request(app).post("/cases/c1/playbook/suggest-hunts").send({});
      expect(first.status).toBe(200);
      expect(first.body.languageSuggestions).toHaveLength(30);
      expect(first.body.more).toBe(true);

      const second = await request(app).post("/cases/c1/playbook/suggest-hunts").send({});
      expect(second.body.languageSuggestions).toHaveLength(40);
      expect(cqlIds(second.body).size).toBe(40);
      expect(second.body.more).toBe(false);
      // The second press sent only the 10 the first one never answered.
      const sent = provider.userPrompts[1].match(/finding:f\d+/g) ?? [];
      expect(new Set(sent).size).toBe(10);
      for (const id of sent) expect(cqlIds(first.body).has(id)).toBe(false);

      // Everything is now seen: a third press sends nothing.
      await request(app).post("/cases/c1/playbook/suggest-hunts").send({});
      expect(provider.userPrompts).toHaveLength(2);
    });

    it("under the cap every task is answered in one press and more stays false", async () => {
      process.env.DFIR_PBHUNT_SUGGEST_MAX = "30";
      const { app, provider } = await makeEchoApp(5);
      const first = await request(app).post("/cases/c1/playbook/suggest-hunts").send({});
      expect(first.body.languageSuggestions).toHaveLength(5);
      expect(first.body.more).toBe(false);
      await request(app).post("/cases/c1/playbook/suggest-hunts").send({});
      expect(provider.userPrompts).toHaveLength(1);
    });

    it("in a mixed VQL + CQL case, more reflects a capped CQL batch", async () => {
      process.env.DFIR_PBHUNT_SUGGEST_MAX = "3";
      const { app } = await makeEchoApp(5, 1);
      const first = await request(app).post("/cases/c1/playbook/suggest-hunts").send({});
      expect(first.body.suggestions).toHaveLength(1); // VQL not capped
      expect(first.body.languageSuggestions).toHaveLength(3);
      expect(first.body.more).toBe(true);
    });

    it("in a mixed VQL + CQL case, more reflects a capped VQL batch", async () => {
      process.env.DFIR_PBHUNT_SUGGEST_MAX = "3";
      const { app } = await makeEchoApp(1, 5);
      const first = await request(app).post("/cases/c1/playbook/suggest-hunts").send({});
      expect(first.body.suggestions).toHaveLength(3);
      expect(first.body.languageSuggestions).toHaveLength(1); // CQL not capped
      expect(first.body.more).toBe(true);
    });
  });
});
