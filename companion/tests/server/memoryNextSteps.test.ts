import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { MockProvider } from "../../src/providers/provider.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

const cannedSuggestions = JSON.stringify({
  suggestions: [
    {
      anomaly: "svchost.exe (PID 1234) is parented by explorer.exe, not services.exe",
      command: "vol -f <image> windows.malfind --pid 1234",
      plugin: "windows.malfind",
      rationale: "Mis-parented svchost — dump injected memory and yara-scan it.",
      severity: "High",
      pid: "1234",
      mitreTechniques: ["T1055"],
    },
  ],
});

async function makeApp(provider: MockProvider | undefined) {
  const root = await mkdtemp(join(tmpdir(), "dfir-memnext-"));
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

function memEvent(over: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id: "e1", timestamp: "2026-06-10T00:00:00.000Z",
    description: "Volatility pslist: svchost.exe (PID 1234, PPID 4500) started",
    severity: "Info", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [],
    sources: ["Volatility"], ...over,
  };
}

async function seedMemory(stateStore: StateStore) {
  const s = emptyState("c1");
  s.forensicTimeline.push(memEvent());
  await stateStore.save(s);
}

describe("POST /cases/:id/memory/next-steps", () => {
  it("returns AI-suggested next steps when memory evidence + an AI provider exist", async () => {
    const { app, stateStore } = await makeApp(new MockProvider("mock", cannedSuggestions));
    await seedMemory(stateStore);
    const res = await request(app).post("/cases/c1/memory/next-steps").send({});
    expect(res.status).toBe(200);
    expect(res.body.suggestions).toHaveLength(1);
    expect(res.body.suggestions[0].command).toContain("windows.malfind");
  });

  it("returns [] (no AI spend) on a case with no memory evidence", async () => {
    const { app, stateStore } = await makeApp(new MockProvider("mock", cannedSuggestions));
    const s = emptyState("c1");
    s.forensicTimeline.push(memEvent({ sources: ["THOR"], description: "THOR alert: not memory" }));
    await stateStore.save(s);
    const res = await request(app).post("/cases/c1/memory/next-steps").send({});
    expect(res.status).toBe(200);
    expect(res.body.suggestions).toEqual([]);
  });

  it("501s when no AI provider is configured", async () => {
    const { app, stateStore } = await makeApp(undefined);
    await seedMemory(stateStore);
    const res = await request(app).post("/cases/c1/memory/next-steps").send({});
    expect(res.status).toBe(501);
  });
});
