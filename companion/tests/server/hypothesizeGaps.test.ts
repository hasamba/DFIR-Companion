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

// The model echoes the worst gap's id (gap-1) with a hypothesis + recommended shadow-artifact ids.
const cannedHypotheses = JSON.stringify({
  hypotheses: [
    {
      gapId: "gap-1",
      hypothesis: "The Security log was cleared after the RDP logon to hide credential access during the silence.",
      attackerActions: ["Cleared the Windows Security event log", "Dumped LSASS"],
      confidence: 55,
      severity: "High",
      mitreTechniques: ["T1070.001", "T1003.001"],
      recommendedArtifactIds: ["prefetch", "amcache", "usn-journal"],
    },
  ],
});

async function makeApp(provider: MockProvider | undefined) {
  const root = await mkdtemp(join(tmpdir(), "dfir-gaphyp-"));
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

function ev(id: string, ts: string): ForensicEvent {
  return { id, timestamp: ts, description: `event ${id}`, severity: "Info", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], asset: "WEB01", sources: ["EventLog"] };
}

// A dense one-minute cadence cluster, then a 4-hour hole, then activity resumes — a complete-silence
// gap that clears the density + floor bars, so detectTimelineGaps flags exactly one gap (gap-1).
async function seedGappyTimeline(stateStore: StateStore) {
  const s = emptyState("c1");
  for (let i = 0; i < 6; i++) s.forensicTimeline.push(ev(`a${i}`, new Date(Date.parse("2026-05-20T08:00:00Z") + i * 60_000).toISOString()));
  for (let i = 0; i < 4; i++) s.forensicTimeline.push(ev(`b${i}`, new Date(Date.parse("2026-05-20T12:00:00Z") + i * 60_000).toISOString()));
  await stateStore.save(s);
}

describe("POST /cases/:id/timeline-gaps/hypothesize", () => {
  it("returns AI hypotheses with shadow-artifact collections when a gap is flagged", async () => {
    const { app, stateStore } = await makeApp(new MockProvider("mock", cannedHypotheses));
    await seedGappyTimeline(stateStore);
    const res = await request(app).post("/cases/c1/timeline-gaps/hypothesize").send({});
    expect(res.status).toBe(200);
    expect(res.body.hypotheses).toHaveLength(1);
    const h = res.body.hypotheses[0];
    expect(h.gapId).toBe("gap-1");
    expect(h.hypothesis).toContain("Security log");
    expect(h.recommendedArtifactIds).toContain("prefetch");
    // Deterministic shadow-artifact collections are attached and deployable.
    expect(h.shadowArtifacts.length).toBeGreaterThan(0);
    expect(h.shadowArtifacts.some((a: { id: string }) => a.id === "usn-journal")).toBe(true);
    expect(h.shadowArtifacts[0].vql).toMatch(/^SELECT .+ FROM Artifact\./);
    expect(h.targetHosts).toContain("WEB01");
    expect(typeof res.body.caveat).toBe("string");
  });

  it("returns no hypotheses (no AI spend) when the timeline has no flagged gaps", async () => {
    const { app, stateStore } = await makeApp(new MockProvider("mock", cannedHypotheses));
    await stateStore.save(emptyState("c1"));
    const res = await request(app).post("/cases/c1/timeline-gaps/hypothesize").send({});
    expect(res.status).toBe(200);
    expect(res.body.hypotheses).toEqual([]);
  });

  it("501s when no AI provider is configured", async () => {
    const { app, stateStore } = await makeApp(undefined);
    await seedGappyTimeline(stateStore);
    const res = await request(app).post("/cases/c1/timeline-gaps/hypothesize").send({});
    expect(res.status).toBe(501);
  });
});
