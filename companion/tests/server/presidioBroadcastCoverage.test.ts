import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline, type AiStatusEvent } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../src/providers/provider.js";
import type { PresidioClient } from "../../src/analysis/presidio.js";

class StubProvider implements AIProvider {
  readonly name = "stub";
  readonly model = "mock-model";
  async analyze(_req: AnalyzeRequest): Promise<AnalyzeResult> {
    // explainEventSchema requires these fields; content is irrelevant — the gate fires before
    // this is ever parsed.
    return {
      rawText: JSON.stringify({
        summary: "x",
        whyItMatters: "x",
        normalContext: "x",
        suspiciousIndicators: "x",
        attackMapping: "x",
        pivotQueries: [],
        evidenceFor: "x",
        evidenceAgainst: "x",
        relatedEventIds: [],
      }),
    };
  }
}

// task 9 review finding: several aiSynthesis.ts routes (explain-event, executive-summary,
// narrative, remediation-plan, hypothesis-review, starred-report, view-summary,
// second-opinion/apply[-all]) throw PresidioApprovalRequired through sendPipelineError with
// NEITHER a client-side 409 handler NOR an ai_status broadcast — so the dashboard's
// store-driven approval panel (which is triggered by case-load + ai_status:error, see task 9)
// never surfaces for them. The fix makes sendPipelineError itself broadcast ai_status:error
// whenever it handles a PresidioApprovalRequired AND is given a case/status-emitter context, so
// every route funnelling errors through the shared helper is covered without hand-wiring each one
// — including routes added later. This test picks explain-event (one of the listed routes, NOT
// Ask/Synthesize/Second-opinion, which already had their own coverage) and asserts BOTH halves.
describe("sendPipelineError broadcasts ai_status:error for PresidioApprovalRequired (explain-event)", () => {
  it("returns 409 with the approval marker AND fires an ai_status:error broadcast", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-presidiobroadcast-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    await store.createCase({ caseId: "c1", name: "Test", investigator: "analyst", aiProvider: null });
    const s = emptyState("c1");
    s.forensicTimeline.push({
      id: "ev1",
      timestamp: "2026-06-01T10:00:00Z",
      description: "powershell.exe spawned",
      severity: "High",
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
      asset: "WS01",
    });
    await stateStore.save(s);

    // A Presidio stub that always reports one PERSON finding — "Jane Doe" is not yet in this
    // fresh case's discovered/suppressed lists, so the gate treats it as new and throws.
    const presidioClient: PresidioClient = {
      analyze: async () => [{ entityType: "PERSON", value: "Jane Doe", score: 0.9 }],
    };
    const pipeline = buildRuntimePipeline({
      provider: new StubProvider(),
      stateStore,
      store,
      imageLoader: async () => ({ base64: "AA", mimeType: "image/webp" }),
      presidio: { client: presidioClient, url: "http://localhost:5002", minScore: 0.6 },
    });

    const statusEvents: { caseId: string; event: AiStatusEvent }[] = [];
    const app = createApp(store, {
      pipeline,
      stateStore,
      aiConfigured: true,
      onAiStatus: (caseId, event) => statusEvents.push({ caseId, event }),
    });

    const res = await request(app).post("/cases/c1/events/ev1/explain");

    // Half 1: the 409 body still carries the approval marker + mapped findings, unchanged.
    expect(res.status).toBe(409);
    expect(res.body).toEqual({
      error: "presidio_approval_required",
      findings: [{ value: "Jane Doe", category: "PERSON" }],
    });

    // Half 2: the status broadcast fired for THIS case, with an error status — this is what lets
    // the dashboard's applyAiStatus → loadPresidioPending path surface the panel for a route that
    // has no dedicated client-side 409 handler.
    const errorEvents = statusEvents.filter((e) => e.event.status === "error");
    expect(errorEvents).toHaveLength(1);
    expect(errorEvents[0].caseId).toBe("c1");
    expect(errorEvents[0].event.detail).toMatch(/Presidio/i);
  });

  it("still answers 500 for a genuine (non-Presidio) failure, with no status broadcast side effect", async () => {
    // Guards against a broadened sendPipelineError accidentally broadcasting on EVERY error,
    // which would spam ai_status:error for ordinary failures unrelated to the approval gate.
    const root = await mkdtemp(join(tmpdir(), "dfir-presidiobroadcast-plain-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    await store.createCase({ caseId: "c1", name: "Test", investigator: "analyst", aiProvider: null });
    const s = emptyState("c1");
    s.forensicTimeline.push({
      id: "ev1",
      timestamp: "2026-06-01T10:00:00Z",
      description: "powershell.exe spawned",
      severity: "High",
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
      asset: "WS01",
    });
    await stateStore.save(s);

    class BrokenProvider implements AIProvider {
      readonly name = "broken";
      readonly model = "mock-model";
      async analyze(): Promise<AnalyzeResult> {
        throw new Error("provider exploded");
      }
    }
    const pipeline = buildRuntimePipeline({
      provider: new BrokenProvider(),
      stateStore,
      store,
      imageLoader: async () => ({ base64: "AA", mimeType: "image/webp" }),
    });

    const statusEvents: { caseId: string; event: AiStatusEvent }[] = [];
    const app = createApp(store, {
      pipeline,
      stateStore,
      aiConfigured: true,
      onAiStatus: (caseId, event) => statusEvents.push({ caseId, event }),
    });

    const res = await request(app).post("/cases/c1/events/ev1/explain");
    expect(res.status).toBe(500);
    expect(res.body.error).toMatch(/provider exploded/);
    expect(statusEvents.filter((e) => e.event.status === "error")).toHaveLength(0);
  });
});

// A second, follow-up review found that FIVE MORE routes reach analyzeRestored/presidioGate but
// never adopted sendPipelineError at all — they caught with a raw `res.status(500).json({ error:
// (err as Error).message })`, so a PresidioApprovalRequired there didn't even 409, just 500'd with
// the marker text buried in a plain error string. This is the same finding as above by a different
// mechanism (never adopted the helper, vs. calling it without ctx) — task 8 only converted
// aiSynthesis.ts/import.ts, and a reviewer tracing sendPipelineError call sites can't see routes
// that never call it. Fixed: translate-query (anonymization.ts), playbook/suggest-hunts
// (playbookHunts.ts), timeline-gaps/hypothesize (timeline.ts), false-positive/suggest (findings.ts,
// AI branch), tagger/suggest-rule (tagger.ts), and velociraptor/suggest-hunts (velociraptor.ts) —
// the last two found by re-auditing every analyzeRestored call site in pipeline.ts against every
// route file, not just the ones named in review. This test picks translate-query — a DIFFERENT
// file from explain-event above (anonymization.ts, not aiSynthesis.ts) — to prove the pattern holds
// outside the file the helper was first adopted in.
describe("sendPipelineError broadcasts ai_status:error for PresidioApprovalRequired (translate-query, a route that never called the helper before this fix)", () => {
  it("returns 409 with the approval marker AND fires an ai_status:error broadcast", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-presidiobroadcast-translate-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    await store.createCase({ caseId: "c1", name: "Test", investigator: "analyst", aiProvider: null });
    const s = emptyState("c1");
    s.forensicTimeline.push({
      id: "ev1",
      timestamp: "2026-06-01T10:00:00Z",
      description: "rdp session from DC01",
      severity: "High",
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
      asset: "DC01",
    });
    await stateStore.save(s);

    const presidioClient: PresidioClient = {
      analyze: async () => [{ entityType: "PERSON", value: "Jane Doe", score: 0.9 }],
    };
    const pipeline = buildRuntimePipeline({
      provider: new StubProvider(),
      stateStore,
      store,
      imageLoader: async () => ({ base64: "AA", mimeType: "image/webp" }),
      presidio: { client: presidioClient, url: "http://localhost:5002", minScore: 0.6 },
    });

    const statusEvents: { caseId: string; event: AiStatusEvent }[] = [];
    const app = createApp(store, {
      pipeline,
      stateStore,
      aiConfigured: true,
      onAiStatus: (caseId, event) => statusEvents.push({ caseId, event }),
    });

    const res = await request(app)
      .post("/cases/c1/translate-query")
      .send({ request: "outbound RDP from this host" });

    expect(res.status).toBe(409);
    expect(res.body).toEqual({
      error: "presidio_approval_required",
      findings: [{ value: "Jane Doe", category: "PERSON" }],
    });

    const errorEvents = statusEvents.filter((e) => e.event.status === "error");
    expect(errorEvents).toHaveLength(1);
    expect(errorEvents[0].caseId).toBe("c1");
    expect(errorEvents[0].event.detail).toMatch(/Presidio/i);
  });

  it("still answers 500 for a genuine (non-Presidio) failure, with no status broadcast side effect", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-presidiobroadcast-translate-plain-"));
    const store = new CaseStore(root);
    const stateStore = new StateStore(store);
    await store.createCase({ caseId: "c1", name: "Test", investigator: "analyst", aiProvider: null });
    const s = emptyState("c1");
    s.forensicTimeline.push({
      id: "ev1",
      timestamp: "2026-06-01T10:00:00Z",
      description: "rdp session from DC01",
      severity: "High",
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
      asset: "DC01",
    });
    await stateStore.save(s);

    class BrokenProvider implements AIProvider {
      readonly name = "broken";
      readonly model = "mock-model";
      async analyze(): Promise<AnalyzeResult> {
        throw new Error("provider exploded");
      }
    }
    const pipeline = buildRuntimePipeline({
      provider: new BrokenProvider(),
      stateStore,
      store,
      imageLoader: async () => ({ base64: "AA", mimeType: "image/webp" }),
    });

    const statusEvents: { caseId: string; event: AiStatusEvent }[] = [];
    const app = createApp(store, {
      pipeline,
      stateStore,
      aiConfigured: true,
      onAiStatus: (caseId, event) => statusEvents.push({ caseId, event }),
    });

    const res = await request(app)
      .post("/cases/c1/translate-query")
      .send({ request: "outbound RDP from this host" });
    expect(res.status).toBe(500);
    expect(res.body.error).toMatch(/provider exploded/);
    expect(statusEvents.filter((e) => e.event.status === "error")).toHaveLength(0);
  });
});
