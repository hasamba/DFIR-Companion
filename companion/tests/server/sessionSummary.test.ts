import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../src/providers/provider.js";

// Route coverage for the per-session AI summary (#342). The point of these tests is the SLICING:
// a session summary that quietly included the whole timeline would still return 200 with plausible
// markdown, so every test here asserts on what actually reached the provider's prompt.

class CapturingProvider implements AIProvider {
  readonly name = "capture";
  readonly model = "capture-model";
  lastReq?: AnalyzeRequest;
  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    this.lastReq = req;
    return { rawText: JSON.stringify({ markdown: "the session account" }) };
  }
}

function ev(
  id: string,
  timestamp: string,
  description: string,
  extra: Partial<ForensicEvent> = {},
): ForensicEvent {
  return {
    id,
    timestamp,
    description,
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...extra,
  };
}

async function harness(opts: { ai?: boolean } = {}) {
  const ai = opts.ai ?? true;
  const root = await mkdtemp(join(tmpdir(), "dfir-sesssum-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const provider = ai ? new CapturingProvider() : undefined;
  const pipeline = buildRuntimePipeline({
    provider,
    synthesisProvider: provider,
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, { pipeline, stateStore, aiConfigured: ai });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  await stateStore.save({
    ...emptyState("c1"),
    forensicTimeline: [
      // Session 1 on DC01 — two tight events.
      ev("e1", "2026-05-20T14:00:00Z", "mimikatz.exe executed", { asset: "DC01" }),
      ev("e2", "2026-05-20T14:01:00Z", "lsass dumped", { asset: "DC01" }),
      // Session 2 on DC01 — hours later.
      ev("e3", "2026-05-20T20:00:00Z", "benign chrome update", { asset: "DC01" }),
    ],
  });
  return { app, provider };
}

describe("POST /cases/:id/sessions/:sid/summary", () => {
  it("501 when no synthesis provider is configured", async () => {
    const { app } = await harness({ ai: false });
    const r = await request(app).post("/cases/c1/sessions/session-1/summary").send({});
    expect(r.status).toBe(501);
  });

  it("summarizes ONLY the events of the requested session", async () => {
    const { app, provider } = await harness();
    const r = await request(app).post("/cases/c1/sessions/session-1/summary").send({});

    expect(r.status).toBe(200);
    expect(r.body.markdown).toBe("the session account");
    expect(r.body.sessionId).toBe("session-1");
    expect(r.body.eventCount).toBe(2);
    expect(r.body.truncated).toBe(false);

    // The actual guarantee: session 2's event never reached the model.
    const prompt = provider!.lastReq!.userPrompt;
    expect(prompt).toContain("mimikatz.exe executed");
    expect(prompt).toContain("lsass dumped");
    expect(prompt).not.toContain("benign chrome update");
  });

  it("passes the session's identity and window as context", async () => {
    const { app, provider } = await harness();
    await request(app).post("/cases/c1/sessions/session-1/summary").send({});

    const prompt = provider!.lastReq!.userPrompt;
    expect(prompt).toMatch(/^SESSION: .+/m);
    expect(prompt).toMatch(/^HOST: .+/m);
    expect(prompt).toContain("WINDOW: 2026-05-20T14:00:00Z → 2026-05-20T14:01:00Z");
  });

  it("anonymizes the session context before it reaches the model", async () => {
    const { app, provider } = await harness();
    const r = await request(app).post("/cases/c1/sessions/session-1/summary").send({});
    expect(r.status).toBe(200);

    // Session events are raw forensic rows carrying hostnames, so the summary MUST route through
    // the same anonymize/restore round-trip as every other AI call. The real hostname must not
    // appear anywhere in the outbound prompt — not in the event lines, and not in the SESSION /
    // HOST context lines this endpoint adds on top of them.
    const prompt = provider!.lastReq!.userPrompt;
    expect(prompt).not.toContain("DC01");
    expect(prompt).toMatch(/HOST: ANON_HOST_\d+/);
  });

  it("addresses a different session by its own id", async () => {
    const { app, provider } = await harness();
    const r = await request(app).post("/cases/c1/sessions/session-2/summary").send({});

    expect(r.status).toBe(200);
    expect(r.body.eventCount).toBe(1);
    expect(provider!.lastReq!.userPrompt).toContain("benign chrome update");
    expect(provider!.lastReq!.userPrompt).not.toContain("mimikatz.exe executed");
  });

  it("404s for a session id the current segmentation does not produce", async () => {
    const { app } = await harness();
    const r = await request(app).post("/cases/c1/sessions/session-99/summary").send({});

    // Session ids are DERIVED, so a stale dashboard card or a changed gap threshold lands here
    // routinely — it must read as "gone", not as a server fault.
    expect(r.status).toBe(404);
    expect(r.body.error).toMatch(/session not found/);
  });

  it("404s for a case that does not exist", async () => {
    const { app } = await harness();
    const r = await request(app).post("/cases/typo/sessions/session-1/summary").send({});
    expect(r.status).toBe(404);
  });
});
