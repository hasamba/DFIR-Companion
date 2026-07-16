import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { TagsStore } from "../../src/analysis/tags.js";
import { StarredReportStore } from "../../src/analysis/starredReportStore.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../src/providers/provider.js";

class CapturingProvider implements AIProvider {
  readonly name = "capture";
  lastReq?: AnalyzeRequest;
  async analyze(req: AnalyzeRequest): Promise<AnalyzeResult> {
    this.lastReq = req;
    return { rawText: JSON.stringify({ markdown: "# Starred Events Report\n\nreport body" }) };
  }
}

const sev = (id: string, ts: string, description: string) => ({
  id, timestamp: ts, description, severity: "Info" as const,
  mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [],
});

async function harness(opts: { ai?: boolean } = {}) {
  const ai = opts.ai ?? true;
  const root = await mkdtemp(join(tmpdir(), "dfir-starredrt-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const provider = ai ? new CapturingProvider() : undefined;
  const pipeline = buildRuntimePipeline({
    provider, synthesisProvider: provider, stateStore, store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const superStore = new SuperTimelineStore(store);
  const app = createApp(store, {
    pipeline, stateStore, aiConfigured: ai,
    tagsStore: new TagsStore(store),
    superTimelineStore: superStore,
    starredReportStore: new StarredReportStore(store),
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, superStore, provider };
}

describe("POST /cases/:id/starred-report", () => {
  it("501 when no AI provider is configured", async () => {
    const { app } = await harness({ ai: false });
    expect((await request(app).post("/cases/c1/starred-report").send({})).status).toBe(501);
  });

  it("400 when nothing is starred", async () => {
    const { app } = await harness();
    const r = await request(app).post("/cases/c1/starred-report").send({});
    expect(r.status).toBe(400);
    expect(r.body.error).toMatch(/no starred events/);
  });

  it("reports over the events tagged 'starred' (and only those)", async () => {
    const { app, superStore, provider } = await harness();
    await superStore.append("c1", [
      sev("sv1", "2026-06-01T09:00:00Z", "mimikatz.exe executed"),
      sev("sv2", "2026-06-01T10:00:00Z", "benign chrome update"),
    ]);
    await request(app).post("/cases/c1/tags").send({ targetType: "event", targetId: "sv1", label: "starred", author: "an" });
    const r = await request(app).post("/cases/c1/starred-report").send({});
    expect(r.status).toBe(200);
    expect(r.body.markdown).toContain("# Starred Events Report");
    expect(r.body.eventCount).toBe(1);
    expect(provider!.lastReq!.userPrompt).toContain("mimikatz.exe executed");
    expect(provider!.lastReq!.userPrompt).not.toContain("benign chrome update");
  });
});

describe("saved starred report (GET/PUT /cases/:id/starred-report)", () => {
  it("404 before anything is saved; round-trips after PUT", async () => {
    const { app } = await harness();
    expect((await request(app).get("/cases/c1/starred-report")).status).toBe(404);
    const put = await request(app).put("/cases/c1/starred-report").send({ markdown: "# saved", eventCount: 3 });
    expect(put.status).toBe(200);
    const got = await request(app).get("/cases/c1/starred-report");
    expect(got.status).toBe(200);
    expect(got.body.markdown).toBe("# saved");
    expect(got.body.eventCount).toBe(3);
    expect(typeof got.body.savedAt).toBe("string");
  });

  it("400 on an empty markdown body", async () => {
    const { app } = await harness();
    expect((await request(app).put("/cases/c1/starred-report").send({ markdown: "" })).status).toBe(400);
  });
});

describe("POST /cases/:id/view-summary", () => {
  it("summarizes only the events matching the posted filter set", async () => {
    const { app, superStore, provider } = await harness();
    await superStore.append("c1", [
      sev("v1", "2026-06-01T09:00:00Z", "psexec lateral hop"),
      sev("v2", "2026-06-01T10:00:00Z", "normal dns chatter"),
    ]);
    await request(app).post("/cases/c1/tags").send({ targetType: "event", targetId: "v1", label: "exfil", author: "an" });
    const r = await request(app).post("/cases/c1/view-summary").send({ labels: "exfil" });
    expect(r.status).toBe(200);
    expect(r.body.eventCount).toBe(1);
    expect(provider!.lastReq!.userPrompt).toContain("psexec lateral hop");
    expect(provider!.lastReq!.userPrompt).not.toContain("normal dns chatter");
  });

  it("applies the starred filter", async () => {
    const { app, superStore, provider } = await harness();
    await superStore.append("c1", [
      sev("v1", "2026-06-01T09:00:00Z", "starred row"),
      sev("v2", "2026-06-01T10:00:00Z", "plain row"),
    ]);
    await request(app).post("/cases/c1/tags").send({ targetType: "event", targetId: "v1", label: "starred", author: "an" });
    const r = await request(app).post("/cases/c1/view-summary").send({ starred: "1" });
    expect(r.status).toBe(200);
    expect(provider!.lastReq!.userPrompt).toContain("starred row");
    expect(provider!.lastReq!.userPrompt).not.toContain("plain row");
  });

  it("400 when the filters match nothing", async () => {
    const { app } = await harness();
    const r = await request(app).post("/cases/c1/view-summary").send({ labels: "nope" });
    expect(r.status).toBe(400);
  });
});
