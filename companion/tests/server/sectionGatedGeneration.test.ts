import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ReportTemplateStore } from "../../src/reports/reportTemplateStore.js";
import { ReportTemplateControlStore } from "../../src/reports/reportTemplateControl.js";
import type { AIProvider, AnalyzeResult } from "../../src/providers/provider.js";
import { emptyState, type InvestigationState } from "../../src/analysis/stateTypes.js";

// A provider that records how many times it's asked to analyze. The gate's whole point is that a
// disabled report section never reaches the model — so `calls` must stay 0 on a gated request.
class CountingProvider implements AIProvider {
  readonly name = "counting";
  calls = 0;
  async analyze(): Promise<AnalyzeResult> {
    this.calls++;
    // Valid for BOTH the exec-summary schema ({summary}) and the narrative schema ({narrativeTimeline}).
    return { rawText: JSON.stringify({ summary: "S", narrativeTimeline: "N" }) };
  }
}

function seededState(): InvestigationState {
  const s = emptyState("c1");
  s.forensicTimeline.push({
    id: "e1", timestamp: "2026-06-10T00:00:00.000Z", description: "malware.exe executed",
    severity: "High", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [],
  });
  return s;
}

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-sectiongate-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const reportTemplateStore = new ReportTemplateStore(join(root, "report-templates"));
  const reportTemplateControlStore = new ReportTemplateControlStore(store);
  const provider = new CountingProvider();
  const pipeline = buildRuntimePipeline({
    provider, synthesisProvider: provider, stateStore, store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, {
    pipeline, stateStore, aiConfigured: true,
    reportTemplateStore, reportTemplateControlStore,
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
  await stateStore.save(seededState());
  return { app, provider };
}

// Create a custom template that disables a given section and select it for case c1.
async function selectTemplateDisabling(app: ReturnType<typeof createApp>, key: string) {
  const tpl = await request(app).post("/report-templates").send({ name: `no-${key}`, sections: [{ key, enabled: false }] });
  await request(app).put("/cases/c1/report-template").send({ templateId: tpl.body.id });
}

describe("AI generation gated by report-section toggle (#168)", () => {
  it("skips the executive-summary AI call (409) when the Executive summary section is disabled", async () => {
    const { app, provider } = await harness();
    await selectTemplateDisabling(app, "executiveSummary");

    const res = await request(app).post("/cases/c1/executive-summary").send({});
    expect(res.status).toBe(409);
    expect(res.body.sectionDisabled).toBe(true);
    expect(res.body.section).toBe("executiveSummary");
    expect(provider.calls).toBe(0); // never reached the model
  });

  it("skips the narrative AI call (409) when the Timeline section (holding the narrative) is disabled", async () => {
    const { app, provider } = await harness();
    await selectTemplateDisabling(app, "timeline");

    const res = await request(app).post("/cases/c1/narrative").send({});
    expect(res.status).toBe(409);
    expect(res.body.sectionDisabled).toBe(true);
    expect(res.body.section).toBe("timeline");
    expect(provider.calls).toBe(0);
  });

  it("generates normally with the default template (all sections enabled)", async () => {
    const { app, provider } = await harness();

    const exec = await request(app).post("/cases/c1/executive-summary").send({});
    expect(exec.status).toBe(200);
    expect(exec.body.summary).toBe("S");

    const narr = await request(app).post("/cases/c1/narrative").send({});
    expect(narr.status).toBe(200);
    expect(narr.body.narrativeTimeline).toBe("N");

    expect(provider.calls).toBe(2); // both generators ran
  });

  it("disabling the Timeline section does NOT block the executive summary (independent gates)", async () => {
    const { app, provider } = await harness();
    await selectTemplateDisabling(app, "timeline");

    const res = await request(app).post("/cases/c1/executive-summary").send({});
    expect(res.status).toBe(200);
    expect(provider.calls).toBe(1);
  });
});
