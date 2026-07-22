import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import sharp from "sharp";
import { CaseStore } from "../src/storage/caseStore.js";
import { createApp } from "../src/server.js";
import { _resetDedupCache } from "../src/ingest/captureIngest.js";
import { AnalysisPipeline } from "../src/analysis/pipeline.js";
import { StateStore } from "../src/analysis/stateStore.js";
import { MockProvider } from "../src/providers/provider.js";
import { ReportWriter } from "../src/reports/reportWriter.js";
import { ReportMetaStore } from "../src/reports/reportMeta.js";

async function pngBase64(): Promise<string> {
  const buf = await sharp({
    create: { width: 16, height: 16, channels: 3, background: { r: 10, g: 20, b: 30 } },
  }).png().toBuffer();
  return buf.toString("base64");
}

function buildPipeline(stateStore: StateStore) {
  return new AnalysisPipeline({
    provider: new MockProvider("extract", JSON.stringify({
      findings: [],
      iocs: [{ id: "i1", type: "hash", value: "4813e753f6f9bfa5c5de0edbb8dd3cc7f1fa51714097d3144d44e5e89dbd33ef", firstSeen: "2026-05-20T09:00:00Z" }],
      mitreTechniques: [],
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: "screenshot extraction note",
      summary: "",
      forensicEvents: [
        { id: "e-from-capture", timestamp: "2026-05-20T09:00:00Z", description: "suspicious process observed in screenshot",
          severity: "High", mitreTechniques: ["T1059"], relatedFindingIds: [], asset: "WIN-01" },
      ],
    })),
    synthesisProvider: new MockProvider("synth", JSON.stringify({
      findings: [
        { id: "f1", severity: "High", title: "Suspicious execution", description: "Execution observed on WIN-01",
          relatedIocs: ["i1"], mitreTechniques: ["T1059"], status: "open", relatedEventIds: ["e-from-capture"] },
      ],
      iocs: [{ id: "i1", type: "hash", value: "4813e753f6f9bfa5c5de0edbb8dd3cc7f1fa51714097d3144d44e5e89dbd33ef", firstSeen: "2026-05-20T09:00:00Z" }],
      mitreTechniques: [{ id: "T1059", name: "Command and Scripting Interpreter" }],
      attackerPath: "Initial execution on WIN-01",
      summary: "Execution was observed on WIN-01.",
      forensicEvents: [],
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: "",
    })),
    stateStore,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
}

// Track temp cases roots so each run cleans up after itself (issue #182 AC: "Cleans up
// temporary cases root after running") instead of leaving dfir-full-pipeline-* dirs behind.
const tempRoots: string[] = [];

beforeEach(async () => {
  _resetDedupCache();
});

afterEach(async () => {
  // Best-effort: on Windows the sync client/indexer can still hold a handle inside the tree here,
  // and rm() then throws ENOTEMPTY from the afterEach — failing a test that actually passed. That
  // teardown race is the oldest symptom in issue #173. Nothing is leaked by tolerating it: these
  // roots live under the per-run temp root that tests/setup/tempRoot.ts removes when the run ends.
  await Promise.all(
    tempRoots.splice(0).map((dir) => rm(dir, { recursive: true, force: true }).catch(() => {})),
  );
});

async function freshFullPipelineApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-full-pipeline-"));
  tempRoots.push(root);
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const reportMetaStore = new ReportMetaStore(store);
  const reportWriter = new ReportWriter(store, stateStore, { reportMeta: reportMetaStore });

  const mockEnrichProvider = {
    name: "MockTI",
    scope: "external" as const,
    supports: () => true,
    lookup: async () => ({ source: "MockTI", verdict: "malicious" as const, score: "10/10" }),
  };

  const fullApp = createApp(store, {
    pipeline: buildPipeline(stateStore),
    stateStore,
    reportWriter,
    enrichmentProviders: [mockEnrichProvider],
    enrichDelayMs: 0,
    autoSynthesize: true,
    autoSynthesizeDebounceMs: 10,
    windowSize: 1,
  });

  return { app: fullApp, store, stateStore, root };
}

// Integration test for issue #182: exercise the complete DFIR-Companion analysis pipeline
// end-to-end (capture → artifact import → synthesis → enrichment → report → encrypted-archive restore).
// AI and enrichment are fully mocked so the test runs offline and deterministically.
describe("full-pipeline integration (capture → import → synthesis → report → encrypted-archive restore)", () => {
  it("runs the complete lifecycle end-to-end with mocked AI and enrichment", async () => {
    const { app, store, stateStore } = await freshFullPipelineApp();
    // Note: this test derives the encrypted-archive password key via scryptSync twice
    // (once on export, once on import) — a CPU-bound blocking call. Under full-suite
    // parallel load (other test files also hammer scryptSync concurrently), that can push
    // this already test-heavy end-to-end run past Vitest's default 5000ms timeout, so it
    // gets a longer one below.

    // 1. Create case
    const create = await request(app).post("/cases").send({
      caseId: "pipeline-1",
      name: "Full Pipeline Test",
      investigator: "integration-test",
      aiProvider: "mock",
    });
    expect(create.status).toBe(201);

    // 2. Turn AI on so capture + synthesis run
    await request(app).post("/cases/pipeline-1/ai-control").send({ enabled: true });

    // 3. Capture a screenshot
    const capture = await request(app).post("/captures").send({
      caseId: "pipeline-1",
      timestamp: "2026-05-20T09:00:00.000Z",
      url: "https://velociraptor.local/hunts",
      tabTitle: "Suspicious Hunt Results",
      triggerType: "navigation",
      imageBase64: await pngBase64(),
    });
    expect(capture.status).toBe(201);
    const screenshotFile = capture.body.screenshotFile as string;

    // Wait for extraction + auto-synthesis to populate state
    let state = await stateStore.load("pipeline-1");
    for (let i = 0; i < 60 && state.findings.length === 0; i++) {
      await new Promise((r) => setTimeout(r, 25));
      state = await stateStore.load("pipeline-1");
    }
    expect(state.forensicTimeline.length).toBeGreaterThanOrEqual(1);
    expect(state.findings.length).toBe(1);
    expect(state.findings[0].title).toBe("Suspicious execution");

    // 4. Import a deterministic artifact (THOR JSON) — no extra AI needed, verdict-first mapping
    const thorJsonl = [
      JSON.stringify({
        time: "2026-05-20T10:00:00Z",
        hostname: "WIN-01",
        level: "Alert",
        module: "Filescan",
        message: "Malware file found",
        file: "C:\\Tools\\mimikatz.exe",
        modified: "2026-05-20T10:00:00Z",
        reason_1: "YARA Powerkatz",
        sha256: "4813e753f6f9bfa5c5de0edbb8dd3cc7f1fa51714097d3144d44e5e89dbd33ef",
      }),
    ].join("\n") + "\n";

    const imp = await request(app)
      .post("/cases/pipeline-1/import")
      .send({ filename: "WIN01_thor.json", text: thorJsonl, minSeverity: "low" });
    expect(imp.status).toBe(202);
    expect(imp.body.kind).toBe("thor");

    // Wait for THOR import to land and re-synthesis to run
    state = await stateStore.load("pipeline-1");
    for (let i = 0; i < 80 && state.forensicTimeline.length < 2; i++) {
      await new Promise((r) => setTimeout(r, 25));
      state = await stateStore.load("pipeline-1");
    }
    expect(state.forensicTimeline.some((e) => e.description.includes("mimikatz"))).toBe(true);
    expect(state.iocs.some((i) => i.value.includes("mimikatz.exe"))).toBe(true);

    // 5. Enrich IOCs with the mocked external provider
    await request(app).post("/cases/pipeline-1/enrich-control").send({ providers: ["MockTI"] });
    const enrich = await request(app).post("/cases/pipeline-1/enrich").send({});
    expect(enrich.status).toBe(202);

    state = await stateStore.load("pipeline-1");
    for (let i = 0; i < 40 && !state.iocs.some((i) => i.enrichments); i++) {
      await new Promise((r) => setTimeout(r, 25));
      state = await stateStore.load("pipeline-1");
    }
    const enrichedIoc = state.iocs.find((i) => i.enrichments?.some((e) => e.source === "MockTI"));
    expect(enrichedIoc).toBeDefined();
    expect(enrichedIoc!.enrichments).toEqual([
      expect.objectContaining({ source: "MockTI", verdict: "malicious", score: "10/10" }),
    ]);

    // 6. Generate the report
    const report = await request(app).post("/cases/pipeline-1/report");
    expect(report.status).toBe(200);
    expect(report.body.markdown).toMatch(/report\.md$/);
    expect(report.body.html).toMatch(/report\.html$/);

    const md = await readFile(report.body.markdown, "utf8");
    expect(md).toContain("Suspicious execution");
    expect(md).toContain("WIN-01");

    // 7. Export the whole case as a password-encrypted archive
    const exportRes = await request(app)
      .post("/cases/pipeline-1/export/encrypted")
      .send({ password: "correct horse battery staple" })
      .buffer()
      .parse((r, cb) => {
        const chunks: Buffer[] = [];
        r.on("data", (c: Buffer) => chunks.push(c));
        r.on("end", () => cb(null, Buffer.concat(chunks)));
      });
    expect(exportRes.status).toBe(200);
    expect(exportRes.headers["content-disposition"]).toContain('attachment; filename="pipeline-1 - Full Pipeline Test.dfircase"');
    const archiveBase64 = (exportRes.body as Buffer).toString("base64");

    // 8. Restore the archive into a new case
    const restore = await request(app)
      .post("/cases/import/encrypted")
      .send({ data: archiveBase64, password: "correct horse battery staple", targetCaseId: "pipeline-1-restored" });
    expect(restore.status).toBe(201);
    expect(restore.body.caseId).toBe("pipeline-1-restored");
    expect(restore.body.counts.forensicEvents).toBeGreaterThanOrEqual(2);
    expect(restore.body.counts.findings).toBeGreaterThanOrEqual(1);
    expect(restore.body.counts.iocs).toBeGreaterThanOrEqual(1);

    // 9. Verify restored case matches key elements
    const restored = await request(app).get("/cases/pipeline-1-restored/state");
    expect(restored.status).toBe(200);
    expect(restored.body.findings.some((f: { title: string }) => f.title === "Suspicious execution")).toBe(true);
    expect(restored.body.iocs.some((i: { value: string }) => i.value.includes("mimikatz.exe"))).toBe(true);

    // 10. Evidence files are preserved — in BOTH the original AND the restored case. This is the
    // whole point of the encrypted archive replacing the old JSON-only snapshot: screenshots and
    // raw imports now travel with the export, not just references to them.
    expect(screenshotFile).toMatch(/\.webp$/);
    const evidence = await request(app).get(`/cases/pipeline-1/evidence/${screenshotFile}`);
    expect(evidence.status).toBe(200);
    expect(evidence.headers["content-type"]).toContain("image/");

    const restoredEvidence = await request(app).get(`/cases/pipeline-1-restored/evidence/${screenshotFile}`);
    expect(restoredEvidence.status).toBe(200);
    expect(restoredEvidence.headers["content-type"]).toContain("image/");

    const importFiles = (await readFile(store.importsLogPath("pipeline-1"), "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    expect(importFiles.length).toBeGreaterThanOrEqual(1);

    const restoredImportFiles = (await readFile(store.importsLogPath("pipeline-1-restored"), "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    expect(restoredImportFiles.length).toBeGreaterThanOrEqual(1);
  }, 20_000);

  it("does not leave AI or enrichment provider artifacts behind when AI is off", async () => {
    const { app, stateStore } = await freshFullPipelineApp();

    await request(app).post("/cases").send({ caseId: "pipeline-ai-off", name: "AI Off", investigator: "test", aiProvider: "mock" });
    // AI stays off

    const capture = await request(app).post("/captures").send({
      caseId: "pipeline-ai-off",
      timestamp: "2026-05-20T09:00:00.000Z",
      url: "u",
      tabTitle: "t",
      triggerType: "navigation",
      imageBase64: await pngBase64(),
    });
    expect(capture.status).toBe(201);

    await new Promise((r) => setTimeout(r, 200));
    const state = await stateStore.load("pipeline-ai-off");
    expect(state.forensicTimeline).toHaveLength(0);
    expect(state.findings).toHaveLength(0);
  });
});
