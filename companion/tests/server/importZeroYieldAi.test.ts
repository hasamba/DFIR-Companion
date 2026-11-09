import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { ForensicGateControlStore } from "../../src/analysis/forensicGateControl.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../src/providers/provider.js";
import { pollFor, POLL_TIMEOUT_MS } from "../helpers/poll.js";

// #2460: a 14-row Sysmon CSV went through AI extraction, the provider kept nothing, and the banner
// said only "no new events" — the zero-yield warning fires from 500 lines up. Import-meta now carries
// the extraction's own count (rows read, events kept), so the dashboard can warn on ANY size without
// mistaking a re-import (every event already present, addedCount 0) for a failed extraction.

const ISO = "2026-05-02T10:00:00Z";
const CSV =
  "UtcTime,Computer,EventID,Image,CommandLine\n" +
  Array.from({ length: 14 }, (_, i) => `${ISO},WS1,1,C:\\Windows\\System32\\cmd.exe,cmd /c whoami ${i}`).join(
    "\n",
  ) +
  "\n";

/** Answers every call with the given events and nothing else. */
class FixedProvider implements AIProvider {
  readonly name = "text";
  readonly model = "mock-model";
  constructor(private readonly events: unknown[]) {}
  async analyze(_req: AnalyzeRequest): Promise<AnalyzeResult> {
    return {
      rawText: JSON.stringify({
        findings: [],
        iocs: [],
        mitreTechniques: [],
        threadsOpened: [],
        threadsClosed: [],
        timelineNote: "",
        summary: "",
        attackerPath: "",
        forensicEvents: this.events,
      }),
    };
  }
}

const HIGH_EVENT = {
  id: "e1",
  timestamp: ISO,
  description: "cmd.exe ran whoami on WS1",
  severity: "High",
  mitreTechniques: [],
  relatedFindingIds: [],
};

async function makeApp(provider: AIProvider) {
  const root = await mkdtemp(join(tmpdir(), "dfir-2460-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined,
    synthesisProvider: provider,
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, {
    pipeline,
    stateStore,
    superTimelineStore: new SuperTimelineStore(store),
    importMetaStore: new ImportMetaStore(store),
    forensicGateControlStore: new ForensicGateControlStore(store),
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
  await request(app).post("/cases/c1/ai-control").send({ enabled: true });
  return app;
}

interface Meta {
  lastImportFile: string;
  addedCount: number;
  path: string;
  aiExtraction?: { rowsIn: number; kept: number };
}

async function importAndWait(
  app: ReturnType<typeof createApp>,
  route: "import" | "import-csv",
  filename: string,
): Promise<Meta> {
  const body = route === "import-csv" ? { csv: CSV, filename } : { text: CSV, filename };
  const res = await request(app).post(`/cases/c1/${route}`).send(body);
  expect(res.status, JSON.stringify(res.body)).toBe(202);
  const file = res.body.file as string;
  return pollFor(`import-meta for ${file}`, async () => {
    const meta = (await request(app).get("/cases/c1/import-meta")).body as Meta;
    return meta.lastImportFile === file ? meta : undefined;
  });
}

describe("AI-triage import records what the extraction kept (#2460)", () => {
  for (const route of ["import-csv", "import"] as const) {
    it(
      `POST /cases/:id/${route}: a 14-row CSV the AI keeps nothing from records kept 0 of 14`,
      async () => {
        const app = await makeApp(new FixedProvider([]));
        const meta = await importAndWait(app, route, "sysmon.csv");
        expect(meta.path).toBe("ai");
        expect(meta.addedCount).toBe(0);
        expect(meta.aiExtraction).toEqual({ rowsIn: 14, kept: 0 });
      },
      POLL_TIMEOUT_MS * 2,
    );

    it(
      `POST /cases/:id/${route}: a re-import whose events are all present keeps > 0 while adding 0`,
      async () => {
        const app = await makeApp(new FixedProvider([HIGH_EVENT]));
        const first = await importAndWait(app, route, "sysmon.csv");
        expect(first.addedCount).toBeGreaterThan(0);
        const again = await importAndWait(app, route, "sysmon-again.csv");
        expect(again.addedCount).toBe(0);
        expect(again.aiExtraction?.rowsIn).toBe(14);
        expect(again.aiExtraction?.kept).toBeGreaterThan(0);
      },
      POLL_TIMEOUT_MS * 2,
    );
  }
});
