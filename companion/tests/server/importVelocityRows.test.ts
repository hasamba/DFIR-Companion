import { describe, it, expect } from "vitest";
import { mkdtemp, open, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import type { Express } from "express";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { ImportLock } from "../../src/analysis/importLock.js";
import { createImportIngest, type ImportIngestDeps } from "../../src/composition/importIngest.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { pollFor } from "../helpers/poll.js";

// #2790: the main Import button, Import-from-path and the drop folder recorded `rows: 0` on their
// imports.jsonl line and never updated it, so Case Statistics' import velocity showed 0 rows for
// every import made that way. Each now records the rows the importer read.

const thorLine = (i: number): string =>
  JSON.stringify({
    time: `2026-06-13T21:18:${String(i).padStart(2, "0")}Z`,
    hostname: "WIN11",
    level: "Alert",
    module: "Filescan",
    message: "Malware file found",
    file: `C:\\Tools\\tool${i}.exe`,
  });
const THOR_JSONL = [0, 1, 2].map(thorLine).join("\n") + "\n";

async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-velocity-rows-"));
  const store = new CaseStore(join(root, "cases"));
  const stateStore = new StateStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined,
    synthesisProvider: undefined,
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, { pipeline, stateStore, importMetaStore: new ImportMetaStore(store) });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, root, store, stateStore, pipeline };
}

async function velocityRows(app: Express): Promise<number> {
  const res = await request(app).get("/cases/c1/stats");
  expect(res.status).toBe(200);
  const days = res.body.importVelocity as Array<{ imports: number; rows: number }>;
  return days.reduce((n, d) => n + d.rows, 0);
}

describe("import velocity counts the rows an import read (#2790)", () => {
  it("the main Import button", async () => {
    const { app } = await makeApp();
    const res = await request(app)
      .post("/cases/c1/import")
      .send({ filename: "thor.jsonl", text: THOR_JSONL });
    expect(res.status, JSON.stringify(res.body)).toBe(202);
    expect(res.body.kind).toBe("thor");
    const rows = await pollFor("a row count on the import", async () => {
      const n = await velocityRows(app);
      return n > 0 ? n : undefined;
    });
    expect(rows).toBe(3);
  });

  it("Import-from-path", async () => {
    const { app, root } = await makeApp();
    const path = join(root, "thor.jsonl");
    await writeFile(path, THOR_JSONL);
    const res = await request(app).post("/cases/c1/import-file").send({ path });
    expect(res.status, JSON.stringify(res.body)).toBe(202);
    const rows = await pollFor("a row count on the import", async () => {
      const n = await velocityRows(app);
      return n > 0 ? n : undefined;
    });
    expect(rows).toBe(3);
  });

  function ingestFor(
    store: CaseStore,
    stateStore: StateStore,
    pipeline: ReturnType<typeof buildRuntimePipeline>,
  ) {
    return createImportIngest({
      store,
      options: { pipeline, stateStore, importMetaStore: new ImportMetaStore(store) },
      runStateExclusive: async (_caseId: string, fn: () => Promise<unknown>) => fn(),
      importLock: new ImportLock(),
      recordImporterRun: () => {},
      redactErr: (err: unknown) => String((err as Error).message ?? err),
      autoTagImported: async () => {},
      getControl: async () => ({ enabled: true }),
      applyWhitelistToCase: async () => ({ matched: 0, added: 0 }),
      applyNsrlToCase: async () => ({ matchedIocs: 0, matchedEvents: 0, added: 0 }),
      applyDeobfuscationToCase: async () => ({ deobfuscated: 0, newIocs: 0, reanalyzed: 0 }),
      resynthesizeInBackground: () => {},
    } as unknown as ImportIngestDeps);
  }

  it("the drop folder, read into memory (ingestStreamed)", async () => {
    const { app, store, stateStore, pipeline } = await makeApp();
    const ingest = ingestFor(store, stateStore, pipeline);
    await ingest.ingestStreamed("c1", "thor", THOR_JSONL, "thor.jsonl");
    expect(await velocityRows(app)).toBe(3);
  });

  it("the drop folder, streamed from disk (ingestDiskFile)", async () => {
    const { app, root, store, stateStore, pipeline } = await makeApp();
    const ingest = ingestFor(store, stateStore, pipeline);
    const records = [0, 1].map((i) => ({
      eventVersion: "1.09",
      userIdentity: { type: "IAMUser", arn: `arn:aws:iam::123456789012:user/ops${i}`, userName: `ops${i}` },
      eventTime: "2026-10-01T10:00:00Z",
      eventSource: "cloudtrail.amazonaws.com",
      eventName: "StopLogging",
      awsRegion: "us-east-1",
      sourceIPAddress: "198.51.100.7",
      eventID: `00000000-0000-4000-b000-${String(i).padStart(12, "0")}`,
      eventType: "AwsApiCall",
    }));
    const src = join(root, "ct.json");
    await writeFile(src, JSON.stringify({ Records: records }));
    const handle = await open(src, "r");
    try {
      await ingest.ingestDiskFile("c1", "aws", handle, "ct.json", undefined);
    } finally {
      await handle.close();
    }
    expect(await velocityRows(app)).toBe(2);
  });
});
