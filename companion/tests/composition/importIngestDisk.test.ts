import { describe, expect, it } from "vitest";
import { mkdtemp, open, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { createImportIngest, type ImportIngestDeps } from "../../src/composition/importIngest.js";
import { ImportLock } from "../../src/analysis/importLock.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { buildRuntimePipeline } from "../../src/server.js";

// #2336 — the drop folder's streamed import: the stored copy is written from the handle the sweep
// opened (no second open of the path), and the file is imported by streaming from that copy, with
// its disclosure on the import-meta record and returned for drop-log.txt.

const record = (i: number, eventName: string) => ({
  eventVersion: "1.09",
  userIdentity: { type: "IAMUser", arn: `arn:aws:iam::123456789012:user/ops${i}`, userName: `ops${i}` },
  eventTime: "2026-10-01T10:00:00Z",
  eventSource: eventName === "StopLogging" ? "cloudtrail.amazonaws.com" : "iam.amazonaws.com",
  eventName,
  awsRegion: "us-east-1",
  sourceIPAddress: "198.51.100.7",
  eventID: `00000000-0000-4000-b000-${String(i).padStart(12, "0")}`,
  eventType: "AwsApiCall",
});

describe("ingestDiskFile — the drop folder's streamed import (#2336)", () => {
  it("stores a gzip CloudTrail object from the handle and imports it by streaming", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-disk-ingest-"));
    const store = new CaseStore(join(root, "cases"));
    await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const stateStore = new StateStore(store);
    const importMetaStore = new ImportMetaStore(store);
    const pipeline = buildRuntimePipeline({
      stateStore,
      store,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
    const ingest = createImportIngest({
      store,
      options: { pipeline, stateStore, importMetaStore },
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

    const gz = gzipSync(JSON.stringify({ Records: [record(1, "StopLogging"), record(2, "ListUsers")] }));
    const src = join(root, "ct.json.gz");
    await writeFile(src, gz);
    const handle = await open(src, "r");
    let r;
    try {
      r = await ingest.ingestDiskFile("c1", "aws", handle, "ct.json.gz", undefined);
    } finally {
      await handle.close();
    }

    expect(r.storedName).toMatch(/^\d{4}_ct\.json\.gz$/);
    expect((await readFile(join(store.importsDir("c1"), r.storedName))).equals(gz)).toBe(true);
    expect(r.disclosure.join(" ")).toContain("gzip, decompressed on read");
    const state = await stateStore.load("c1");
    expect(state.forensicTimeline.some((e) => /StopLogging/.test(e.description))).toBe(true);
    const meta = await importMetaStore.load("c1");
    expect(meta.lastImportFile).toBe(r.storedName);
    expect(meta.streamDisclosure?.join(" ")).toContain("gzip, decompressed on read");
  });
});
