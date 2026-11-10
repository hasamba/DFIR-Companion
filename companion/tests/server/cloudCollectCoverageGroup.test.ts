import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { CloudRecordStore } from "../../src/analysis/cloudRecordStore.js";
import { CloudCoverageStore } from "../../src/analysis/cloudCoverage.js";
import { StateLock } from "../../src/analysis/stateLock.js";
import { ImportLock } from "../../src/analysis/importLock.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import type { AppOptions } from "../../src/composition/appOptions.js";
import type { RouteContext } from "../../src/routes/context.js";
import { caseCollectImporter } from "../../src/routes/cloudCollectImporter.js";
import { trailRecord } from "../helpers/cloudCollectFakes.js";

// #2538 — the PRODUCTION page importer (not the test fake) tells the pipeline which collection a
// page belongs to, so its coverage folds into one `collection:<id>` row.

let root: string;
let coverageStore: CloudCoverageStore;
let ctx: RouteContext;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "collect-coverage-group-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(cases);
  coverageStore = new CloudCoverageStore(cases);
  const lock = new StateLock();
  const pipeline = new AnalysisPipeline({
    stateStore,
    superTimelineStore: new SuperTimelineStore(cases),
    cloudRecordStore: new CloudRecordStore(cases),
    cloudCoverageStore: coverageStore,
    stateLock: lock,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const options = { stateStore, pipeline } as unknown as AppOptions;
  ctx = {
    options,
    importLock: new ImportLock(),
    runStateExclusive: <T>(c: string, fn: () => Promise<T>) => lock.runExclusive(c, fn),
    serverLogger: { info: () => {}, warn: () => {}, debug: () => {}, error: () => {} },
  } as unknown as RouteContext;
});
afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

async function page(seq: number, first: number) {
  const path = join(root, `p00000${seq}-ct.json`);
  await writeFile(path, JSON.stringify({ Records: [first, first + 1].map((i) => trailRecord(i)) }));
  return {
    kind: "aws" as const,
    path,
    label: `evidence/cloud/cc-prod/p00000${seq}-ct.json`,
    idPrefix: `ccprodp${seq}`,
    importedAt: "2026-10-02T00:00:00Z",
    collectionId: "cc-prod",
  };
}

describe("caseCollectImporter coverage group (#2538)", () => {
  it("two pages of one collection land as one coverage row keyed collection:<id>", async () => {
    const importer = caseCollectImporter(ctx);
    for (const p of [await page(1, 1), await page(2, 10)])
      await importer.withImportSection("c1", () => importer.importPage("c1", p));
    const records = await coverageStore.load("c1");
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({ uploadId: "collection:cc-prod", recordCount: 4, pages: 2 });
  });
});
