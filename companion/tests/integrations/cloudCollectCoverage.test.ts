import { describe, it, expect } from "vitest";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createCollection, runCollection } from "../../src/integrations/cloudCollect/collectEngine.js";
import type { CollectFs } from "../../src/integrations/cloudCollect/collectFs.js";
import type { CloudCollectSession } from "../../src/integrations/cloudCollect/collectTypes.js";
import { CloudCoverageStore } from "../../src/analysis/cloudCoverage.js";
import {
  fakeSession,
  faultFs,
  kill,
  pipelineImporter,
  tempCase,
  trailRecord,
  type TempCase,
} from "../helpers/cloudCollectFakes.js";

// #2538 — through the real collection engine and pipeline: a live collection's pages fold into one
// Cloud Coverage row per account, keyed `collection:<id>`, and a replayed page never folds twice.

const SOURCES = [{ id: "ct", label: "CloudTrail", streamKind: "aws" as const }];
const WINDOW = { start: "2026-10-01T00:00:00Z", end: "2026-10-02T00:00:00Z" };
let tick = 0;
const now = () => new Date(Date.UTC(2026, 9, 5, 0, 0, tick++)).toISOString();

async function start(t: TempCase, fs: CollectFs, session: CloudCollectSession) {
  await createCollection(
    fs,
    session,
    {
      dir: t.dir,
      collectionId: "cc-test-abc123",
      caseId: "c1",
      accountId: "acct1",
      accountName: "lab",
      provider: "aws",
      sources: ["ct"],
      window: WINDOW,
      filters: {},
      companionVersion: "0.0.0-test",
    },
    now,
  );
}

const run = (
  t: TempCase,
  fs: CollectFs,
  session: CloudCollectSession,
  importer = pipelineImporter(t),
  resume = false,
) => runCollection({ fs, session, importer, sources: SOURCES, now }, t.dir, { resume });

const coverage = (t: TempCase) => new CloudCoverageStore(t.cases).load("c1");

describe("live collection coverage (#2538)", () => {
  it("a 3-page collection is one coverage row, with the pages' records summed", async () => {
    const t = await tempCase();
    const fs = faultFs();
    const session = fakeSession({ pages: 3, perPage: 4 });
    await start(t, fs, session);
    expect((await run(t, fs, session)).status).toBe("complete");
    const records = await coverage(t);
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({
      provider: "aws-cloudtrail",
      uploadId: "collection:cc-test-abc123",
      recordCount: 12,
      pages: 3,
    });
  });

  it("a page whose import landed but was not checkpointed does not fold twice on resume", async () => {
    const t = await tempCase();
    const fs = faultFs();
    const session = fakeSession({ pages: 2, perPage: 4 });
    await start(t, fs, session);
    let stage = "";
    fs.inject(
      "writeFileSync",
      (p) => /checkpoint\.json\.[0-9a-f-]{36}\.tmp$/.test(p) && stage === "import-1",
      kill,
    );
    const importer = pipelineImporter(t);
    const wrapped = {
      ...importer,
      importPage: async (...a: Parameters<typeof importer.importPage>) => {
        await importer.importPage(...a);
        stage = "import-1";
      },
    };
    await expect(run(t, fs, session, wrapped)).rejects.toThrow("simulated kill");
    fs.clear();
    const resumed = pipelineImporter(t);
    await run(t, fs, session, resumed, true);
    expect(resumed.imports).toEqual(["evidence/cloud/cc-test-abc123/p000002-ct.json"]);
    const records = await coverage(t);
    expect(records).toHaveLength(1);
    expect(records[0].recordCount).toBe(8);
    expect(records[0].pages).toBe(2);
  });

  it("importCloudFile sums two pages of one collection into one disclosure (#2546)", async () => {
    const t = await tempCase();
    for (const [seq, first, n] of [
      [1, 1, 3],
      [2, 10, 4],
    ] as const) {
      const path = join(t.root, `p00000${seq}-ct.json`);
      const recs = Array.from({ length: n }, (_, i) => trailRecord(first + i));
      await writeFile(path, JSON.stringify({ Records: recs }));
      await t.pipeline.importCloudFile("c1", "aws", path, {
        label: `evidence/cloud/cc-sum/p00000${seq}-ct.json`,
        idPrefix: `ccsump${seq}`,
        importedAt: "2026-10-03T00:00:00Z",
        coverageGroup: "collection:cc-sum",
      });
    }
    const records = await coverage(t);
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({ recordCount: 7, pages: 2 });
    expect(records[0].streamDisclosure?.records).toBe(7);
    const streamed = (records[0].importDisclosure ?? []).filter((s) => s.startsWith("streamed from disk"));
    expect(streamed).toEqual(["streamed from disk: 7 record(s), json"]);
  });

  it("a manual streamed import with no group is still keyed by its own file (the #2303 path)", async () => {
    const t = await tempCase();
    const path = join(t.root, "manual-ct.json");
    await writeFile(path, JSON.stringify({ Records: [1, 2, 3].map((i) => trailRecord(i)) }));
    await t.pipeline.importCloudFile("c1", "aws", path, {
      label: "manual-ct.json",
      idPrefix: "manualct",
      importedAt: "2026-10-03T00:00:00Z",
    });
    const records = await coverage(t);
    expect(records).toHaveLength(1);
    expect(records[0].uploadId).not.toMatch(/^collection:/);
    expect(records[0].pages).toBeUndefined();
  });
});
