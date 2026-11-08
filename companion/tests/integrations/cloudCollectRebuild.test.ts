import { describe, it, expect } from "vitest";
import { rm, writeFile } from "node:fs/promises";
import {
  createCollection,
  markCollectionStopped,
  runCollection,
} from "../../src/integrations/cloudCollect/collectEngine.js";
import { collectionPaths } from "../../src/integrations/cloudCollect/collectManifest.js";
import {
  readCheckpoint,
  REBUILT_CHECKPOINT_NOTE,
} from "../../src/integrations/cloudCollect/collectCheckpoint.js";
import { readCollection } from "../../src/integrations/cloudCollect/collectStore.js";
import { nodeCollectFs, type CollectFs } from "../../src/integrations/cloudCollect/collectFs.js";
import type { CloudCollectSession } from "../../src/integrations/cloudCollect/collectTypes.js";
import {
  fakeSession,
  faultFs,
  pipelineImporter,
  tempCase,
  type TempCase,
} from "../helpers/cloudCollectFakes.js";

// #2402: a missing or unreadable checkpoint used to hide a collection from the panel and make Resume
// throw, although the manifest — the collection's source of truth — still held everything.

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

describe("a collection whose checkpoint is gone (#2402)", () => {
  it("is still listed, as interrupted, with a note saying it was rebuilt", async () => {
    const t = await tempCase();
    const fs = faultFs();
    const session = fakeSession({ pages: 2 });
    await start(t, fs, session);
    await rm(collectionPaths(t.dir).checkpoint);
    // (listCollections only walks real collection ids; the fixture's id is not one.)
    const summary = await readCollection(nodeCollectFs, t.dir);
    expect(summary?.checkpoint).toMatchObject({
      collectionId: "cc-test-abc123",
      caseId: "c1",
      accountId: "acct1",
      status: "interrupted",
      error: REBUILT_CHECKPOINT_NOTE,
    });
    expect(await readCheckpoint(nodeCollectFs, collectionPaths(t.dir))).toBeNull(); // a list writes nothing
  });

  it("rebuilds a checkpoint that is valid JSON but missing required fields", async () => {
    const t = await tempCase();
    const fs = faultFs();
    await start(t, fs, fakeSession({ pages: 1 }));
    await writeFile(
      collectionPaths(t.dir).checkpoint,
      JSON.stringify({
        version: 1,
        collectionId: "cc-test-abc123",
        caseId: "c1",
        subWindows: [],
        imported: [],
      }),
    );
    const summary = await readCollection(nodeCollectFs, t.dir);
    expect(summary?.checkpoint.status).toBe("interrupted");
    expect(summary?.checkpoint.window).toEqual(WINDOW);
  });

  it("stays hidden when the manifest header is unusable too", async () => {
    const t = await tempCase();
    const fs = faultFs();
    await start(t, fs, fakeSession({ pages: 1 }));
    await rm(collectionPaths(t.dir).checkpoint);
    await writeFile(collectionPaths(t.dir).manifest, `${JSON.stringify({ type: "header" })}\n`);
    expect(await readCollection(nodeCollectFs, t.dir)).toBeNull();
  });

  it("resumes against the CASE, and never imports a page already in the case again", async () => {
    const t = await tempCase();
    const fs = faultFs();
    const session = fakeSession({ pages: 2 });
    await start(t, fs, session);
    const first = await run(t, fs, session);
    expect(first.status).toBe("complete");
    await rm(collectionPaths(t.dir).checkpoint);
    const importer = pipelineImporter(t);
    const caseIds: string[] = [];
    const landed = importer.landed;
    importer.landed = async (caseId, label) => {
      caseIds.push(caseId);
      return landed(caseId, label);
    };
    const resumed = await run(t, fs, session, importer, true);
    expect(resumed.caseId).toBe("c1");
    expect(importer.imports).toEqual([]);
    expect(caseIds.length).toBeGreaterThan(0);
    expect(new Set(caseIds)).toEqual(new Set(["c1"]));
    expect(resumed.imported).toHaveLength(2);
  });
});

describe('"failed" means nothing was collected (#2402)', () => {
  it("a run stopped by an error after pages were saved is partial, not failed", async () => {
    const t = await tempCase();
    const fs = faultFs();
    const session = fakeSession({ pages: 2 });
    await start(t, fs, session);
    await run(t, fs, session);
    await markCollectionStopped(nodeCollectFs, t.dir, "failed", "import blew up", now);
    const cp = await readCheckpoint(nodeCollectFs, collectionPaths(t.dir));
    expect(cp).toMatchObject({ status: "partial", error: "import blew up" });
  });

  it("a run stopped by an error before any page was saved stays failed", async () => {
    const t = await tempCase();
    const fs = faultFs();
    await start(t, fs, fakeSession({ pages: 2 }));
    await markCollectionStopped(nodeCollectFs, t.dir, "failed", "AccessDenied", now);
    expect((await readCheckpoint(nodeCollectFs, collectionPaths(t.dir)))?.status).toBe("failed");
  });
});
