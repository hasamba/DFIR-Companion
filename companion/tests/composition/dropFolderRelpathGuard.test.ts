import { describe, it, expect } from "vitest";
import { mkdtemp, mkdir, writeFile, stat, access } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createDropFolder, dropDirOf } from "../../src/composition/dropFolder.js";

// #919. moveDropFile is the destructive half of the drop-folder contract: it renames the file the
// relpath names into _processed/ or _failed/. Its relpath used to be trusted because the walk could
// only ever produce descendants of drop/ — but POST /cases/:id/drop/run-pending feeds it relpaths
// from state/drop-status.json, and an imported archive restores that file verbatim. The schema now
// drops an escaping relpath at load (dropStatus.test.ts); this is the second layer, at the one
// function that can move a file, so no future writer of the status file can reach a rename.
//
// The guard must run BEFORE the mkdir of the destination's parent: that mkdir used to be the first
// statement, so a traversal relpath created directories outside drop/ before any check ran.

function harness(store: CaseStore) {
  const refuse = (): never => {
    throw new Error("not expected to be called by moveDropFile");
  };
  return createDropFolder({
    store,
    options: {},
    hasAiProvider: () => false,
    getControl: refuse,
    recordImportFailure: refuse,
    dispatchNotify: refuse,
    resolveImportKind: refuse,
    ingestStreamed: refuse,
    liveToolConfigs: () => new Map(),
    resolveToolForExt: () => null,
    rawExtClaimed: () => false,
    runDropToolAndIngest: refuse,
    indexCaptureText: refuse,
    captureBuffers: new Map(),
    flush: refuse,
  });
}

async function seed() {
  const root = await mkdtemp(join(tmpdir(), "dfir-drop-relpath-"));
  const store = new CaseStore(root);
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const dropDir = dropDirOf(store, "c1");
  await mkdir(dropDir, { recursive: true });
  // A file OUTSIDE the drop folder — beside the case directory, inside a directory of its own, so
  // that the would-be destination `_processed/../../planted/...` has a parent (`<caseDir>/planted`)
  // that does NOT exist unless the move created it. With the file directly beside the case dir the
  // parent collapses to the case dir itself, which always exists, and the mkdir assertion below
  // would prove nothing.
  const outside = join(dirname(dirname(dropDir)), "planted", "outside-secret.txt");
  await mkdir(dirname(outside), { recursive: true });
  await writeFile(outside, "HOST-FILE", "utf8");
  const relpath = join("..", "..", "planted", "outside-secret.txt");
  return { store, dropDir, outside, relpath };
}

describe("moveDropFile refuses a relpath that escapes the drop folder (#919)", () => {
  it("rejects the move, and leaves the outside file and the filesystem untouched", async () => {
    const { store, dropDir, outside, relpath } = await seed();
    const drops = harness(store);

    await expect(drops.moveDropFile(dropDir, relpath, true)).rejects.toThrow(/outside the drop folder/);

    // The outside file is still exactly where it was.
    expect((await stat(outside)).isFile()).toBe(true);
    // And nothing was created on the way to the would-be destination: the old code ran
    // mkdir(dirname(dest)) before any guard, which would have planted `_processed/../..`-shaped
    // directories outside drop/. The would-be dest's parent must not exist.
    const wouldBeDest = join(dropDir, "_processed", relpath);
    await expect(access(dirname(wouldBeDest))).rejects.toThrow();
  });

  it("refuses on the failure path too — a tool that rejects the file must not move it either", async () => {
    const { store, dropDir, outside, relpath } = await seed();
    const drops = harness(store);
    await expect(drops.moveDropFile(dropDir, relpath, false)).rejects.toThrow(/outside the drop folder/);
    expect((await stat(outside)).isFile()).toBe(true);
  });

  it("still moves an ordinary dropped file into _processed/", async () => {
    const { store, dropDir } = await seed();
    const drops = harness(store);
    await mkdir(join(dropDir, "triage"), { recursive: true });
    await writeFile(join(dropDir, "triage", "evidence.json"), "[]", "utf8");

    await drops.moveDropFile(dropDir, join("triage", "evidence.json"), true);

    expect((await stat(join(dropDir, "_processed", "triage", "evidence.json"))).isFile()).toBe(true);
    await expect(access(join(dropDir, "triage", "evidence.json"))).rejects.toThrow();
  });
});
