import { describe, it, expect } from "vitest";
import { mkdtemp, mkdir, writeFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { DropStatusStore } from "../../src/analysis/dropStatus.js";
import { detectImportWithCustom } from "../../src/analysis/importDetect.js";
import { createDropFolder, dropDirOf } from "../../src/composition/dropFolder.js";

// #1308. PR #1302 taught the HTTP import routes to name WHY a capa report was refused (a
// dynamic-flavor report is real upstream but unsupported here), instead of the generic "could not
// detect" message. The drop-folder sweep shares the same detector and the same `unknown` outcome,
// but kept its own generic reason — so the analyst who drops that report into the case folder gets
// "unrecognized file type" in the drop-status record, the notification and drop-log.txt, while the
// same file through the Import button gets the named reason. This test pins the drop path to the
// same hint: the fixture is the #1302 test's dynamic-flavor report, driven through the REAL
// `detectImportWithCustom` (not a stub) and the real `scanCaseDrops`.

const CAPA_DYNAMIC_REPORT = JSON.stringify({
  meta: {
    timestamp: "2026-08-08T20:30:07.562894",
    version: "9.4.0",
    argv: ["-j", "sample.dll"],
    sample: {
      md5: "7a450304b58917290f54ffbdccb095b6",
      sha1: "db054d79d4d913671732d9ff696dca69f911601a",
      sha256: "afed46612dce2c6fa48d95192426366dcc0a4517f4b56240f0c8e39a5104748a",
      path: "samples/sample.dll",
    },
    flavor: "dynamic",
    analysis: { format: "dotnet", arch: "amd64", os: "any", extractor: "DnfileFeatureExtractor" },
  },
  rules: {},
});

const NAMED_REASON = 'capa report flavor "dynamic" is not yet supported (only "static" reports are parsed)';

function harness(store: CaseStore, dropStatusStore: DropStatusStore) {
  const refuse = (): never => {
    throw new Error("not expected to be reached for an unrecognized text file");
  };
  return createDropFolder({
    store,
    options: { dropStatusStore },
    hasAiProvider: () => false,
    getControl: refuse,
    recordImportFailure: refuse,
    dispatchNotify: () => {},
    resolveImportKind: (filename, text) => detectImportWithCustom(filename, text, new Map(), "builtin-first"),
    ingestStreamed: refuse,
    ingestMacLoginItemBinary: refuse,
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
  const root = await mkdtemp(join(tmpdir(), "dfir-drop-capa-flavor-"));
  const store = new CaseStore(root);
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const dropDir = dropDirOf(store, "c1");
  await mkdir(dropDir, { recursive: true });
  await writeFile(join(dropDir, "capa-dynamic.json"), CAPA_DYNAMIC_REPORT, "utf8");
  return { store, dropDir, dropStatusStore: new DropStatusStore(store) };
}

describe("drop folder names the capa flavor when it refuses a non-static report (#1308)", () => {
  it("records the same named reason the import routes give, not the generic one", async () => {
    const { store, dropDir, dropStatusStore } = await seed();
    const drops = harness(store, dropStatusStore);

    // A file is ready only once a second sweep sees it unchanged (one poll interval of stability).
    await drops.scanCaseDrops("c1");
    await drops.scanCaseDrops("c1");

    const status = await dropStatusStore.load("c1");
    expect(status.imported).toEqual([]);
    expect(status.failed).toEqual([{ relpath: "capa-dynamic.json", reason: NAMED_REASON }]);
    // Still refused: the file lands in _failed/ exactly as before — only the reason changed.
    expect((await stat(join(dropDir, "_failed", "capa-dynamic.json"))).isFile()).toBe(true);
  });
});
