import { describe, it, expect, vi } from "vitest";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { DropStatusStore } from "../../src/analysis/dropStatus.js";
import { detectImportWithCustom } from "../../src/analysis/importDetect.js";
import { createDropFolder, dropDirOf } from "../../src/composition/dropFolder.js";

// #1496: a drop subfolder named asset=<HOST> declares the host its files came from. The sweep
// hands that host to ingestStreamed for a text file; a raw file (EVTX → external tool) derives it
// again from the relpath inside runDropToolAndIngest, so both paths agree and "Run pending"
// replays it. An ordinary subfolder, or an invalid name, declares nothing.

const BARE = JSON.stringify([
  {
    EventTime: "2025-12-05T03:02:24Z",
    Detection: "x",
    Severity: "high",
    "Rule Group": "Sigma",
    Computer: "WIN-UK1GV882OK6",
    Channel: "Security",
    EventID: 4624,
    SystemData: { Computer: "WIN-UK1GV882OK6" },
    EventData: {},
  },
]);

async function seed(files: Record<string, string>) {
  const root = await mkdtemp(join(tmpdir(), "dfir-drop-asset-"));
  const store = new CaseStore(root);
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const dropDir = dropDirOf(store, "c1");
  for (const [rel, text] of Object.entries(files)) {
    await mkdir(join(dropDir, ...rel.split("/").slice(0, -1)), { recursive: true });
    await writeFile(join(dropDir, ...rel.split("/")), text, "utf8");
  }
  const ingestStreamed = vi.fn(
    async (..._args: [string, string, string, string, undefined?, undefined?, string?]) => ({
      storedName: "s",
      addedEvents: 1,
      addedIocs: 0,
      analyzed: true,
    }),
  );
  const refuse = (): never => {
    throw new Error("not expected");
  };
  const drops = createDropFolder({
    store,
    options: { dropStatusStore: new DropStatusStore(store) },
    hasAiProvider: () => false,
    getControl: refuse,
    recordImportFailure: refuse,
    dispatchNotify: () => {},
    resolveImportKind: (filename, text) => detectImportWithCustom(filename, text, new Map(), "builtin-first"),
    ingestStreamed,
    ingestMacLoginItemBinary: refuse,
    liveToolConfigs: () => new Map(),
    resolveToolForExt: () => null,
    rawExtClaimed: () => false,
    runDropToolAndIngest: refuse,
    indexCaptureText: refuse,
    captureBuffers: new Map(),
    flush: refuse,
  });
  await drops.scanCaseDrops("c1");
  await drops.scanCaseDrops("c1");
  return ingestStreamed;
}

describe("drop folder — asset=<HOST> subfolder (#1496)", () => {
  it("hands the declared host to the import for a file under asset=HOST/", async () => {
    const ingest = await seed({ "asset=DESKTOP-16OJFO6/chainsaw.json": BARE });
    expect(ingest).toHaveBeenCalledOnce();
    expect(ingest.mock.calls[0][6]).toBe("DESKTOP-16OJFO6");
  });

  it("declares nothing for an ordinary subfolder or an invalid name", async () => {
    const ingest = await seed({ "tools/chainsaw.json": BARE, "asset=-bad/chainsaw.json": BARE });
    expect(ingest).toHaveBeenCalledTimes(2);
    for (const call of ingest.mock.calls) expect(call[6]).toBeUndefined();
  });
});
