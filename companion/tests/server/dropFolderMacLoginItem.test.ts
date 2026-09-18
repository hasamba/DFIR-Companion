import { describe, it, expect } from "vitest";
import { mkdtemp, mkdir, writeFile, readdir, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import { DropStatusStore } from "../../src/analysis/dropStatus.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { MockProvider } from "../../src/providers/provider.js";
import { createApp } from "../../src/server.js";
import { CustomToolStore } from "../../src/integrations/tools/customToolStore.js";

// #1153: the evidence drop folder had no notion of "a binary this codebase natively parses" — a
// BTM file's raw bytes (bplist keyed archive) trip dropScan.ts's own looksBinary() NUL-byte sniff,
// so it fell into the external-tool routing branch and sat as a "run external tool" pending banner
// forever, even though routes/importMacLoginItem.ts already parses this exact format. These tests
// exercise the REAL drop-folder poller end to end (composition/dropFolder.ts's processDropFile is
// a closure inside createApp with no exported surface, matching dropFolderSymlink.test.ts's own
// precedent) — proving a real BTM file now auto-imports, a foreign file merely NAMED like one does
// not get coerced, and the size cap this branch needed (Ollama design-review finding 2) is real.

// A REAL CFURL bookmark blob (michaeldiazlutz/mac_alias's own Bookmark.to_bytes()) inside a
// hand-built NSKeyedArchiver bplist matching mnrkbys/bgiparser's own confirmed legacy container
// shape (version === 2, backgroundItems.allContainers[*].internalItems[0].bookmark.data) — the
// same fixture tests/analysis/macLoginItemImport.test.ts uses for the parser itself.
const LEGACY_BTM_HEX =
  "62706c6973743030d4010203040506282b5924617263686976657258246f626a656374735424746f70582476657273696f6e5f100f4e534b657965644172636869766572aa07080d101215171a1d2255246e756c6cd2090a0b0c5f100f6261636b67726f756e644974656d735776657273696f6e80021002d10e0f5d616c6c436f6e7461696e6572738003a1118004d113145d696e7465726e616c4974656d738005a1168006d1181958626f6f6b6d61726b8007d11b1c54646174618008d21e1f20215624636c617373574e532e6461746180094f110184626f6f6b84010000000004103000000000000000000000000000000000000000000000000000000000000000000000000401000010000000010600001c0000002c000000380000004c000000050000000101000055736572730000000300000001010000626f62000c000000010100004170706c69636174696f6e730d000000010100004c65676163794170702e61707000000010000000010600007c0000008800000094000000a000000004000000030300000200000004000000030300003200000004000000030300003c0000000400000003030000460000000c000000010100004d6163696e746f7368204844240000000101000041414141414141412d313131312d323232322d333333332d3434343434343434343434340d000000010100004c65676163794170702e61707000000034000000feffffff01000000000000000500000004100000040000000000000005100000640000000000000010200000ac0000000000000011200000c00000000000000017f00000ec00000000000000d2232425265824636c61737365735a24636c6173736e616d65a22627564e5344617461584e534f626a656374d1292a54726f6f74800112000186a000080011001b0024002900320044004f0055005a006c007400760078007b0089008b008d008f009200a000a200a400a600a900b200b400b700bc00be00c300ca00d200d4025c0261026a02750278027f0288028b029002920000000000000201000000000000002c00000000000000000000000000000297";

// A real bplist00 keyed archive that matches NEITHER the legacy nor the modern BTM shape — a
// "book" (name+magic pass, wrong internal structure) rather than a wrong-format file.
const UNRELATED_KEYED_ARCHIVE_HEX =
  "62706c6973743030d40102030405060b0e5924617263686976657258246f626a656374735424746f70582476657273696f6e5f100f4e534b657965644172636869766572a2070855246e756c6cd1090a5568656c6c6f55776f726c64d10c0d54726f6f74800112000186a008111b24293244474d50565c5f64660000000000000101000000000000000f0000000000000000000000000000006b";

function findingPipeline(stateStore: StateStore): AnalysisPipeline {
  return new AnalysisPipeline({
    provider: new MockProvider(
      "mock",
      JSON.stringify({
        findings: [],
        iocs: [],
        mitreTechniques: [],
        threadsOpened: [],
        threadsClosed: [],
        timelineNote: "n",
        summary: "s",
      }),
    ),
    stateStore,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
}

async function harness(customToolStore?: CustomToolStore) {
  const prevPoll = process.env.DFIR_DROP_POLL_S;
  process.env.DFIR_DROP_POLL_S = "2"; // minimum settle: seen at poll 1, imported at poll 2
  const root = await mkdtemp(join(tmpdir(), "dfir-drop-btm-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const jobManager = new JobManager();
  const app = createApp(store, {
    pipeline: findingPipeline(stateStore),
    stateStore,
    jobManager,
    dropStatusStore: new DropStatusStore(store), // presence ARMS the drop-folder poller
    ...(customToolStore ? { customToolStore } : {}),
  });
  const restore = () => {
    if (prevPoll === undefined) delete process.env.DFIR_DROP_POLL_S;
    else process.env.DFIR_DROP_POLL_S = prevPoll;
  };
  return { app, store, stateStore, jobManager, restore };
}

async function importLedgerRows(
  store: CaseStore,
  caseId: string,
): Promise<{ originalName: string; rows: number }[]> {
  const raw = await readFile(store.importsLogPath(caseId), "utf8").catch(() => "");
  return raw
    .split("\n")
    .filter((l) => l.trim())
    .map((l) => JSON.parse(l));
}

// composition/dropFolder.ts's own `scanCaseDrops` calls `jobManager.finish()` BEFORE
// `dropStatusStore.record()` — so a job-status-only wait can resolve before the drop-status record
// (or the file move) it precedes has actually happened (caught by this suite's own first draft,
// which read dropStatus immediately after the job went terminal and flaked). Every assertion below
// polls its own real, final condition instead, mirroring dropFolderSymlink.test.ts's own "wait for
// the CONDITION the assertions need, not a fixed sleep past job creation" precedent.
async function waitForCondition(check: () => Promise<boolean>, deadlineMs = 20_000): Promise<void> {
  const deadline = Date.now() + deadlineMs;
  while (Date.now() < deadline) {
    if (await check()) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error("condition not met within the deadline");
}

async function fileExistsIn(dir: string, name: string): Promise<boolean> {
  const entries = await readdir(dir).catch(() => [] as string[]);
  return entries.includes(name);
}

describe("drop-folder auto-importer — macOS Background Task Management (#1153)", () => {
  it("auto-imports a real BTM file dropped into the evidence folder, instead of leaving it pending", async () => {
    const { app, store, stateStore, restore } = await harness();
    try {
      await request(app)
        .post("/cases")
        .send({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
      const dropDir = join(store.caseDir("c1"), "drop");
      await mkdir(dropDir, { recursive: true });
      await writeFile(join(dropDir, "backgrounditems.btm"), Buffer.from(LEGACY_BTM_HEX, "hex"));

      await waitForCondition(() => fileExistsIn(join(dropDir, "_processed"), "backgrounditems.btm"));

      const state = await stateStore.load("c1");
      const macEvent = state.forensicTimeline.find((e) => e.canonical?.macLoginItem);
      expect(macEvent).toBeTruthy();
      expect(macEvent!.canonical!.macLoginItem!.targetPathComponents).toEqual([
        "Users",
        "bob",
        "Applications",
        "LegacyApp.app",
      ]);

      // Moved to _processed/, never left as a "run external tool" pending banner.
      const processed = await readdir(join(dropDir, "_processed")).catch(() => []);
      expect(processed).toContain("backgrounditems.btm");
      const dropStatus = await new DropStatusStore(store).load("c1");
      expect(dropStatus?.pendingRawInputs?.length ?? 0).toBe(0);
      // The ledger's own `rows` count reflects what was actually kept/imported (preview.kept),
      // matching routes/importMacLoginItem.ts's own inline convention — not the persistRawEvidence
      // default of 0.
      const imports = await importLedgerRows(store, "c1");
      expect(imports.find((i) => i.originalName === "backgrounditems.btm")?.rows).toBe(1);
    } finally {
      restore();
    }
  }, 30_000);

  it("never coerces a file merely NAMED like a BTM whose bytes are not a real bplist", async () => {
    const { app, store, restore } = await harness();
    try {
      await request(app)
        .post("/cases")
        .send({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
      const dropDir = join(store.caseDir("c1"), "drop");
      await mkdir(dropDir, { recursive: true });
      // Real BTM filename, but the content is NOT bplist00 — detectBinaryImportKind requires both;
      // this must fall through to the existing binary-sniff/pending path, unchanged.
      await writeFile(
        join(dropDir, "backgrounditems.btm"),
        Buffer.from([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]),
      );

      const dropStatusStore = new DropStatusStore(store);
      await waitForCondition(async () =>
        Boolean(
          (await dropStatusStore.load("c1"))?.pendingRawInputs?.some(
            (p) => p.relpath === "backgrounditems.btm",
          ),
        ),
      );

      const dropStatus = await dropStatusStore.load("c1");
      expect(dropStatus?.pendingRawInputs?.some((p) => p.relpath === "backgrounditems.btm")).toBe(true);
      const remaining = await readdir(dropDir);
      expect(remaining).toContain("backgrounditems.btm");
    } finally {
      restore();
    }
  }, 30_000);

  it("imports natively even when a configured custom tool claims the .btm extension (native takes precedence)", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-drop-btm-tools-"));
    const customToolStore = new CustomToolStore(join(root, "custom-tools.json"));
    await customToolStore.add({
      name: "Fake BTM Tool",
      binary: "/bin/true",
      extensions: [".btm"],
      autoRun: true,
    });
    const { app, store, stateStore, restore } = await harness(customToolStore);
    try {
      await request(app)
        .post("/cases")
        .send({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
      const dropDir = join(store.caseDir("c1"), "drop");
      await mkdir(dropDir, { recursive: true });
      await writeFile(join(dropDir, "backgrounditems.btm"), Buffer.from(LEGACY_BTM_HEX, "hex"));

      await waitForCondition(() => fileExistsIn(join(dropDir, "_processed"), "backgrounditems.btm"));

      // Natively imported — the configured tool was never consulted (no "submitted"/pending state,
      // and the real macLoginItem event landed in the forensic timeline).
      const state = await stateStore.load("c1");
      expect(state.forensicTimeline.some((e) => e.canonical?.macLoginItem)).toBe(true);
      const dropStatus = await new DropStatusStore(store).load("c1");
      expect(dropStatus?.pendingRawInputs?.length ?? 0).toBe(0);
      const processed = await readdir(join(dropDir, "_processed")).catch(() => []);
      expect(processed).toContain("backgrounditems.btm");
    } finally {
      restore();
    }
  }, 30_000);

  it("still imports the BTM file when the case's AI toggle is off (fully deterministic, no LLM call)", async () => {
    const { app, store, stateStore, restore } = await harness();
    try {
      await request(app)
        .post("/cases")
        .send({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
      await request(app).post("/cases/c1/ai-control").send({ enabled: false });
      const dropDir = join(store.caseDir("c1"), "drop");
      await mkdir(dropDir, { recursive: true });
      await writeFile(join(dropDir, "backgrounditems.btm"), Buffer.from(LEGACY_BTM_HEX, "hex"));

      await waitForCondition(() => fileExistsIn(join(dropDir, "_processed"), "backgrounditems.btm"));

      const state = await stateStore.load("c1");
      expect(state.forensicTimeline.some((e) => e.canonical?.macLoginItem)).toBe(true);
      const processed = await readdir(join(dropDir, "_processed")).catch(() => []);
      expect(processed).toContain("backgrounditems.btm");
    } finally {
      restore();
    }
  }, 30_000);

  it("fails a foreign keyed archive under a matching BTM filename, and leaves NO import-ledger row for it", async () => {
    const { app, store, restore } = await harness();
    try {
      await request(app)
        .post("/cases")
        .send({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
      const dropDir = join(store.caseDir("c1"), "drop");
      await mkdir(dropDir, { recursive: true });
      await writeFile(
        join(dropDir, "BackgroundItems-v3.btm"),
        Buffer.from(UNRELATED_KEYED_ARCHIVE_HEX, "hex"),
      );

      await waitForCondition(() => fileExistsIn(join(dropDir, "_failed"), "BackgroundItems-v3.btm"));

      const failed = await readdir(join(dropDir, "_failed")).catch(() => []);
      expect(failed).toContain("BackgroundItems-v3.btm");
      // No phantom "successful" ledger row for a file that never actually imported (design-review
      // finding 3 — parse-before-persist ordering).
      const imports = await importLedgerRows(store, "c1");
      expect(imports.some((i) => i.originalName === "BackgroundItems-v3.btm")).toBe(false);
    } finally {
      restore();
    }
  }, 30_000);

  it("still ignores a random binary that is not name+magic BTM (existing pending-tool behavior unchanged)", async () => {
    const { app, store, restore } = await harness();
    try {
      await request(app)
        .post("/cases")
        .send({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
      const dropDir = join(store.caseDir("c1"), "drop");
      await mkdir(dropDir, { recursive: true });
      // NUL byte forces the binary sniff; extension is unrecognized by any importer or tool.
      await writeFile(join(dropDir, "sample.bin"), Buffer.from([0x00, 0x01, 0x02, 0x03, 0x04]));

      const dropStatusStore = new DropStatusStore(store);
      await waitForCondition(async () =>
        Boolean(
          (await dropStatusStore.load("c1"))?.pendingRawInputs?.some((p) => p.relpath === "sample.bin"),
        ),
      );

      const dropStatus = await dropStatusStore.load("c1");
      expect(dropStatus?.pendingRawInputs?.some((p) => p.relpath === "sample.bin")).toBe(true);
      // Never moved — a pending raw input stays in place so a manual tool run can still act on it.
      const remaining = await readdir(dropDir);
      expect(remaining).toContain("sample.bin");
    } finally {
      restore();
    }
  }, 30_000);

  it("rejects a .btm file over the size cap, with the real byte counts in the failure reason", async () => {
    const prevMax = process.env.DFIR_MAX_IMPORT_FILE_MB;
    process.env.DFIR_MAX_IMPORT_FILE_MB = "1"; // shrink the cap so the test file can be small
    const { app, store, restore } = await harness();
    try {
      await request(app)
        .post("/cases")
        .send({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
      const dropDir = join(store.caseDir("c1"), "drop");
      await mkdir(dropDir, { recursive: true });
      // Real magic + real name so detection matches, padded well past the 1 MB cap.
      const padBytes = 2 * 1024 * 1024;
      const oversized = Buffer.concat([Buffer.from(LEGACY_BTM_HEX, "hex"), Buffer.alloc(padBytes, 0x41)]);
      const realSize = oversized.byteLength;
      await writeFile(join(dropDir, "backgrounditems.btm"), oversized);

      await waitForCondition(() => fileExistsIn(join(dropDir, "_failed"), "backgrounditems.btm"));

      const failed = await readdir(join(dropDir, "_failed")).catch(() => []);
      expect(failed).toContain("backgrounditems.btm");
      const imports = await importLedgerRows(store, "c1");
      expect(imports.some((i) => i.originalName === "backgrounditems.btm")).toBe(false);
      // Asserts the REAL size and the REAL 1 MB cap both appear — a bare /too large/i match would
      // also pass on a broken `${err.size}`/`${err.maxBytes}` interpolation (Ollama code review
      // finding), so this pins the actual numbers, not just the word "large".
      const raw = await readFile(join(dropDir, "drop-log.txt"), "utf8").catch(() => "");
      expect(raw).toContain(`${realSize} bytes`);
      expect(raw).toContain(`${1024 * 1024}-byte cap`);
    } finally {
      restore();
      if (prevMax === undefined) delete process.env.DFIR_MAX_IMPORT_FILE_MB;
      else process.env.DFIR_MAX_IMPORT_FILE_MB = prevMax;
    }
  }, 30_000);
});
