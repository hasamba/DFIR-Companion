import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtemp, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createExternalTools } from "../../src/composition/externalTools.js";
import { loadAllToolConfigs } from "../../src/integrations/tools/toolConfig.js";
import { dropMaxBytesFromEnv } from "../../src/analysis/dropScan.js";

// #921, gap 1. processDropFile checks for a raw tool input BEFORE the oversize check, on purpose:
// "size-independent, so checked BEFORE the oversize cap". That was true when every tool was a
// spawned process handed a path. The HTTP transport reads the WHOLE file into a Buffer for the
// upload, so a 4 GB PCAP dropped into a case with SO-CRATES configured was buffered in full and the
// 200 MB cap never ran. run-pending reaches the same function from the banner.
//
// The cap therefore lives in runDropToolAndIngest itself, for the HTTP transport only — a spawn
// tool really is size-independent — so both callers are covered and neither has to know.

const refuse = (): never => {
  throw new Error("not expected on this path");
};

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-upload-cap-"));
  const store = new CaseStore(join(root, "cases"));
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const tools = createExternalTools({
    store,
    // A SO-CRATES that exists but cannot be reached: an attempted upload fails on the connection,
    // which is how the tests tell "refused before reading" from "read and tried to send".
    options: { loadToolConfigs: () => loadAllToolConfigs({ DFIR_TOOL_SOCRATES_URL: "http://127.0.0.1:9" }) },
    resolveImportKind: refuse,
    ingestStreamed: refuse,
    persistRawEvidence: refuse,
    pushImportCheckpoint: refuse,
  });
  return { root, tools };
}

const saved = process.env.DFIR_DROP_MAX_BYTES;
beforeEach(() => {
  process.env.DFIR_DROP_MAX_BYTES = "1024";
});
afterEach(() => {
  if (saved === undefined) delete process.env.DFIR_DROP_MAX_BYTES;
  else process.env.DFIR_DROP_MAX_BYTES = saved;
});

describe("runDropToolAndIngest — HTTP transport honours the drop size cap (#921)", () => {
  it("refuses an oversize file before reading it, naming the cap", async () => {
    const { root, tools } = await harness();
    const big = join(root, "big.pcap");
    await writeFile(big, Buffer.alloc(2048, 0xab));

    await expect(tools.runDropToolAndIngest("c1", "socrates", big, { name: "big.pcap" })).rejects.toThrow(
      /too large.*DFIR_DROP_MAX_BYTES/,
    );
  });

  it("still uploads a file under the cap — the refusal is size-conditional", async () => {
    const { root, tools } = await harness();
    const small = join(root, "small.pcap");
    await writeFile(small, Buffer.alloc(512, 0xab));

    // It got past the cap and tried the network: the error is the connection, not the cap.
    await expect(tools.runDropToolAndIngest("c1", "socrates", small, { name: "small.pcap" })).rejects.toThrow(
      /ECONNREFUSED|fetch failed|SO-CRATES/,
    );
    await expect(
      tools.runDropToolAndIngest("c1", "socrates", small, { name: "small.pcap" }),
    ).rejects.not.toThrow(/DFIR_DROP_MAX_BYTES/);
  });
});

describe("runDropToolAndIngest — HTTP transport reads through the link guard (#921 review)", () => {
  it("refuses a symlink planted at the path instead of uploading its target", async () => {
    const { root, tools } = await harness();
    const target = join(root, "outside.bin");
    await writeFile(target, Buffer.alloc(16, 0x01));
    const planted = join(root, "planted.pcap");
    await symlink(target, planted);

    // Before: a plain readFile(path) followed the link and uploaded the target. Now the descriptor
    // is opened O_NOFOLLOW, so this is a refusal, not a connection error.
    await expect(
      tools.runDropToolAndIngest("c1", "socrates", planted, { name: "planted.pcap" }),
    ).rejects.toThrow(/symlink/);
  });
});

describe("dropMaxBytesFromEnv", () => {
  it("defaults to 200 MB and reads DFIR_DROP_MAX_BYTES", () => {
    expect(dropMaxBytesFromEnv({})).toBe(200 * 1024 * 1024);
    expect(dropMaxBytesFromEnv({ DFIR_DROP_MAX_BYTES: "1024" })).toBe(1024);
    // Garbage and zero both fall back to the default, as the inline expression always did.
    expect(dropMaxBytesFromEnv({ DFIR_DROP_MAX_BYTES: "lots" })).toBe(200 * 1024 * 1024);
    expect(dropMaxBytesFromEnv({ DFIR_DROP_MAX_BYTES: "0" })).toBe(200 * 1024 * 1024);
  });

  it("falls back on a negative or infinite value — a negative cap silently disabled it", () => {
    // isOversize() treats maxBytes <= 0 as "no cap", so "-1" used to switch the drop cap OFF.
    expect(dropMaxBytesFromEnv({ DFIR_DROP_MAX_BYTES: "-1" })).toBe(200 * 1024 * 1024);
    expect(dropMaxBytesFromEnv({ DFIR_DROP_MAX_BYTES: "Infinity" })).toBe(200 * 1024 * 1024);
  });
});
