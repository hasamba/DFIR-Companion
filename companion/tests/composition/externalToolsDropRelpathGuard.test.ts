import { describe, expect, it } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createExternalTools } from "../../src/composition/externalTools.js";
import { loadAllToolConfigs } from "../../src/integrations/tools/toolConfig.js";

// #980 (defense-in-depth on #919). run-pending feeds runDropToolAndIngest a relpath from
// state/drop-status.json, which an imported archive restores verbatim. The schema drops an escaping
// entry at load, and moveDropFile refuses one before the rename — but the READ half had only the
// schema: the HTTP branch opened `join(dropDir, relpath)` and uploaded the bytes with no check of
// its own. The rename got two layers; the upload, the more dangerous operation, got one. The guard
// now sits at the top of runDropToolAndIngest so both transports and both callers share it.

const refuse = (): never => {
  throw new Error("not expected on this path");
};

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-drop-read-guard-"));
  const store = new CaseStore(join(root, "cases"));
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const tools = createExternalTools({
    store,
    // A SO-CRATES that exists but cannot be reached: an attempted upload fails on the connection,
    // which is how the test tells "refused before reading" from "read and tried to send".
    options: { loadToolConfigs: () => loadAllToolConfigs({ DFIR_TOOL_SOCRATES_URL: "http://127.0.0.1:9" }) },
    resolveImportKind: refuse,
    ingestStreamed: refuse,
    persistRawEvidence: refuse,
    pushImportCheckpoint: refuse,
  });
  // A readable file outside any drop folder, standing in for whatever a traversal relpath names.
  const outside = join(root, "outside-secret.pcap");
  await writeFile(outside, Buffer.alloc(64, 0x01));
  return { tools, outside };
}

describe("runDropToolAndIngest refuses a drop relpath that escapes the drop folder (#980)", () => {
  it("does not open or upload the file — the refusal precedes the read, so it is not a connection error", async () => {
    const { tools, outside } = await harness();
    const relpath = join("..", "..", "outside-secret.pcap");
    await expect(
      tools.runDropToolAndIngest("c1", "socrates", outside, {
        name: "outside-secret.pcap",
        dropRelpath: relpath,
      }),
    ).rejects.toThrow(/outside the drop folder/);
  });

  it("refuses an absolute relpath the same way", async () => {
    const { tools, outside } = await harness();
    await expect(
      tools.runDropToolAndIngest("c1", "socrates", outside, {
        name: "outside-secret.pcap",
        dropRelpath: outside,
      }),
    ).rejects.toThrow(/outside the drop folder/);
  });

  it("still reaches the upload for an ordinary relpath — the error is the connection, not the guard", async () => {
    const { tools, outside } = await harness();
    await expect(
      tools.runDropToolAndIngest("c1", "socrates", outside, {
        name: "outside-secret.pcap",
        dropRelpath: join("triage", "outside-secret.pcap"),
      }),
    ).rejects.toThrow(/ECONNREFUSED|fetch failed|SO-CRATES/);
  });

  it("is unchanged for a caller that passes no relpath (the manual tool-run route)", async () => {
    const { tools, outside } = await harness();
    await expect(
      tools.runDropToolAndIngest("c1", "socrates", outside, { name: "outside-secret.pcap" }),
    ).rejects.toThrow(/ECONNREFUSED|fetch failed|SO-CRATES/);
  });
});
