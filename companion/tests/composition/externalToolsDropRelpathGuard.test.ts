import { describe, expect, it } from "vitest";
import { mkdir, mkdtemp, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createExternalTools } from "../../src/composition/externalTools.js";
import { dropDirOf } from "../../src/composition/dropFolder.js";
import { loadAllToolConfigs } from "../../src/integrations/tools/toolConfig.js";

// #980 (defense-in-depth on #919). run-pending feeds runDropToolAndIngest a relpath from
// state/drop-status.json, which an imported archive restores verbatim. The schema drops an escaping
// entry at load, and moveDropFile refuses one before the rename — but the READ half had only the
// schema: the HTTP branch opened `join(dropDir, relpath)` and uploaded the bytes with no check of
// its own. The rename got two layers; the upload, the more dangerous operation, got one.
//
// The guard is BOUND to the file that is opened, not to a label beside it (Codex P1 on the first
// cut): the path is derived from the case's own drop directory, a caller's disagreeing fullPath is
// a bug and refused, and containment is checked on the REAL parent directory, so a relpath that
// walks through a symlinked subdirectory is refused even though every segment of it looks safe.

const refuse = (): never => {
  throw new Error("not expected on this path");
};

const REACHED_UPLOAD = /ECONNREFUSED|fetch failed|SO-CRATES/;
const DIR_LINK = process.platform === "win32" ? "junction" : "dir";

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-drop-read-guard-"));
  const store = new CaseStore(join(root, "cases"));
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const dropDir = dropDirOf(store, "c1");
  await mkdir(join(dropDir, "triage"), { recursive: true });
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
  const outsideDir = join(root, "planted");
  await mkdir(outsideDir, { recursive: true });
  const outside = join(outsideDir, "outside-secret.pcap");
  await writeFile(outside, Buffer.alloc(64, 0x01));
  return { root, tools, dropDir, outsideDir, outside };
}

// What run-pending does: join the relpath onto the drop dir and pass both.
function runPending(tools: Awaited<ReturnType<typeof harness>>["tools"], dropDir: string, relpath: string) {
  return tools.runDropToolAndIngest("c1", "socrates", join(dropDir, relpath), {
    name: "x.pcap",
    dropRelpath: relpath,
  });
}

describe("runDropToolAndIngest refuses a drop relpath that escapes the drop folder (#980)", () => {
  it("refuses a traversal relpath before the read — not a connection error", async () => {
    const { tools, dropDir } = await harness();
    await expect(
      runPending(tools, dropDir, join("..", "..", "..", "planted", "outside-secret.pcap")),
    ).rejects.toThrow(/outside the drop folder/);
  });

  it("refuses an absolute relpath the same way", async () => {
    const { tools, dropDir, outside } = await harness();
    await expect(runPending(tools, dropDir, outside)).rejects.toThrow(/outside the drop folder/);
  });

  it("refuses a relpath through a symlinked subdirectory — every segment looks safe, the real parent is outside", async () => {
    const { tools, dropDir, outsideDir } = await harness();
    await symlink(outsideDir, join(dropDir, "linked"), DIR_LINK);
    // Lexically `linked/outside-secret.pcap` is a descendant of drop/; on disk it is the planted
    // file. O_NOFOLLOW guards only the final component, so this has to be caught by containment.
    await expect(runPending(tools, dropDir, join("linked", "outside-secret.pcap"))).rejects.toThrow(
      /outside the drop folder/,
    );
  });

  it("refuses a caller whose fullPath disagrees with the relpath — the label is not the file", async () => {
    const { tools, dropDir, outside } = await harness();
    await writeFile(join(dropDir, "triage", "ok.pcap"), Buffer.alloc(64, 0x02));
    await expect(
      tools.runDropToolAndIngest("c1", "socrates", outside, {
        name: "ok.pcap",
        dropRelpath: join("triage", "ok.pcap"),
      }),
    ).rejects.toThrow(/outside the drop folder/);
  });

  it("still refuses a symlink at the final component — containment does not replace the link guard", async () => {
    const { tools, dropDir, outside } = await harness();
    await symlink(outside, join(dropDir, "triage", "planted.pcap"));
    await expect(runPending(tools, dropDir, join("triage", "planted.pcap"))).rejects.toThrow(/symlink/);
  });

  it("still reaches the upload for an ordinary dropped file — the error is the connection, not the guard", async () => {
    const { tools, dropDir } = await harness();
    await writeFile(join(dropDir, "triage", "ok.pcap"), Buffer.alloc(64, 0x02));
    await expect(runPending(tools, dropDir, join("triage", "ok.pcap"))).rejects.toThrow(REACHED_UPLOAD);
  });

  it("is unchanged for a caller that passes no relpath (the manual tool-run route)", async () => {
    const { tools, outside } = await harness();
    await expect(tools.runDropToolAndIngest("c1", "socrates", outside, { name: "x.pcap" })).rejects.toThrow(
      REACHED_UPLOAD,
    );
  });
});
