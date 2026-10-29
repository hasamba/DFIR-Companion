import { describe, expect, it } from "vitest";
import { mkdtemp, readFile, readdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { inflateRawSync } from "node:zlib";
import { archiveCase } from "../../src/analysis/caseArchive.js";
import { INVESTIGATION_DB_FILENAME, StateStore } from "../../src/analysis/stateStore.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { CaseStore } from "../../src/storage/caseStore.js";

// #2247: the plain ZIP archive walks the case once and snapshots the database only when that walk
// saw it. A database that APPEARS after the walk — a legacy JSON case migrated by a dashboard load,
// which does not take the state lock — is deliberately left out. The archive is still complete: the
// migration copies from state/investigation.json and never deletes it, and the manifest carries only
// per-file hashes of the bytes it packaged, so it cannot contradict itself. This pins that behaviour.

async function walk(dir: string, rel = ""): Promise<string[]> {
  const out: string[] = [];
  for (const e of await readdir(join(dir, rel), { withFileTypes: true })) {
    const childRel = rel ? `${rel}/${e.name}` : e.name;
    if (e.isDirectory()) out.push(...(await walk(dir, childRel)));
    else out.push(childRel);
  }
  return out;
}

// Entry name -> inflated bytes. buildZip writes sizes into every local header (method 8, DEFLATE).
function zipEntries(buf: Buffer): Map<string, Buffer> {
  const out = new Map<string, Buffer>();
  let ptr = 0;
  while (ptr + 30 <= buf.length && buf.readUInt32LE(ptr) === 0x04034b50) {
    const nameLen = buf.readUInt16LE(ptr + 26);
    const extraLen = buf.readUInt16LE(ptr + 28);
    const compressedLen = buf.readUInt32LE(ptr + 18);
    const name = buf.toString("utf8", ptr + 30, ptr + 30 + nameLen);
    const start = ptr + 30 + nameLen + extraLen;
    out.set(name, inflateRawSync(buf.subarray(start, start + compressedLen)));
    ptr = start + compressedLen;
  }
  return out;
}

describe("plain ZIP archive vs a database that appears after the walk (#2247)", () => {
  it("ships the legacy JSON state complete and leaves the new database out, with a self-consistent manifest", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-archive-race-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const legacyPath = join(cases.stateDir("c1"), "investigation.json");
    await writeFile(legacyPath, JSON.stringify(emptyState("c1")), "utf8");
    const legacyBytes = await readFile(legacyPath);

    // Walk, THEN migrate: the dashboard load lands between the scan and the snapshot decision.
    const scanFiles = async (caseDir: string): Promise<string[]> => {
      const paths = await walk(caseDir);
      await new StateStore(cases).load("c1");
      return paths;
    };
    const result = await archiveCase(root, "c1", { scanFiles }, "n", cases.caseDir("c1"));

    // The migration really happened on disk while the archive ran.
    expect(await readdir(cases.stateDir("c1"))).toContain(INVESTIGATION_DB_FILENAME);

    const entries = zipEntries(await readFile(result.archivePath));
    const names = [...entries.keys()].map((n) => n.replace(/^c1\//, ""));
    expect(names).toContain("state/investigation.json");
    expect(names.some((n) => n.endsWith(".sqlite"))).toBe(false);
    expect(entries.get("c1/state/investigation.json")?.equals(legacyBytes)).toBe(true);
    const caseFiles = names.filter((n) => n !== "archive-manifest.json");
    expect(result.manifest.files.map((f) => f.path).sort()).toEqual([...caseFiles].sort());
    expect(result.manifest.totalFiles).toBe(caseFiles.length);
  });
});
