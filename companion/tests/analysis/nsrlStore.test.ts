import { describe, it, expect } from "vitest";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { NsrlStore, ingestNsrlFiles, splitNsrlPaths } from "../../src/analysis/nsrlStore.js";

const MD5 = "d41d8cd98f00b204e9800998ecf8427e";
const SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

async function store(): Promise<NsrlStore> {
  const dir = await mkdtemp(join(tmpdir(), "dfir-nsrl-"));
  // A nested subdir that doesn't exist yet, to exercise the mkdir-on-persist path.
  return new NsrlStore(join(dir, "nsrl", "known-hashes.txt"));
}

describe("NsrlStore", () => {
  it("starts empty", async () => {
    const s = await store();
    expect(await s.count()).toBe(0);
    expect((await s.load()).size).toBe(0);
  });

  it("adds hashes, normalizes + dedups, and reports how many were new", async () => {
    const s = await store();
    const r1 = await s.addMany([MD5.toUpperCase(), SHA256, MD5, "not-a-hash", "ffffffff"]);
    expect(r1.added).toBe(2);     // MD5 + SHA256; junk dropped, dupe collapsed
    expect(r1.total).toBe(2);
    expect((await s.load()).has(MD5)).toBe(true);

    const r2 = await s.addMany([MD5, SHA256]);   // both already present
    expect(r2.added).toBe(0);
    expect(r2.total).toBe(2);
  });

  it("persists a normalized, sorted hash-per-line file that reloads", async () => {
    const s = await store();
    await s.addMany([SHA256, MD5]);
    const onDisk = await readFile((s as unknown as { file: string }).file, "utf8");
    expect(onDisk).toBe([MD5, SHA256].sort().join("\n") + "\n");

    // A fresh store over the same file sees the same set (read path re-validates).
    const s2 = new NsrlStore((s as unknown as { file: string }).file);
    expect(await s2.count()).toBe(2);
  });

  it("clears the set and exports a newline-delimited dump", async () => {
    const s = await store();
    await s.addMany([MD5, SHA256]);
    expect(await s.exportText()).toBe([MD5, SHA256].sort().join("\n") + "\n");
    await s.clear();
    expect(await s.count()).toBe(0);
    expect(await s.exportText()).toBe("");
  });
});

describe("splitNsrlPaths", () => {
  it("splits on ';', trims, and drops blanks (Windows-path safe)", () => {
    expect(splitNsrlPaths("C:\\rds\\a.txt ; C:\\rds b\\c.txt;")).toEqual(["C:\\rds\\a.txt", "C:\\rds b\\c.txt"]);
    expect(splitNsrlPaths(undefined)).toEqual([]);
    expect(splitNsrlPaths("   ")).toEqual([]);
  });
});

describe("ingestNsrlFiles", () => {
  it("reads + ingests file(s) by path, best-effort per file (a bad path is reported, not fatal)", async () => {
    const dir = await mkdtemp(join(tmpdir(), "dfir-nsrl-ing-"));
    const good = join(dir, "rds.txt");
    await writeFile(good, `"SHA-1","MD5","CRC32"\n"${"da39a3ee5e6b4b0d3255bfef95601890afd80709".toUpperCase()}","${MD5.toUpperCase()}","0"\n`, "utf8");
    const s = new NsrlStore(join(dir, "store", "known.txt"));

    const results = await ingestNsrlFiles(s, [good, join(dir, "missing.txt")]);
    expect(results).toHaveLength(2);
    expect(results[0]).toMatchObject({ file: good, added: 2 });
    expect(results[0].error).toBeUndefined();
    expect(results[1].error).toBeTruthy();           // missing file → error result, not a throw
    expect(results[1].added).toBe(0);
    expect(await s.count()).toBe(2);                 // the good file still loaded
  });
});
