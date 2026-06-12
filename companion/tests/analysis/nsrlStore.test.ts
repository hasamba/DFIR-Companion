import { describe, it, expect } from "vitest";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { NsrlStore } from "../../src/analysis/nsrlStore.js";

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
