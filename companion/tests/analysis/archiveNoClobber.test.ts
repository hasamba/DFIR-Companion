// #2787: writeBufferNewFile never replaces an existing file — it takes the next free " (n)" name.
import { describe, it, expect } from "vitest";
import { mkdtemp, readFile, readdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { writeBufferNewFile, copyNumberedSuffix } from "../../src/analysis/archiveNoClobber.js";
import { caseNamedFilename, MAX_CASE_FILENAME_BYTES } from "../../src/analysis/caseFilename.js";

describe("copyNumberedSuffix", () => {
  it("leaves the first copy unnumbered and numbers later ones before the extension", () => {
    expect(copyNumberedSuffix(".dfircase", 1)).toBe(".dfircase");
    expect(copyNumberedSuffix(".dfircase", 2)).toBe(" (2).dfircase");
    expect(copyNumberedSuffix(" (no password).zip", 3)).toBe(" (no password) (3).zip");
  });
});

describe("writeBufferNewFile", () => {
  it("writes the base name, then (2), (3) — earlier files untouched, no temp left", async () => {
    const dir = await mkdtemp(join(tmpdir(), "dfir-noclobber-unit-"));
    try {
      const nameFor = (n: number) => caseNamedFilename("c1", "Name", copyNumberedSuffix(".dfircase", n));
      const a = await writeBufferNewFile(dir, nameFor, Buffer.from("one"));
      const b = await writeBufferNewFile(dir, nameFor, Buffer.from("two"));
      const c = await writeBufferNewFile(dir, nameFor, Buffer.from("three"));
      expect([a, b, c]).toEqual([
        join(dir, "c1 - Name.dfircase"),
        join(dir, "c1 - Name (2).dfircase"),
        join(dir, "c1 - Name (3).dfircase"),
      ]);
      expect((await readFile(a)).toString()).toBe("one");
      expect((await readFile(b)).toString()).toBe("two");
      expect((await readdir(dir)).filter((f) => f.endsWith(".tmp"))).toEqual([]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("skips a name already taken by something else (a file the analyst put there)", async () => {
    const dir = await mkdtemp(join(tmpdir(), "dfir-noclobber-unit-"));
    try {
      await writeFile(join(dir, "c1.dfircase"), "mine");
      const p = await writeBufferNewFile(
        dir,
        (n) => `c1${copyNumberedSuffix(".dfircase", n)}`,
        Buffer.from("x"),
      );
      expect(p).toBe(join(dir, "c1 (2).dfircase"));
      expect((await readFile(join(dir, "c1.dfircase"))).toString()).toBe("mine");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("a failed publish leaves no temp file and rejects", async () => {
    const dir = await mkdtemp(join(tmpdir(), "dfir-noclobber-unit-"));
    try {
      await writeFile(join(dir, "a.zip"), "taken");
      const nameFor = (n: number) => (n === 1 ? "a.zip" : join("missing", "a.zip"));
      await expect(writeBufferNewFile(dir, nameFor, Buffer.from("x"))).rejects.toThrow();
      expect(await readdir(dir)).toEqual(["a.zip"]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("keeps a numbered long name inside the UTF-8 byte cap", () => {
    const long = "ש".repeat(400);
    const name = caseNamedFilename("c1", long, copyNumberedSuffix(".dfircase", 12));
    expect(Buffer.byteLength(name, "utf8")).toBeLessThanOrEqual(MAX_CASE_FILENAME_BYTES);
    expect(name.endsWith(" (12).dfircase")).toBe(true);
  });
});
