import { describe, it, expect } from "vitest";
import { mkdtemp, writeFile, readFile, open, access } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { copyHandleBounded } from "../../src/storage/handleCopy.js";
import { FileTooLargeError } from "../../src/storage/boundedRead.js";

// #2270: the drop folder's cross-filesystem move used to buffer the whole file with
// FileHandle.readFile(). copyHandleBounded streams it instead, and stops at a byte bound so a file
// that grew after it was sized is refused rather than copied in full.

async function fixture(bytes: Buffer) {
  const dir = await mkdtemp(join(tmpdir(), "dfir-handlecopy-"));
  const src = join(dir, "src.bin");
  await writeFile(src, bytes);
  return { dir, src, dest: join(dir, "dest.bin") };
}

describe("copyHandleBounded (#2270)", () => {
  it("copies exactly the bytes of the open file when it is within the bound", async () => {
    const data = Buffer.from("evidence bytes ".repeat(1000));
    const { src, dest } = await fixture(data);
    const handle = await open(src, "r");
    try {
      const { bytes } = await copyHandleBounded(handle, dest, data.length);
      expect(bytes).toBe(data.length);
    } finally {
      await handle.close();
    }
    expect((await readFile(dest)).equals(data)).toBe(true);
  });

  it("copies an empty file with a bound of zero", async () => {
    const { src, dest } = await fixture(Buffer.alloc(0));
    const handle = await open(src, "r");
    try {
      await copyHandleBounded(handle, dest, 0);
    } finally {
      await handle.close();
    }
    expect((await readFile(dest)).length).toBe(0);
  });

  it("refuses a file larger than the bound, removes the partial copy, and leaves the source alone", async () => {
    const data = Buffer.from("0123456789".repeat(500));
    const { src, dest } = await fixture(data);
    const handle = await open(src, "r");
    try {
      await expect(copyHandleBounded(handle, dest, data.length - 1)).rejects.toBeInstanceOf(
        FileTooLargeError,
      );
    } finally {
      await handle.close();
    }
    await expect(access(dest)).rejects.toThrow();
    expect((await readFile(src)).equals(data)).toBe(true);
  });

  it("never overwrites an existing destination", async () => {
    const { src, dest } = await fixture(Buffer.from("new"));
    await writeFile(dest, "ALREADY-HERE");
    const handle = await open(src, "r");
    try {
      await expect(copyHandleBounded(handle, dest, 3)).rejects.toThrow(/EEXIST/);
    } finally {
      await handle.close();
    }
    expect(await readFile(dest, "utf8")).toBe("ALREADY-HERE");
  });

  it("rejects a bound that is not a non-negative whole number", async () => {
    const { src, dest } = await fixture(Buffer.from("x"));
    const handle = await open(src, "r");
    try {
      await expect(copyHandleBounded(handle, dest, -1)).rejects.toThrow(/bound/);
      await expect(copyHandleBounded(handle, dest, Number.NaN)).rejects.toThrow(/bound/);
    } finally {
      await handle.close();
    }
    await expect(access(dest)).rejects.toThrow();
  });
});
