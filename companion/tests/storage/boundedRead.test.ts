import { describe, expect, it } from "vitest";
import { mkdtemp, open, writeFile } from "node:fs/promises";
import type { FileHandle } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { FileTooLargeError, readHandleBounded } from "../../src/storage/boundedRead.js";

// #921 review. A `stat(path)` followed by `readFile(path)` checks one inode and reads whatever
// occupies the path afterwards, so a swap between the two defeats a size cap. The check and the
// read have to share a descriptor — and the read itself has to be bounded, because a regular file
// can be appended to between fstat and read without ever changing identity.

async function tmpFile(bytes: number): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "dfir-bounded-read-"));
  const path = join(dir, "f.bin");
  await writeFile(path, Buffer.alloc(bytes, 0x5a));
  return path;
}

describe("readHandleBounded", () => {
  it("returns the whole file when it is within the cap", async () => {
    const fh = await open(await tmpFile(1000), "r");
    try {
      const out = await readHandleBounded(fh, 1000);
      expect(out.length).toBe(1000);
      expect(out.every((b) => b === 0x5a)).toBe(true);
    } finally {
      await fh.close();
    }
  });

  it("refuses a file over the cap from the descriptor's own size, before allocating for it", async () => {
    const fh = await open(await tmpFile(1001), "r");
    try {
      await expect(readHandleBounded(fh, 1000)).rejects.toBeInstanceOf(FileTooLargeError);
      await expect(readHandleBounded(fh, 1000)).rejects.toMatchObject({ size: 1001, maxBytes: 1000 });
    } finally {
      await fh.close();
    }
  });

  it("refuses a file that grew between fstat and read — the bound is on bytes read, not on the stat", async () => {
    // A handle whose stat says 10 bytes but whose read keeps producing: the shape of a file being
    // appended to (same inode, same descriptor) while it is read.
    let served = 0;
    const growing = {
      stat: async () => ({ size: 10 }),
      read: async (buf: Buffer, offset: number, length: number) => {
        const n = Math.min(length, 4);
        buf.fill(0x41, offset, offset + n);
        served += n;
        return { bytesRead: n, buffer: buf };
      },
    } as unknown as FileHandle;

    await expect(readHandleBounded(growing, 1000)).rejects.toBeInstanceOf(FileTooLargeError);
    // It stopped as soon as it had one byte more than the size it was promised — it did not keep
    // reading an unbounded stream to find out how big it really was.
    expect(served).toBeLessThanOrEqual(10 + 4);
  });

  it("rejects an empty or non-positive cap rather than reading nothing or everything", async () => {
    const fh = await open(await tmpFile(10), "r");
    try {
      await expect(readHandleBounded(fh, 0)).rejects.toThrow(/cap/);
      await expect(readHandleBounded(fh, -1)).rejects.toThrow(/cap/);
    } finally {
      await fh.close();
    }
  });
});
