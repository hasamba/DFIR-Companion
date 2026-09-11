import type { FileHandle } from "node:fs/promises";

/**
 * Read a whole file into memory with a hard ceiling, on ONE descriptor (#921).
 *
 * The obvious shape — `stat(path)`, compare, `readFile(path)` — checks one inode and then reads
 * whatever occupies the path a moment later. In a drop folder that is a synced share, or on a
 * server path an analyst typed, that moment is enough for a swap: a symlink or a multi-gigabyte
 * file put in place after the check is read in full, and the cap bounded nothing. Two things close
 * that: the size comes from `fstat` on the handle the read draws from, and the read itself stops
 * one byte past the size it was promised, because a regular file can be appended to between fstat
 * and read without ever changing identity.
 *
 * Allocation is bounded at `size + 1`, never at the cap: a small file costs a small buffer.
 */
export class FileTooLargeError extends Error {
  constructor(
    /** The size fstat reported, or the promised size + 1 when the file grew past it mid-read. */
    readonly size: number,
    readonly maxBytes: number,
  ) {
    super(`file is ${size} bytes, over the ${maxBytes}-byte cap`);
    this.name = "FileTooLargeError";
  }
}

export async function readHandleBounded(handle: FileHandle, maxBytes: number): Promise<Buffer> {
  if (!Number.isFinite(maxBytes) || maxBytes <= 0) {
    throw new Error(`readHandleBounded: cap must be a positive number of bytes, got ${maxBytes}`);
  }
  const { size } = await handle.stat();
  if (size > maxBytes) throw new FileTooLargeError(size, maxBytes);
  // One byte of headroom is the growth detector: a read that fills it means the file is now
  // larger than fstat said, so the bytes in hand are not the whole file and never will be.
  const buffer = Buffer.alloc(size + 1);
  let offset = 0;
  while (offset < buffer.length) {
    const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, offset);
    if (bytesRead === 0) break;
    offset += bytesRead;
  }
  if (offset > size) throw new FileTooLargeError(offset, maxBytes);
  return buffer.subarray(0, offset);
}
