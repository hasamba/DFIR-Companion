// The filesystem operations the collection engine (#2311) uses, behind one small interface so the
// tests can inject faults at any step (a kill between the page rename and the manifest line, a
// full disk) without touching a real disk's behaviour.
//
// DURABILITY, PER PAGE (collectPageCommit.ts): write page.tmp → fsync the file → rename → fsync the
// directory → append the manifest line → fsync the manifest → update the checkpoint.
//
// WINDOWS: a directory cannot be opened for fsync there (EPERM/EISDIR), so `fsyncDir` is a no-op
// on win32. The rename is still atomic (MoveFileEx), the page file itself was fsynced before it,
// and the manifest is fsynced after its line — so the only loss a crash can cause is a renamed page
// with no manifest line, which resume finds and quarantines (collectReplay.ts).

import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { mkdir, open, readFile, readdir, rename, stat, truncate } from "node:fs/promises";

export interface CollectFs {
  mkdir(path: string): Promise<void>;
  /** Write the whole file and fsync it before returning. */
  writeFileSync(path: string, data: Uint8Array | string): Promise<void>;
  rename(from: string, to: string): Promise<void>;
  /** fsync a directory, so a rename inside it survives a power loss. No-op on Windows. */
  fsyncDir(path: string): Promise<void>;
  /** Append to a file and fsync it before returning. */
  appendSync(path: string, data: string): Promise<void>;
  truncate(path: string, length: number): Promise<void>;
  readFile(path: string): Promise<Buffer>;
  /** File names in a directory; [] when it does not exist. */
  readdir(path: string): Promise<string[]>;
  exists(path: string): Promise<boolean>;
  /** SHA-256 hex and byte count of a file, streamed. */
  hashFile(path: string): Promise<{ sha256: string; bytes: number }>;
}

async function writeAndSync(path: string, data: Uint8Array | string, flags: "w" | "a"): Promise<void> {
  const handle = await open(path, flags);
  try {
    await handle.writeFile(data);
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function syncDirectory(path: string): Promise<void> {
  if (process.platform === "win32") return; // see the file header
  const handle = await open(path, "r");
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

function hashStream(path: string): Promise<{ sha256: string; bytes: number }> {
  return new Promise((resolve, reject) => {
    const hash = createHash("sha256");
    let bytes = 0;
    createReadStream(path)
      .on("data", (chunk: string | Buffer) => {
        const buf = typeof chunk === "string" ? Buffer.from(chunk) : chunk;
        bytes += buf.length;
        hash.update(buf);
      })
      .on("error", reject)
      .on("end", () => resolve({ sha256: hash.digest("hex"), bytes }));
  });
}

/** The real filesystem. */
export const nodeCollectFs: CollectFs = {
  mkdir: async (path) => {
    await mkdir(path, { recursive: true });
  },
  writeFileSync: (path, data) => writeAndSync(path, data, "w"),
  rename: (from, to) => rename(from, to),
  fsyncDir: syncDirectory,
  appendSync: (path, data) => writeAndSync(path, data, "a"),
  truncate: (path, length) => truncate(path, length),
  readFile: (path) => readFile(path),
  readdir: async (path) => {
    try {
      return await readdir(path);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
  },
  exists: async (path) => {
    try {
      await stat(path);
      return true;
    } catch {
      return false;
    }
  },
  hashFile: hashStream,
};

/** SHA-256 hex of bytes in memory. */
export function sha256Hex(data: Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}
