import type { BigIntStats } from "node:fs";
import { lstat, readdir } from "node:fs/promises";
import { join } from "node:path";

/**
 * Does a folder tree hold another name (hard link) for this inode? (#1834)
 *
 * The server-path guard judges an open file by where it lives. A hard link gives one inode two
 * places at once: a case file can be linked out to a harmless-looking folder. For a file with more
 * than one link, the guard asks this about each protected tree. Only then — a multi-link file is
 * rare, so the walk is rare — and only on the same device, since a hard link cannot cross one.
 * Symlinks are not followed: they are names for paths, not for inodes. An unreadable folder is
 * skipped, never a failure.
 */
export async function treeHoldsInode(root: string, st: BigIntStats): Promise<boolean> {
  const top = await lstat(root, { bigint: true }).catch(() => null);
  if (!top || top.dev !== st.dev) return false;
  if (!top.isDirectory()) return top.ino === st.ino;
  const pending = [root];
  while (pending.length > 0) {
    const dir = pending.pop()!;
    const entries = await readdir(dir, { withFileTypes: true }).catch(() => []);
    for (const entry of entries) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) pending.push(path);
      else if (entry.isFile()) {
        const s = await lstat(path, { bigint: true }).catch(() => null);
        if (s && s.dev === st.dev && s.ino === st.ino) return true;
      }
    }
  }
  return false;
}
