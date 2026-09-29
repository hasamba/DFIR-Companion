import type { BigIntStats } from "node:fs";
import { readlink, realpath, stat, type FileHandle } from "node:fs/promises";
import { isAbsolute } from "node:path";

/**
 * Where an OPEN file lives, for a deny-list that must judge the bytes it will read (#1834).
 *
 * A check that resolves a path and then re-opens it reads whatever occupies the path a moment
 * later. So the guard opens first and judges the handle. The handle's inode is fixed; what the
 * deny-list needs besides is the folder that inode sits in, and that is what this answers.
 *
 * - Linux: `/proc/self/fd/<fd>` is the kernel's own name for the open inode — no path lookup, no
 *   race. A name the kernel marks " (deleted)" means the link we opened is gone (a hardlink opened
 *   and then unlinked, leaving only the protected name): null, unless a live file really has that
 *   name and is this inode.
 * - Elsewhere (Windows, macOS, a Linux without /proc): the path we opened must still be canonical
 *   (realpath returns it unchanged) and must still name this inode (dev + ino). A swap of the final
 *   component fails that. Residual: an attacker who toggles an INTERMEDIATE directory between a real
 *   folder and a link in step with open, realpath and stat — Node offers no handle-to-path call on
 *   these platforms. It needs write access to the named path's folders on the Companion host.
 */
const DELETED_SUFFIX = " (deleted)";

async function namesInode(path: string, st: BigIntStats): Promise<boolean> {
  const at = await stat(path, { bigint: true }).catch(() => null);
  return at !== null && at.dev === st.dev && at.ino === st.ino;
}

/** The fallback: `target` (the realpath that was opened) still canonical and still this inode. */
export async function confirmedPath(target: string, st: BigIntStats): Promise<string | null> {
  const again = await realpath(target).catch(() => null);
  if (again !== target) return null;
  return (await namesInode(target, st)) ? target : null;
}

async function procPath(handle: FileHandle): Promise<string | null> {
  if (process.platform !== "linux") return null;
  return readlink(`/proc/self/fd/${handle.fd}`).catch(() => null);
}

/** The path of the open handle's inode, or null when it cannot be pinned (the caller refuses). */
export async function openedPath(handle: FileHandle, target: string, st: BigIntStats): Promise<string | null> {
  const viaProc = await procPath(handle);
  if (viaProc === null) return confirmedPath(target, st);
  if (!isAbsolute(viaProc)) return null;
  if (!viaProc.endsWith(DELETED_SUFFIX)) return viaProc;
  return (await namesInode(viaProc, st)) ? viaProc : null;
}
