import { realpath } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, relative } from "node:path";

// A path relative to a case's drop/ folder, as the drop-folder machinery passes it around.
//
// It has two producers, and they are not equally trustworthy (#919). The recursive walk in
// composition/dropFolder.ts emits `relative(dropDir, join(dir, entry.name))`, which can only ever
// name a descendant. But `pendingRawInputs[].relpath` in state/drop-status.json is a second
// producer: that file rides inside a whole-case archive and import restores it verbatim, and the
// archive validator checks entry PATHS, never the values inside an entry. So a crafted .dfircase
// controls the list of "raw files awaiting a tool", and POST /cases/:id/drop/run-pending joins
// each relpath onto drop/ and reads, uploads and moves the result.
//
// This is the one rule both consumers apply. It is deliberately narrower than
// isSafeZipEntryPath in caseExportArchive.ts: an archive path must be portable, so that helper
// refuses colons and backslashes outright. A drop relpath only has to stay inside drop/ on the
// machine it is on — a colon is an ordinary Linux filename character (timestamps are common
// names), and on win32 the walk's own output is backslash-separated. Segments are therefore
// split on BOTH separators, so a `..` hidden behind the other platform's separator is still seen.
const SEPARATOR = /[\\/]/;

/** True when `relpath` can only name a descendant of the drop folder it is joined onto. */
export function isSafeDropRelpath(relpath: string): boolean {
  if (!relpath) return false;
  // Absolute on either platform, a UNC path, or a win32 drive prefix (`C:x` is drive-relative
  // and resolves against that drive's current directory, which is never inside drop/).
  if (relpath.startsWith("/") || relpath.startsWith("\\") || /^[A-Za-z]:/.test(relpath)) return false;
  if (relpath.includes("\u0000")) return false;
  return relpath.split(SEPARATOR).every((seg) => seg !== "" && seg !== "." && seg !== "..");
}

/**
 * The absolute path a drop relpath names, bound to the drop folder it belongs to. Throws when the
 * relpath is unsafe (above) OR when the directory that actually holds the file is outside
 * `dropDir` on disk — a relpath whose every segment looks safe can still walk through a symlinked
 * subdirectory, and O_NOFOLLOW on the open only refuses a link at the FINAL component. The parent
 * is resolved with realpath and the file name is joined back on unresolved, so the caller's
 * openNoFollow still sees, and refuses, a link at the file itself. The window between this
 * realpath and that open is the same one the non-O_NOFOLLOW fallback in noFollowRead.ts accepts.
 */
export async function resolveInsideDropDir(dropDir: string, relpath: string): Promise<string> {
  if (!isSafeDropRelpath(relpath)) {
    throw new Error(`refused to read a path outside the drop folder (security): ${relpath}`);
  }
  const target = join(dropDir, relpath);
  const [realDrop, realParent] = await Promise.all([realpath(dropDir), realpath(dirname(target))]);
  const rel = relative(realDrop, realParent);
  if (rel.startsWith("..") || isAbsolute(rel)) {
    throw new Error(`refused to read a path outside the drop folder (security): ${relpath}`);
  }
  return join(realParent, basename(target));
}
