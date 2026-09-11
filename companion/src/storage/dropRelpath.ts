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
