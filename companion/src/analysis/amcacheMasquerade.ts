// The name an Amcache entry wears against the name compiled into it.
//
// An Amcache row carries both: `EntryName` is what the file was called on disk, `OriginalFileName`
// is what its version resource says it is. DetectRaptor's Amcache pack grades on the first — it
// recognises `RustDesk.exe` as remote-access tooling and calls it Medium — and never compares the
// two. So a row reading
//
//     EntryName          RustDesk.exe
//     OriginalFileName   notepad.exe
//     Publisher          microsoft corporation
//
// lands as an ordinary "an RMM tool is installed" note, with the part that makes it interesting
// dropped on the floor.
//
// binaryRenameImport already reasons about exactly this mismatch, and never sees an Amcache row:
// the row arrives carrying a `Detection` verdict, so classify() routes it to the detection mapper
// long before the Amcache branch is reached. Rather than move that routing — the verdict SHOULD
// lead, and the rule pack's grade should still be consumed — this module supplies the one fact the
// pack did not look at, and the detection mapper folds it in.

import { getCI, str } from "./siemImport.js";

type Row = Record<string, unknown>;

export interface AmcacheMasquerade {
  /** The name the file wore on disk, verbatim — the spelling the analyst will search for. */
  onDisk: string;
  /** The name its version resource claims, verbatim. */
  original: string;
}

// Reduce either spelling to a bare lowercase filename, so "RUSTDESK.EXE" and "RustDesk.exe" compare
// equal and a path-bearing OriginalFileName reduces to its leaf. Mirrors binaryRenameImport's
// leafName: the two modules must agree on what "the same name" means, or one will report a rename
// the other denies. `split` always returns a non-empty array, so the last element cannot be
// undefined.
function leafName(value: string): string {
  const parts = value.trim().replace(/["']/g, "").split(/[\\/]/);
  return parts[parts.length - 1].trim().toLowerCase();
}

/**
 * The mismatch, or null when there is none to report.
 *
 * Both names must be present. A missing version resource proves nothing either way — plenty of
 * legitimate binaries ship without one, and treating absence as evidence would fire on all of them.
 *
 * A mismatch alone is the finding; no publisher or path condition narrows it further. Renamed
 * installers do exist, so this would be too loose as a standalone sweep — but it never runs as one.
 * It only ever refines a row a detection pack has ALREADY singled out, which on a real collection
 * was three rows on the whole machine.
 */
export function amcacheMasquerade(row: Row): AmcacheMasquerade | null {
  const onDisk = str(getCI(row, "EntryName")).trim();
  const original = str(getCI(row, "OriginalFileName")).trim();
  if (!onDisk || !original) return null;
  if (leafName(onDisk) === leafName(original)) return null;
  return { onDisk, original };
}
