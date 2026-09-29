import type { FileHandle } from "node:fs/promises";
import { decodeImportedText } from "../ingest/decodeText.js";
import { closeTruncatedJsonArray } from "../analysis/extractJson.js";
import { FileTooLargeError, readHandleBounded } from "../storage/boundedRead.js";
import { DEFAULT_MAX_IMPORT_FILE_MB, maxImportFileBytes } from "../analysis/ingest/importFileCap.js";

/**
 * The first look POST /cases/:id/import-file takes at a server-local file, and the one bound on
 * how much of it the route may then hold in memory (#921).
 *
 * The route is the documented escape hatch: the drop folder's oversize message sends a file here,
 * and Plaso super-timelines that cannot be held as a string at all stream through it. So it cannot
 * have a fixed cap. What it had instead was the catch for V8's "Invalid string length" at ~512 MB,
 * and that is not a cap either — a 400 MB file needs a 400 MB Buffer plus a string of up to twice
 * that on the heap, and on a host with a modest --max-old-space-size the heap OOM lands before the
 * string-length error ever throws. A heap OOM is a process crash, not a 413.
 *
 * The cap is a knob the 413 names, so an operator with the memory to spare can raise it — and it
 * is enforced on the descriptor the whole-file read draws from, not on a stat of the path taken
 * earlier (storage/boundedRead.ts): a file swapped or appended to between the two would otherwise
 * be read in full.
 */

/** 256 KB — plenty for the header and many rows of any supported format. */
export const IMPORT_FILE_HEAD_BYTES = 1 << 18;

/**
 * A BOM-aware decoded head sample for kind detection, read from the handle the path guard judged
 * (#1834) — never a re-open of the path. Throws what read throws. The caller closes the handle.
 *
 * A head that cuts a JSON array mid-way is completed to its whole elements HERE, on this path
 * only (#953): the detector is shared with the upload and drop-folder paths, which hand it whole
 * files, and a genuinely malformed whole file must still be refused rather than classified from
 * its one good row and then imported as nothing. See closeTruncatedJsonArray.
 */
export async function sniffImportFileHead(fh: FileHandle): Promise<string> {
  const buf = Buffer.alloc(IMPORT_FILE_HEAD_BYTES);
  const { bytesRead } = await fh.read(buf, 0, buf.length, 0);
  const sample = decodeImportedText(buf.subarray(0, bytesRead));
  return closeTruncatedJsonArray(sample) ?? sample;
}

/**
 * The whole file as text, or the 413 message when it is over the cap. One descriptor — the one the
 * path guard judged (#1834): the size check and the read share it, and the read stops the moment it passes the size it was
 * promised. I/O errors and "Invalid string length" propagate as before. Decoded BOM-aware, the
 * same as the head sample: a UTF-16 CSV was sniffed as csv and then parsed as UTF-8 mojibake.
 */
export async function readImportFileBounded(
  fh: FileHandle,
  kind: string,
  maxBytes = maxImportFileBytes(),
): Promise<{ text: string; tooLarge?: undefined } | { text?: undefined; tooLarge: string }> {
  try {
    return { text: decodeImportedText(await readHandleBounded(fh, maxBytes)) };
  } catch (err) {
    if (err instanceof FileTooLargeError) return { tooLarge: importFileTooLarge(err.size, kind, maxBytes)! };
    throw err;
  }
}

const MB = 1024 * 1024;
// The cap lives beside the importers, which honour it too (#1756); re-exported for existing callers.
export { DEFAULT_MAX_IMPORT_FILE_MB, maxImportFileBytes };

/**
 * The 413 message when a file would have to be held whole and is over the cap; null when it may be
 * read. Plaso is exempt: it streams from disk line by line and never becomes one string.
 */
export function importFileTooLarge(
  size: number,
  kind: string,
  maxBytes = maxImportFileBytes(),
): string | null {
  if (kind === "plaso" || size <= maxBytes) return null;
  return (
    `file is too large to import as ${kind} (${Math.ceil(size / MB)} MB > ${Math.round(maxBytes / MB)} MB) — ` +
    "raise DFIR_MAX_IMPORT_FILE_MB and restart the companion, or split the file; " +
    "only Plaso super-timelines stream and are exempt"
  );
}
