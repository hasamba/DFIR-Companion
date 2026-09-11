import { open } from "node:fs/promises";
import { decodeImportedText } from "../ingest/decodeText.js";
import { closeTruncatedJsonArray } from "../analysis/extractJson.js";
import { FileTooLargeError, readHandleBounded } from "../storage/boundedRead.js";

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
 * A BOM-aware decoded head sample for kind detection. Throws what open/read throw.
 *
 * A head that cuts a JSON array mid-way is completed to its whole elements HERE, on this path
 * only (#953): the detector is shared with the upload and drop-folder paths, which hand it whole
 * files, and a genuinely malformed whole file must still be refused rather than classified from
 * its one good row and then imported as nothing. See closeTruncatedJsonArray.
 */
export async function sniffImportFileHead(filePath: string): Promise<string> {
  const fh = await open(filePath, "r");
  try {
    const buf = Buffer.alloc(IMPORT_FILE_HEAD_BYTES);
    const { bytesRead } = await fh.read(buf, 0, buf.length, 0);
    const sample = decodeImportedText(buf.subarray(0, bytesRead));
    return closeTruncatedJsonArray(sample) ?? sample;
  } finally {
    await fh.close();
  }
}

/**
 * The whole file as UTF-8, or the 413 message when it is over the cap. One open: the size check
 * and the read share the descriptor, and the read stops the moment it passes the size it was
 * promised. I/O errors and "Invalid string length" propagate as before.
 */
export async function readImportFileBounded(
  filePath: string,
  kind: string,
  maxBytes = maxImportFileBytes(),
): Promise<{ text: string; tooLarge?: undefined } | { text?: undefined; tooLarge: string }> {
  const fh = await open(filePath, "r");
  try {
    return { text: (await readHandleBounded(fh, maxBytes)).toString("utf8") };
  } catch (err) {
    if (err instanceof FileTooLargeError) return { tooLarge: importFileTooLarge(err.size, kind, maxBytes)! };
    throw err;
  } finally {
    await fh.close();
  }
}

const MB = 1024 * 1024;
/** Matches DFIR_MAX_BODY_MB's default, so the two whole-file ceilings show an operator one number. */
export const DEFAULT_MAX_IMPORT_FILE_MB = 256;

/** DFIR_MAX_IMPORT_FILE_MB in bytes. Garbage, zero, negative or infinite falls back to the default:
 *  a negative cap would refuse every import, an infinite one would disable the protection, and
 *  both strings pass Number() and the generic settings validation. */
export function maxImportFileBytes(env: NodeJS.ProcessEnv = process.env): number {
  const n = Number(env.DFIR_MAX_IMPORT_FILE_MB);
  return (Number.isFinite(n) && n > 0 ? n : DEFAULT_MAX_IMPORT_FILE_MB) * MB;
}

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
