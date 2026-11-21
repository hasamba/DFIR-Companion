/**
 * The drop folder's whole-file read for a text file under DFIR_DROP_MAX_BYTES (#2785).
 *
 * A file under the cap is read and decoded whole before its import takes the case's import section
 * (composition/dropFolder.ts). That read, and the parse right after it, are where a large file runs
 * the server out of memory — and the crash-loop guard (composition/dropInFlight.ts, #2713) counted a
 * start only once the section was granted, so a server that died there left no marker and died on
 * the same file at every start. For a LARGE file this module therefore:
 *
 * 1. asks the import memory guard first (analysis/importMemoryGuard.ts — the same estimate the
 *    upload path uses), and releases the reservation at once: the import's own admission inside its
 *    section is what holds one, and holding this one too would count the file twice. A refusal
 *    throws, and the sweep moves the file to `_failed/` with the guard's reason, unread.
 * 2. counts the import attempt's start BEFORE the read (analysis/importAttempt.ts), so a crash
 *    during the read or the parse counts toward the guard's limit and the file goes to `_failed/`.
 *
 * Small files keep the #2713 rule (counted when granted the section), so a small file still waiting
 * behind another one is never blamed for the other one's crash. Two LARGE files read at once in one
 * sweep can still share the blame for a crash — accepted: both are candidates for it.
 *
 * The guard's estimate is capped by DFIR_MAX_EVENTS, so on a small case it seldom refuses a single
 * file; step 2 is what stops the loop.
 */
import { decodeImportedText } from "../ingest/decodeText.js";
import { noteImportSectionStart } from "../analysis/importAttempt.js";
import type { ImportAdmissionHint, RefusalWording } from "../analysis/importMemoryGuard.js";
import { openNoFollow } from "../storage/noFollowRead.js";
import { readHandleBounded } from "../storage/boundedRead.js";

/**
 * At or above this size a dropped text file counts its start before it is read. Low enough that any
 * file able to exhaust a server's heap while read whole and parsed (a parse peaks at many times the
 * file's size) is covered; high enough that the common small file keeps the queue-safe rule.
 */
export const DROP_EARLY_MARK_BYTES = 16 * 1024 * 1024;

const REFUSAL_WORDING: RefusalWording = {
  saved: "The file was not read; it is in the drop folder's _failed folder",
  retry: "move it back into the drop folder, or use Import-from-path",
};

// The ONE whole-file read for every branch of processDropFile. The cap travels with the descriptor:
// opened O_NOFOLLOW, sized by fstat on that same handle, and the read stops one byte past the
// promised size (storage/boundedRead.ts). The listing stat's `isOversize` gate stays as the cheap
// early skip, but it is only a check on what the sweep saw — a file that grew, or was swapped for a
// larger one, between the listing and this read was read in full by the old path-based
// `readFileNoFollow` (#1329, the #947 check-then-read shape). Throws FileTooLargeError, which each
// caller phrases in its own terms.
export async function readDropFileBounded(fullPath: string, maxBytes: number): Promise<Buffer> {
  const handle = await openNoFollow(fullPath);
  try {
    return await readHandleBounded(handle, maxBytes);
  } finally {
    await handle.close();
  }
}

export interface DropWholeReadDeps {
  maxBytes: number;
  /** DROP_EARLY_MARK_BYTES unless a test injects a smaller one. */
  earlyMarkBytes?: number;
  /** The import memory guard, admitted without taking the case's section; absent → not asked. */
  admit?: (caseId: string, hint: ImportAdmissionHint) => Promise<() => void>;
  read?: (fullPath: string, maxBytes: number) => Promise<Buffer>;
}

/** Read one under-cap drop file as text: (caseId, full path, listed size) → decoded text. */
export function createDropWholeReader(
  deps: DropWholeReadDeps,
): (caseId: string, fullPath: string, size: number) => Promise<string> {
  const earlyMarkBytes = deps.earlyMarkBytes ?? DROP_EARLY_MARK_BYTES;
  const read = deps.read ?? readDropFileBounded;
  return async (caseId, fullPath, size) => {
    if (size >= earlyMarkBytes) {
      if (deps.admit) {
        const release = await deps.admit(caseId, { incomingBytes: size, wording: REFUSAL_WORDING });
        release();
      }
      await noteImportSectionStart();
    }
    // BOM-aware: a Report.wer is UTF-16LE, and utf8 turns it into NUL-interleaved mojibake.
    return decodeImportedText(await read(fullPath, deps.maxBytes));
  };
}
