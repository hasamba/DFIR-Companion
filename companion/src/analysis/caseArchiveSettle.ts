import { warnLine } from "../logging/serverLogger.js";

// A whole-case archive (ZIP archive, ZIP/encrypted delete, encrypted export) walks the case folder
// and then reads every file it listed. The app keeps writing to a case in the background while that
// happens — an auto-enrichment run after an IOC add records its analysis run, and that record puts
// down state/analysis-runs/pending.json and removes it again a moment later (#2784). A file listed
// by the walk and gone by the read used to take the whole archive down with a raw ENOENT 500.
//
// Such a file is NOT skipped. pending.json is the analysis-run ledger's crash marker, and other
// files that come and go (drop-folder moves, batch markers) are case content too: an archive that
// quietly leaves out a file it listed is the one outcome a forensic archive must never produce.
// Instead the whole archive is built again from a fresh walk — the walk, the database snapshot and
// every read — so each attempt is one consistent view of the folder. The same applies to a file that
// APPEARS while the files are read (the analysis-run record also writes a new manifest and moves the
// ledger head): a second walk after the reads must list exactly what was packaged, or it is built
// again. Only when the folder never settles within the attempts does the archive fail, and then with
// a message that names the file and says what to do — never a bare filesystem error.
//
// Every attempt is verified, the last one included (#2801). The final attempt used to return without
// its re-walk, so a file written during the last build was missing from the archive — and a ZIP or
// encrypted delete then removed the case. A last build whose folder changed now fails retryably.

/** How many times an archive is built before a folder that keeps changing fails it. */
export const ARCHIVE_SETTLE_ATTEMPTS = 3;

/** How a file changed while the case was packaged. */
export type CaseFileChange = "disappeared" | "appeared";

/** A file the walk listed was gone when it was read — or the folder's file set changed by the end. */
export class CaseFileVanishedError extends Error {
  readonly code = "DFIR_CASE_FILE_VANISHED";
  /** A retry-later condition, not a server fault (#2795): routes answer it 503 with this message. */
  readonly httpStatus = 503;
  constructor(
    readonly rel: string,
    readonly change: CaseFileChange = "disappeared",
  ) {
    super(
      `"${rel}" ${change} while the case was being packaged — something is still writing to ` +
        `this case. Let it finish (or close the case) and try again.`,
    );
    this.name = "CaseFileVanishedError";
  }
}

/** For a `.catch` on the read of a listed file: ENOENT becomes CaseFileVanishedError, anything else
 *  is rethrown untouched. */
export function vanishedAs(rel: string): (err: unknown) => never {
  return (err: unknown) => {
    if ((err as NodeJS.ErrnoException | null)?.code === "ENOENT") throw new CaseFileVanishedError(rel);
    throw err;
  };
}

export interface SettledBuild<T> {
  value: T;
  /** The case-relative paths this build packaged. */
  relPaths: readonly string[];
}

/** The first path in one list and not the other, or null when both name the same files. */
function firstDifference(packaged: readonly string[], now: readonly string[]): CaseFileVanishedError | null {
  const before = new Set(packaged);
  const after = new Set(now);
  for (const p of after) if (!before.has(p)) return new CaseFileVanishedError(p, "appeared");
  for (const p of before) if (!after.has(p)) return new CaseFileVanishedError(p, "disappeared");
  return null;
}

/** The change `rewalk` finds against what a build packaged, or null when the folder held still. */
async function changeSince(
  packaged: readonly string[],
  rewalk: () => Promise<readonly string[]>,
): Promise<CaseFileVanishedError | null> {
  return rewalk().then(
    (now) => firstDifference(packaged, now),
    (err: unknown) => {
      if (err instanceof CaseFileVanishedError) return err;
      throw err;
    },
  );
}

/**
 * Run `build` until it packages a folder that held still: no listed file vanished during it, and
 * `rewalk` afterwards lists exactly what it packaged. Every attempt is re-walked, the last one too: a
 * file that vanished or appeared during the last attempt throws a CaseFileVanishedError (503, retry
 * later) and nothing is returned, so no caller deletes a case on an unverified archive (#2801). Any
 * other error ends it at once.
 */
export async function buildFromSettledCase<T>(
  label: string,
  build: () => Promise<SettledBuild<T>>,
  rewalk: () => Promise<readonly string[]>,
  attempts: number = ARCHIVE_SETTLE_ATTEMPTS,
): Promise<T> {
  for (let attempt = 1; ; attempt++) {
    let built: SettledBuild<T>;
    try {
      built = await build();
    } catch (err) {
      if (!(err instanceof CaseFileVanishedError) || attempt >= attempts) throw err;
      warnLine(`${label} "${err.rel}" disappeared mid-build — building again (attempt ${attempt + 1})`);
      continue;
    }
    const changed = await changeSince(built.relPaths, rewalk);
    if (changed === null) return built.value;
    if (attempt >= attempts) throw changed;
    warnLine(
      `${label} "${changed.rel}" ${changed.change} mid-build — building again (attempt ${attempt + 1})`,
    );
  }
}
