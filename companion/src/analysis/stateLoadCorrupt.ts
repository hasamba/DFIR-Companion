import { getServerLogger } from "../logging/serverLogger.js";
import { StateFileCorruptError } from "../storage/stateFileCorrupt.js";

/**
 * A damaged investigation.json or case SQLite store (#2783). Before this, GET /cases/:id/state
 * answered 500 with the bare parser or sqlite text ("Unexpected end of JSON input", "file is not a
 * database"), naming neither the case nor the file. The same treatment #2760 gave the other state
 * files: a StateFileCorruptError naming the case and the file.
 *
 * The analyst-facing reason is FIXED text. The raw parser/sqlite message is logged server-side only.
 */

/**
 * The case's indexed store and its pre-SQLite legacy file, inside the case's state folder. The same
 * names as stateStore.ts's INVESTIGATION_DB_FILENAME / LEGACY_STATE_FILENAME (that file is at its
 * size limit, so it keeps its own literals rather than importing these).
 */
const STATE_SQLITE_FILE = "investigation.sqlite";
const LEGACY_STATE_JSON_FILE = "investigation.json";

/**
 * Where a failed read was: `migrate` opens the store and, when there is none yet, parses the
 * legacy JSON file; `read` reads the store's own rows.
 */
export type StateLoadPhase = "migrate" | "read";

const CONSEQUENCE = "The case cannot be opened until the file is restored from a backup.";

/** Messages node:sqlite raises for a file that is not, or is no longer, a readable database. */
const SQLITE_DAMAGE = /file is not a database|database disk image is malformed|malformed database schema/i;

function isJsonDamage(err: unknown): boolean {
  return err instanceof Error && err.name === "SyntaxError";
}

function isSqliteDamage(err: unknown): boolean {
  return err instanceof Error && SQLITE_DAMAGE.test(err.message);
}

/** Which file `err` says is damaged, or null when it is some other failure. */
function damagedFile(err: unknown, phase: StateLoadPhase): string | null {
  if (isSqliteDamage(err)) return STATE_SQLITE_FILE;
  // While migrating, the only JSON parsed is the legacy file; on a read it is a stored row payload.
  if (isJsonDamage(err)) return phase === "migrate" ? LEGACY_STATE_JSON_FILE : STATE_SQLITE_FILE;
  return null;
}

/**
 * The StateFileCorruptError for `err` when it means a state file is damaged; otherwise `err`
 * unchanged, so every other failure keeps its own handling.
 */
export function asStateLoadCorruption(err: unknown, caseId: string, phase: StateLoadPhase): unknown {
  if (err instanceof StateFileCorruptError) return err;
  const file = damagedFile(err, phase);
  if (!file) return err;
  getServerLogger().warn(`case "${caseId}": state/${file} is damaged: ${(err as Error).message}`);
  const reason = file === STATE_SQLITE_FILE ? "it is not a readable SQLite database" : "it is not valid JSON";
  return new StateFileCorruptError(caseId, file, CONSEQUENCE, reason);
}

/** `read`, with a damaged store's failure mapped to StateFileCorruptError. */
export async function readingStateStore<T>(caseId: string, read: Promise<T>): Promise<T> {
  try {
    return await read;
  } catch (err) {
    throw asStateLoadCorruption(err, caseId, "read");
  }
}
