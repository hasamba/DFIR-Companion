import { writeFile as fsWriteFile, rename as fsRename, unlink as fsUnlink } from "node:fs/promises";
import { randomUUID } from "node:crypto";

// fs error codes that mean "the file is briefly locked by another process" on Windows. A
// syncing client (Dropbox / OneDrive), antivirus, or the search indexer can hold a file open
// for a few ms exactly when we try to rename over it — so the atomic `rename(tmp → target)`
// throws EPERM/EBUSY/EACCES even though the write itself is fine. Retrying clears it. (This
// bites when DFIR_CASES_ROOT lives inside a synced folder and JSON sidecars are written rapidly.)
const TRANSIENT_LOCK = new Set(["EPERM", "EBUSY", "EACCES"]);

// How many times to retry the rename before giving up. The backoff is linear and capped at
// BACKOFF_CAP_MS, so the default 20 retries ≈ 8.4s of total wait — enough to ride out a Defender
// real-time scan or search-indexer handle on a large sidecar can outlast a short retry budget.
// Operators
// on especially aggressive AV / slow disks can raise it via DFIR_ATOMIC_WRITE_RETRIES.
const DEFAULT_RETRIES = 20;
const BACKOFF_CAP_MS = 1000;

// Retry count from DFIR_ATOMIC_WRITE_RETRIES (positive integer), else DEFAULT_RETRIES. An unset,
// zero, negative, or unparseable value keeps the default so a typo can't silently disable retries.
export function atomicWriteRetries(): number {
  const n = Number(process.env.DFIR_ATOMIC_WRITE_RETRIES);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : DEFAULT_RETRIES;
}

// The suffix appended to build the temp file, and the pattern that recognizes one again. These are
// deliberately adjacent: the whole-case export walks the case directory while the app is still
// writing to it, and has to tell "a write is in flight" apart from "this is case content". If the
// two ever drift, the export goes back to tripping over temp files (see caseExportArchive.ts).
//
// The pattern matches ONLY the uuid-suffixed shape below, never a bare ".tmp". A case directory
// holds evidence an analyst imported, and a malware sample named "payload.tmp" is entirely
// ordinary — dropping it from an archive because of its extension is exactly the silent evidence
// loss a forensic export must never produce.
const TEMP_SUFFIX_PATTERN = /\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.tmp$/i;

function tempPathFor(target: string): string {
  return `${target}.${randomUUID()}.tmp`;
}

/** True when `path` is a temp file atomicWrite created — a write in progress, not case content. */
export function isAtomicWriteTempPath(path: string): boolean {
  return TEMP_SUFFIX_PATTERN.test(path);
}

export interface AtomicWriteDeps {
  writeFile?: (path: string, content: string | Uint8Array) => Promise<void>;
  rename?: (from: string, to: string) => Promise<void>;
  unlink?: (path: string) => Promise<void>;
  sleep?: (ms: number) => Promise<void>;
  retries?: number;
  // Called once with the number of retries used when a write only succeeded after retrying, so the
  // server can surface a "state dir is contended (AV/indexer?)" warning. Never called on first-try
  // success or on final failure (that path throws). Best-effort: exceptions here are ignored.
  onRetry?: (attempts: number) => void;
}

// Write `content` to `target` atomically: write a temp file, then rename it over the target.
// The rename is retried with a short backoff on a transient Windows lock, so a Dropbox/
// OneDrive-synced cases/ dir doesn't fail analysis with EPERM. A non-transient error (or a
// lock that won't clear within the retry budget) is rethrown.
//
// The temp file gets a UNIQUE name per call (a uuid suffix). Without this, two concurrent
// saves of the same JSON sidecar share one `${target}.tmp`,
// clobber each other's bytes, and leave a corrupted file — valid JSON followed by the tail of
// the other write — which then breaks every endpoint that loads state. A unique tmp means each
// write lands in its own file and the final `rename` replaces the target atomically; the worst
// case is a lost update (last writer wins), never a malformed file.
export async function atomicWrite(
  target: string,
  content: string | Uint8Array,
  deps: AtomicWriteDeps = {},
): Promise<void> {
  const write =
    deps.writeFile ?? ((p, c) => (typeof c === "string" ? fsWriteFile(p, c, "utf8") : fsWriteFile(p, c)));
  const rename = deps.rename ?? fsRename;
  const unlink = deps.unlink ?? fsUnlink;
  const sleep = deps.sleep ?? ((ms) => new Promise<void>((r) => setTimeout(r, ms)));
  const retries = deps.retries ?? atomicWriteRetries();

  const tmp = tempPathFor(target);
  await write(tmp, content);
  try {
    for (let attempt = 0; ; attempt++) {
      try {
        await rename(tmp, target);
        if (attempt > 0) {
          try {
            deps.onRetry?.(attempt);
          } catch {
            /* observability is best-effort */
          }
        }
        return;
      } catch (err) {
        const code = (err as NodeJS.ErrnoException).code ?? "";
        if (attempt >= retries || !TRANSIENT_LOCK.has(code)) throw err;
        await sleep(Math.min(BACKOFF_CAP_MS, 40 * (attempt + 1))); // linear backoff, capped at 1s
      }
    }
  } catch (err) {
    // Best-effort cleanup of the now-orphaned temp file so failed writes don't litter the
    // state dir. Ignore ENOENT — the rename may have partially succeeded or another caller
    // already cleaned up.
    await unlink(tmp).catch(() => {});
    throw err;
  }
}
