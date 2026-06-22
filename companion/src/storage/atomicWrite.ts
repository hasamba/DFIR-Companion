import { writeFile as fsWriteFile, rename as fsRename, unlink as fsUnlink } from "node:fs/promises";
import { randomUUID } from "node:crypto";

// fs error codes that mean "the file is briefly locked by another process" on Windows. A
// syncing client (Dropbox / OneDrive), antivirus, or the search indexer can hold a file open
// for a few ms exactly when we try to rename over it — so the atomic `rename(tmp → target)`
// throws EPERM/EBUSY/EACCES even though the write itself is fine. Retrying clears it. (This
// bites when DFIR_CASES_ROOT lives inside a synced folder; investigation.json is written
// rapidly during analysis.)
const TRANSIENT_LOCK = new Set(["EPERM", "EBUSY", "EACCES"]);

export interface AtomicWriteDeps {
  writeFile?: (path: string, content: string) => Promise<void>;
  rename?: (from: string, to: string) => Promise<void>;
  unlink?: (path: string) => Promise<void>;
  sleep?: (ms: number) => Promise<void>;
  retries?: number;
}

// Write `content` to `target` atomically: write a temp file, then rename it over the target.
// The rename is retried with a short backoff on a transient Windows lock, so a Dropbox/
// OneDrive-synced cases/ dir doesn't fail analysis with EPERM. A non-transient error (or a
// lock that won't clear within the retry budget) is rethrown.
//
// The temp file gets a UNIQUE name per call (a uuid suffix). Without this, two concurrent
// saves of the same target (e.g. a manual event add saving state while a background
// enrichment/resynthesis also saves the same investigation.json) share one `${target}.tmp`,
// clobber each other's bytes, and leave a corrupted file — valid JSON followed by the tail of
// the other write — which then breaks every endpoint that loads state. A unique tmp means each
// write lands in its own file and the final `rename` replaces the target atomically; the worst
// case is a lost update (last writer wins), never a malformed file.
export async function atomicWrite(target: string, content: string, deps: AtomicWriteDeps = {}): Promise<void> {
  const write = deps.writeFile ?? ((p, c) => fsWriteFile(p, c, "utf8"));
  const rename = deps.rename ?? fsRename;
  const unlink = deps.unlink ?? fsUnlink;
  const sleep = deps.sleep ?? ((ms) => new Promise<void>((r) => setTimeout(r, ms)));
  const retries = deps.retries ?? 10;

  const tmp = `${target}.${randomUUID()}.tmp`;
  await write(tmp, content);
  try {
    for (let attempt = 0; ; attempt++) {
      try {
        await rename(tmp, target);
        return;
      } catch (err) {
        const code = (err as NodeJS.ErrnoException).code ?? "";
        if (attempt >= retries || !TRANSIENT_LOCK.has(code)) throw err;
        await sleep(Math.min(500, 40 * (attempt + 1)));   // linear backoff, capped at 500ms
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
