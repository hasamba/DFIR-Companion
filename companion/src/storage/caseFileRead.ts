import { createHash } from "node:crypto";
import { constants, createWriteStream, type BigIntStats } from "node:fs";
import { lstat, open, readlink, realpath, rm, stat, type FileHandle } from "node:fs/promises";
import { isAbsolute, join, relative, sep } from "node:path";
import { Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import type { GuardedFile } from "./serverPathGuard.js";
import { createStagingDir } from "./exportStaging.js";

/**
 * Reading a case's OWN file for something that leaves the host or the case (#1846, #1847): an
 * archive, an export, a download, a screenshot sent to an AI provider, an SCP delivery.
 *
 * Reading by name reads whatever occupies the name at that moment. Whoever can write inside the case
 * folder can swap the name — or a folder above it — for a link to another case's file or to the
 * Companion's configuration, and the bytes that ship are not the case's. A FIFO at the name blocks
 * `open()` forever. So the file is opened ONCE (O_NOFOLLOW, O_NONBLOCK), the open handle is judged,
 * and the caller reads that handle and nothing else — the mechanism of the server-path guard
 * (storage/serverPathGuard.ts, #1834). The rule is stricter than that guard's deny-list: the open
 * inode must be a plain, single-link, regular file whose real path is exactly
 * `<real case folder>/<rel>` — no link anywhere below the case folder, and the case folder itself not
 * a link out of the cases root.
 *
 * Why not openServerPath itself: its deny-list is for operator-named host paths, and it refuses a file
 * that is replaced right after the open (409). A live case replaces its sidecars constantly (atomic
 * saves rename over them), so an export of a case in use would fail. Here a replaced file is fine
 * when the kernel shows its last name was exactly the expected path and it has no other name left.
 *
 * On Linux the handle's path comes from /proc and has no race. Elsewhere the path is re-resolved and
 * compared by identity, with the guard's stated residual (an intermediate folder toggled in step with
 * the syscalls).
 */

export interface CaseScope {
  casesRoot: string;
  /** The case folder (archive-aware, e.g. CaseStore.caseDir). */
  caseDir: string;
}

export type CaseFileRefusalKind = "symlink" | "hardlink" | "special file" | "changed file" | "protected file";

/** The file is not one this case may ship. `kind` lets each caller phrase it; `path` is the name asked for. */
export class CaseFileRefusedError extends Error {
  constructor(
    readonly kind: CaseFileRefusalKind,
    readonly path: string,
    readonly reason: string,
  ) {
    super(`${kind} detected at "${path}" — ${reason}`);
    this.name = "CaseFileRefusedError";
  }
}

// A rename can land between the syscalls; an ordinary save loses the race once or twice. Anything
// still changing after this many tries is treated as hostile.
const CHANGE_RETRIES = 5;
const DELETED_SUFFIX = " (deleted)";

// Only where the platform defines them (Windows has neither).
const optionalFlag = (name: string): number => (constants as Record<string, number | undefined>)[name] ?? 0;
const OPEN_FLAGS = constants.O_RDONLY | optionalFlag("O_NOFOLLOW") | optionalFlag("O_NONBLOCK");

// Windows only. macOS volumes can be case-sensitive, where c1 and C1 are two cases; folding there would
// let a link from one to the other pass. Every path compared here is built from on-disk names.
const CASE_INSENSITIVE = process.platform === "win32";
const norm = (p: string): string => (CASE_INSENSITIVE ? p.toLowerCase() : p);

function relInside(root: string, p: string): string | null {
  const rel = relative(root, p);
  if (rel === "" || rel.startsWith("..") || isAbsolute(rel)) return null;
  return rel;
}

const refuse = (kind: CaseFileRefusalKind, path: string, reason: string): never => {
  throw new CaseFileRefusedError(kind, path, reason);
};

async function preCheck(absPath: string): Promise<void> {
  const st = await lstat(absPath);
  if (st.isSymbolicLink()) refuse("symlink", absPath, "the name is a link");
  if (st.isFile() && st.nlink > 1) refuse("hardlink", absPath, "the file has a second name elsewhere");
  if (!st.isFile()) refuse("special file", absPath, "not a regular file");
}

/** Where the file must really be: `<real case folder>/<rel>`, the case folder not a link out of the cases root. */
async function expectedRealPath(scope: CaseScope, absPath: string, rel: string): Promise<string> {
  const realRoot = await realpath(scope.casesRoot);
  const realCase = await realpath(scope.caseDir);
  const caseRel = relInside(scope.casesRoot, scope.caseDir);
  if (caseRel === null || norm(realCase) !== norm(join(realRoot, caseRel)))
    refuse("symlink", absPath, "the case folder is a link");
  const expected = join(realCase, rel);
  if (norm(await realpath(absPath)) !== norm(expected))
    refuse("symlink", absPath, "a folder on the way to the file is a link");
  return expected;
}

/** Whether the open handle is the inode at `expected`, judged without a second lookup where possible. */
async function handleIsAt(handle: FileHandle, expected: string, st: BigIntStats): Promise<boolean> {
  if (process.platform === "linux") {
    const at = await readlink(`/proc/self/fd/${handle.fd}`).catch(() => null);
    if (at !== null) {
      if (at === expected) return true;
      if (!at.endsWith(DELETED_SUFFIX) || at.slice(0, -DELETED_SUFFIX.length) !== expected) return false;
      // Replaced after the open (an atomic save): its last name was the expected path, and with no
      // name left anywhere it cannot be a second name for someone else's file.
      return (await handle.stat({ bigint: true })).nlink === 0n;
    }
  }
  const again = await realpath(expected).catch(() => null);
  if (again === null || norm(again) !== norm(expected)) return false;
  // lstat, not stat: a final component swapped to a link to the open inode must not match.
  const named = await lstat(expected, { bigint: true }).catch(() => null);
  return named !== null && named.dev === st.dev && named.ino === st.ino;
}

async function attempt(scope: CaseScope, absPath: string, rel: string): Promise<GuardedFile | null> {
  await preCheck(absPath);
  const expected = await expectedRealPath(scope, absPath, rel);
  // Never open a device or a FIFO in the ordinary case; the fstat below covers a swap after this.
  if (!(await stat(expected)).isFile()) refuse("special file", absPath, "not a regular file");
  let handle: FileHandle;
  try {
    handle = await open(expected, OPEN_FLAGS);
  } catch (err) {
    // ELOOP: the final component became a link after the checks above.
    if ((err as NodeJS.ErrnoException).code === "ELOOP") return null;
    throw err;
  }
  try {
    const st = await handle.stat({ bigint: true });
    if (!st.isFile()) refuse("special file", absPath, "not a regular file");
    if (st.nlink > 1n) refuse("hardlink", absPath, "the file has a second name elsewhere");
    if (await handleIsAt(handle, expected, st)) return { handle, realPath: expected, stat: st };
    await handle.close();
    return null;
  } catch (err) {
    await handle.close().catch(() => undefined);
    throw err;
  }
}

/**
 * Open a file inside `scope.caseDir` for reading, judged on the open handle. Throws
 * CaseFileRefusedError when the file may not ship, or the fs error (ENOENT for a missing file). The
 * caller owns the handle and closes it.
 */
export async function openCaseFile(scope: CaseScope, absPath: string): Promise<GuardedFile> {
  const rel = relInside(scope.caseDir, absPath);
  if (rel === null) refuse("protected file", absPath, "the path is outside the case folder");
  for (let tries = 0; ; tries++) {
    const file = await attempt(scope, absPath, rel as string);
    if (file) return file;
    if (tries >= CHANGE_RETRIES)
      refuse("changed file", absPath, "the file kept changing while it was being checked");
  }
}

/** The whole file, read from the judged handle. */
export async function readCaseFile(scope: CaseScope, absPath: string): Promise<Buffer> {
  const file = await openCaseFile(scope, absPath);
  try {
    return await file.handle.readFile();
  } finally {
    await file.handle.close();
  }
}

/** The last `maxBytes` of a case file (a log) and its full size, from the judged handle. */
export async function readCaseFileTail(
  scope: CaseScope,
  absPath: string,
  maxBytes: number,
): Promise<{ bytes: Buffer; size: number }> {
  const file = await openCaseFile(scope, absPath);
  try {
    const size = Number(file.stat.size);
    const length = Math.min(size, Math.max(0, maxBytes));
    const bytes = Buffer.alloc(length);
    if (length > 0) await file.handle.read(bytes, 0, length, size - length);
    return { bytes, size };
  } finally {
    await file.handle.close();
  }
}

export interface CaseFileSnapshot {
  /** A private copy of the judged bytes. Hand THIS path to an external program, never the case path. */
  path: string;
  bytes: number;
  sha256: string;
  /** The permission bits of the file that was copied — read from the checked handle, not the name. */
  mode: number;
  /**
   * Removes the copy and its folder, retrying a locked file (antivirus, sync clients). Never throws:
   * resolves with what is left behind and why, or null when it is gone — the caller logs it.
   */
  dispose: () => Promise<string | null>;
}

/**
 * Copy a judged case file into a private folder under `stagingRoot` so a program that opens files by
 * name (scp) reads bytes this process has checked. The copy is bounded to the size the handle had at
 * open: a writer appending to the inode cannot grow it, and a file that shrinks mid-copy fails.
 */
export async function snapshotCaseFile(
  scope: CaseScope,
  absPath: string,
  stagingRoot: string,
  opts: { signal?: AbortSignal; name?: string } = {},
): Promise<CaseFileSnapshot> {
  const file = await openCaseFile(scope, absPath);
  let dir: string | undefined;
  const dispose = async (): Promise<string | null> => {
    if (!dir) return null;
    const at = dir;
    return rm(at, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }).then(
      () => null,
      (err: unknown) => `${at}: ${(err as Error).message}`,
    );
  };
  try {
    dir = await createStagingDir(stagingRoot, "delivery-");
    const path = join(dir, (opts.name ?? "evidence.dat").split(sep).join("_"));
    const size = Number(file.stat.size);
    const hash = createHash("sha256");
    let copied = 0;
    const tap = new Transform({
      transform(chunk: Buffer, _enc, done) {
        hash.update(chunk);
        copied += chunk.length;
        done(null, chunk);
      },
    });
    const source =
      size > 0
        ? file.handle.createReadStream({ start: 0, end: size - 1, autoClose: false, highWaterMark: 1 << 20 })
        : null;
    const sink = createWriteStream(path, { flags: "wx", mode: 0o600 });
    if (source) await pipeline(source, tap, sink, opts.signal ? { signal: opts.signal } : {});
    else
      await new Promise<void>((resolve, reject) =>
        sink.end((err?: Error | null) => (err ? reject(err) : resolve())),
      );
    if (copied !== size) {
      throw new CaseFileRefusedError("changed file", absPath, "the file shrank while it was being copied");
    }
    return { path, bytes: copied, sha256: hash.digest("hex"), mode: Number(file.stat.mode) & 0o777, dispose };
  } catch (err) {
    await dispose();
    throw err;
  } finally {
    await file.handle.close().catch(() => undefined);
  }
}

/**
 * Run `work` — something that opens `absPath` by name, like the SQLite worker's snapshot — while this
 * process holds the judged handle, then judge the name again: both opens must pass and be the same
 * inode. A swap to a link or to another file before or after the work fails the export. Residual: a
 * swap away and back again entirely inside `work`; SQLite offers no open-by-handle.
 */
export async function withPinnedCaseFile<T>(
  scope: CaseScope,
  absPath: string,
  work: () => Promise<T>,
): Promise<T> {
  const missingAsNull = (err: unknown): null => {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw err;
  };
  const before = await openCaseFile(scope, absPath).catch(missingAsNull);
  try {
    const out = await work();
    const after = await openCaseFile(scope, absPath).catch(missingAsNull);
    await after?.handle.close().catch(() => undefined);
    const same =
      before === null
        ? after === null
        : after !== null && after.stat.dev === before.stat.dev && after.stat.ino === before.stat.ino;
    if (!same)
      throw new CaseFileRefusedError(
        "changed file",
        absPath,
        "the file was replaced while it was being read",
      );
    return out;
  } finally {
    await before?.handle.close().catch(() => undefined);
  }
}
