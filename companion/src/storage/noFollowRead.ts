import { open, lstat, type FileHandle } from "node:fs/promises";
import { constants } from "node:fs";

// Reading a file that a symlink check has just approved is two syscalls, and the gap between them
// belongs to whoever controls the directory. Every path-based guard in this codebase had the same
// shape — lstat the path, decide it is a plain file, then open/readFile/copyFile that path AGAIN —
// so a process able to write into a case directory or a shared drop folder could replace the
// checked file with a symlink in between and have the second call follow it. The payoff is not
// hypothetical: an arbitrary host-readable file gets imported into a case as evidence, sent to an
// AI provider for analysis, or sealed into an encrypted export.
//
// The fix is to stop naming the file twice. Open it ONCE with O_NOFOLLOW, verify the descriptor
// itself with fstat, and read from that same descriptor — the checked object and the read object
// are then the same object by construction, with no window to swap.

/**
 * Whether the platform can refuse to follow a symlink at open() time. POSIX has O_NOFOLLOW; Windows
 * does not, so there the guard degrades to a metadata comparison around the open (below), which
 * narrows the window rather than closing it.
 */
export const NOFOLLOW_SUPPORTED = typeof constants.O_NOFOLLOW === "number";

/**
 * How many times openNoFollow re-opens a file that was replaced between its check and its open.
 * Only the non-O_NOFOLLOW path can see this. A concurrent atomic write loses the race at most once
 * or twice; anything still swapping after this many tries is treated as hostile.
 */
const SWAP_RETRIES = 5;

export type LinkGuardKind = "symlink" | "hardlink";

/**
 * The path was, or became, something other than the plain unshared file it was taken for. Carries
 * WHICH so each caller can phrase it in its own terms (an export refuses to include, the drop
 * folder refuses to read) without matching on message text.
 */
export class LinkGuardError extends Error {
  constructor(
    readonly kind: LinkGuardKind,
    readonly path: string,
  ) {
    super(`${kind} detected at "${path}"`);
    this.name = "LinkGuardError";
  }
}

/**
 * Open `path` for reading, guaranteeing the descriptor refers to a plain file that no symlink was
 * followed to reach and that no other directory entry aliases.
 *
 * Throws LinkGuardError("symlink") if the path is a link, LinkGuardError("hardlink") if the opened
 * file has more than one link. A hardlink is invisible to a symlink check and to readdir alike —
 * only the link count reveals that some other path, anywhere on the same filesystem, names this
 * exact inode. Every file this application writes into a case is nlink === 1.
 *
 * The caller owns the returned handle and must close it.
 */
export async function openNoFollow(path: string): Promise<FileHandle> {
  // An identity mismatch means the file was REPLACED between the check and the open. A symlink
  // swap does that — and so does every ordinary atomic write in this codebase, which writes a temp
  // file and renames it over the target. On the O_NOFOLLOW path `before` is null and the question
  // never arises, so this only ever bit Windows: exporting a case while any sidecar saved reported
  // the analyst's own write as "symlink detected … refusing to include in export (security)".
  //
  // Retrying is safe. The guarantee is that the returned handle's identity matches a pre-check that
  // saw a non-symlink, and each attempt re-establishes both halves of that from scratch. An
  // attacker swapping repeatedly cannot make a mismatched pair look matched; they can only cause
  // more attempts, which the bound below turns into a refusal.
  for (let attempt = 0; ; attempt++) {
    // Without O_NOFOLLOW the pre-check is the only thing that can reject a link that is ALREADY in
    // place; the identity comparison after the open is what catches a swap during it.
    const before = NOFOLLOW_SUPPORTED ? null : await lstat(path);
    if (before?.isSymbolicLink()) throw new LinkGuardError("symlink", path);

    let handle: FileHandle;
    try {
      handle = await open(path, constants.O_RDONLY | (NOFOLLOW_SUPPORTED ? constants.O_NOFOLLOW : 0));
    } catch (err) {
      // ELOOP is precisely "you asked me not to follow a symlink, and it is one".
      if ((err as NodeJS.ErrnoException).code === "ELOOP") throw new LinkGuardError("symlink", path);
      throw err;
    }

    try {
      const opened = await handle.stat();
      if (opened.nlink > 1) throw new LinkGuardError("hardlink", path);
      // Windows fallback: the file the descriptor points at must be the file that was checked.
      // Inode and device are the identity a rename or relink cannot preserve.
      if (before && (before.ino !== opened.ino || before.dev !== opened.dev)) {
        await handle.close().catch(() => {
          /* replaced under us; the retry re-opens from scratch */
        });
        // Persistent churn is indistinguishable from a determined attacker, so refuse rather than
        // spin. A rename loses to the next attempt; only something re-replacing the file on every
        // single try reaches this.
        if (attempt >= SWAP_RETRIES) throw new LinkGuardError("symlink", path);
        continue;
      }
      return handle;
    } catch (err) {
      await handle.close().catch(() => {
        /* the throw below is what the caller needs to see */
      });
      throw err;
    }
  }
}

/** Read a whole file through openNoFollow's guarantees, closing the descriptor either way. */
export async function readFileNoFollow(path: string): Promise<Buffer> {
  const handle = await openNoFollow(path);
  try {
    return await handle.readFile();
  } finally {
    await handle.close();
  }
}

/**
 * Read at most `length` bytes from the start of a file through openNoFollow's guarantees.
 *
 * Used to sniff a file's head without reading a multi-gigabyte evidence file into memory. Returns
 * the bytes actually read, which may be shorter than requested.
 */
export async function readHeadNoFollow(path: string, length: number): Promise<Buffer> {
  const handle = await openNoFollow(path);
  try {
    const buffer = Buffer.alloc(Math.max(0, length));
    if (!buffer.length) return buffer;
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    return buffer.subarray(0, bytesRead);
  } finally {
    await handle.close();
  }
}
