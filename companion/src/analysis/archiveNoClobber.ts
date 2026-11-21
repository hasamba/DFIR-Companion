// Archive copies written into the cases root are never replaced (#2787). The server-side copy an
// encrypted delete saves — and the ZIP an archive or a ZIP delete writes — can be the only copy of a
// case that no longer exists on disk. A later delete or archive of a case with the same id and name
// used to rename its file over the earlier one; now it takes the next free " (n)" name.
//
// The callers delete the case right after this returns, so the copy must be DURABLE first (#2800):
// the temp file is fsynced before it is published, a copied file is fsynced again, and the folder is
// fsynced so the new name survives a power loss or OS crash too. A sync that fails fails the write —
// the published name is removed and the caller keeps the case.
import { constants } from "node:fs";
import { copyFile, link, open, unlink } from "node:fs/promises";
import { join } from "node:path";
import { randomUUID } from "node:crypto";

/** Give up after this many taken names rather than loop forever on a broken folder. */
export const MAX_ARCHIVE_COPY_NUMBER = 1000;

// Hard links are not available on every filesystem (FAT/exFAT, some network shares and container
// volumes). There an exclusive copy takes their place: still never replaces an existing file.
const NO_HARDLINK_CODES = new Set(["EPERM", "ENOTSUP", "EOPNOTSUPP", "ENOSYS", "EXDEV"]);

/**
 * The file-name suffix for copy number `n`: the first copy keeps `suffix` unchanged; later ones get
 * " (n)" before the extension — ".dfircase" → " (2).dfircase", " (no password).zip" →
 * " (no password) (2).zip". Passed to caseNamedFilename, so the UTF-8 byte cap still holds.
 */
export function copyNumberedSuffix(suffix: string, n: number): string {
  if (n <= 1) return suffix;
  const dot = suffix.lastIndexOf(".");
  const stem = dot >= 0 ? suffix.slice(0, dot) : suffix;
  const ext = dot >= 0 ? suffix.slice(dot) : "";
  return `${stem} (${n})${ext}`;
}

function errCode(err: unknown): string | undefined {
  return (err as NodeJS.ErrnoException | undefined)?.code;
}

// A folder fsync some platforms refuse: Windows cannot open a directory for writing (EPERM/EISDIR)
// and some filesystems reject fsync on one (EINVAL, ENOTSUP). There the folder sync is best effort —
// the file itself is already synced, and nothing more can be done from Node. Any other error fails.
const NO_DIR_FSYNC_CODES = new Set(["EPERM", "EISDIR", "EINVAL", "ENOTSUP", "EOPNOTSUPP"]);

async function syncPath(path: string, flags: string): Promise<void> {
  const fh = await open(path, flags);
  try {
    await fh.sync();
  } finally {
    await fh.close();
  }
}

async function syncDir(dir: string): Promise<void> {
  try {
    await syncPath(dir, "r");
  } catch (err) {
    if (!NO_DIR_FSYNC_CODES.has(errCode(err) ?? "")) throw err;
  }
}

// Write `data` to a new file at `tmp` and fsync it, so the bytes are on disk before any name for
// them is published.
async function writeSynced(tmp: string, data: Buffer): Promise<void> {
  const fh = await open(tmp, "wx");
  try {
    await fh.writeFile(data);
    await fh.sync();
  } finally {
    await fh.close();
  }
}

// Publish `tmp` at `target` only if nothing is there. True when published, false when taken.
// A hard link shares the already-synced bytes; a copy is new data and is synced itself.
async function publishIfFree(tmp: string, target: string): Promise<boolean> {
  try {
    await link(tmp, target);
    return true;
  } catch (err) {
    if (errCode(err) === "EEXIST") return false;
    if (!NO_HARDLINK_CODES.has(errCode(err) ?? "")) throw err;
  }
  try {
    await copyFile(tmp, target, constants.COPYFILE_EXCL);
  } catch (err) {
    if (errCode(err) === "EEXIST") return false;
    throw err;
  }
  await syncPath(target, "r+").catch(removeAndRethrow(target));
  return true;
}

function removeAndRethrow(target: string): (err: unknown) => Promise<never> {
  return async (err: unknown) => {
    await unlink(target).catch(() => undefined);
    throw err;
  };
}

/**
 * Write `data` into `dir` under the first free name `nameFor(1)`, `nameFor(2)`, … and return the
 * full path it landed at. The bytes go to a unique temp file first, so a crash never leaves a
 * partial archive under a real name; the temp file is always removed. An existing file — an earlier
 * archive copy or anything else — is never replaced. When this resolves, the file and its folder
 * entry are fsynced (the folder best effort where the platform cannot, see NO_DIR_FSYNC_CODES); when
 * that cannot be done it rejects and leaves no published file behind (#2800).
 */
export async function writeBufferNewFile(
  dir: string,
  nameFor: (copyNumber: number) => string,
  data: Buffer,
): Promise<string> {
  const tmp = `${join(dir, nameFor(1))}.${randomUUID()}.tmp`;
  try {
    await writeSynced(tmp, data);
    for (let n = 1; n <= MAX_ARCHIVE_COPY_NUMBER; n++) {
      const target = join(dir, nameFor(n));
      if (!(await publishIfFree(tmp, target))) continue;
      await syncDir(dir).catch(removeAndRethrow(target));
      return target;
    }
    throw new Error(
      `no free archive file name in ${dir}: "${nameFor(1)}" and ${MAX_ARCHIVE_COPY_NUMBER - 1} numbered copies all exist`,
    );
  } finally {
    await unlink(tmp).catch(() => undefined);
  }
}
