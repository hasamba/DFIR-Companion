// Archive copies written into the cases root are never replaced (#2787). The server-side copy an
// encrypted delete saves — and the ZIP an archive or a ZIP delete writes — can be the only copy of a
// case that no longer exists on disk. A later delete or archive of a case with the same id and name
// used to rename its file over the earlier one; now it takes the next free " (n)" name.
import { constants } from "node:fs";
import { copyFile, link, unlink, writeFile } from "node:fs/promises";
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

// Publish `tmp` at `target` only if nothing is there. True when published, false when taken.
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
    return true;
  } catch (err) {
    if (errCode(err) === "EEXIST") return false;
    throw err;
  }
}

/**
 * Write `data` into `dir` under the first free name `nameFor(1)`, `nameFor(2)`, … and return the
 * full path it landed at. The bytes go to a unique temp file first, so a crash never leaves a
 * partial archive under a real name; the temp file is always removed. An existing file — an earlier
 * archive copy or anything else — is never replaced.
 */
export async function writeBufferNewFile(
  dir: string,
  nameFor: (copyNumber: number) => string,
  data: Buffer,
): Promise<string> {
  const tmp = `${join(dir, nameFor(1))}.${randomUUID()}.tmp`;
  try {
    await writeFile(tmp, data, { flag: "wx" });
    for (let n = 1; n <= MAX_ARCHIVE_COPY_NUMBER; n++) {
      const target = join(dir, nameFor(n));
      if (await publishIfFree(tmp, target)) return target;
    }
    throw new Error(
      `no free archive file name in ${dir}: "${nameFor(1)}" and ${MAX_ARCHIVE_COPY_NUMBER - 1} numbered copies all exist`,
    );
  } finally {
    await unlink(tmp).catch(() => undefined);
  }
}
