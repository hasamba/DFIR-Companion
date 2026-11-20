/**
 * Where a hunt-export zip's members land on disk (#2714): a failed member is extracted to
 * `drop/_failed/<zip relpath without .zip>/<member>` so the analyst can drop that one file back in,
 * and a member too large to read into memory is staged in `drop/.hunt-zip-staging/` (a dot-folder the
 * walker never enters, on the same filesystem as `_failed/`) so the disk streamers can read it.
 *
 * Every write is exclusive (`wx`: never through an existing file or link), its parent must resolve
 * inside `_failed/` (a planted symlinked folder cannot redirect it), a name already taken gets `_N`,
 * and a partial file is removed when the write fails. The member name was validated before it got
 * here; this is the second layer.
 */
import { randomUUID } from "node:crypto";
import { mkdir, open, realpath, rename, rm, type FileHandle } from "node:fs/promises";
import { dirname, extname, join, relative, sep } from "node:path";
import { DROP_FAILED, DROP_HELD } from "../analysis/dropScan.js";
import { withCaseWrite } from "../storage/caseIncarnation.js";

export const HUNT_ZIP_STAGING = ".hunt-zip-staging";

/** The folder a zip's failed members go to, relative to drop/: `_failed/<zip relpath minus .zip>`. */
export function failedMembersFolder(zipRelpath: string): string {
  const posix = zipRelpath.replace(/\\/g, "/");
  const stem = posix.replace(/\.zip$/i, "") || posix;
  return `${DROP_FAILED}/${stem}`;
}

/** The folder a zip's held members go to (#2755): `_held/<zip relpath minus .zip>`. */
export function heldMembersFolder(zipRelpath: string): string {
  return `${DROP_HELD}${failedMembersFolder(zipRelpath).slice(DROP_FAILED.length)}`;
}

/**
 * A unique, exclusively created file at `folder/<member>` under one reserved root of drop/ (`_failed`
 * or `_held`); its parent must resolve inside that root. A name already taken gets `_N`.
 */
async function reserveUnder(
  dropDir: string,
  root: string,
  folder: string,
  member: string,
): Promise<{ path: string; handle: FileHandle }> {
  const rootDir = join(dropDir, root);
  const target = join(dropDir, ...folder.split("/"), ...member.split("/"));
  await mkdir(dirname(target), { recursive: true });
  const [realRoot, realParent] = await Promise.all([realpath(rootDir), realpath(dirname(target))]);
  if (realParent !== realRoot && !realParent.startsWith(realRoot + sep))
    throw new Error(`refused to extract outside ${root}/ (security): ${member}`);
  const ext = extname(target);
  const stem = target.slice(0, target.length - ext.length);
  for (let n = 0; n < 1000; n++) {
    const path = n === 0 ? target : `${stem}_${n}${ext}`;
    try {
      return { path, handle: await open(path, "wx") };
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
    }
  }
  throw new Error(`no free name to extract ${member} to`);
}

const reserveFailedPath = (dropDir: string, zipRelpath: string, member: string) =>
  reserveUnder(dropDir, DROP_FAILED, failedMembersFolder(zipRelpath), member);

/** Extract a held member via `fill` to `_held/<zip stem>/<member>`; returns its path relative to drop/. */
export async function extractHeldMember(
  dropDir: string,
  zipRelpath: string,
  member: string,
  fill: (out: FileHandle) => Promise<unknown>,
): Promise<string> {
  return withCaseWrite(join(dropDir, DROP_HELD), async () => {
    await mkdir(join(dropDir, DROP_HELD), { recursive: true });
    const { path, handle } = await reserveUnder(dropDir, DROP_HELD, heldMembersFolder(zipRelpath), member);
    try {
      await fill(handle);
    } catch (e) {
      await handle.close().catch(() => undefined);
      await rm(path, { force: true });
      throw e;
    }
    await handle.close();
    return relative(dropDir, path).replace(/\\/g, "/");
  });
}

/** Write a failed member via `fill`; returns its path relative to drop/. */
export async function extractFailedMember(
  dropDir: string,
  zipRelpath: string,
  member: string,
  fill: (out: FileHandle) => Promise<unknown>,
): Promise<string> {
  const failedRoot = join(dropDir, DROP_FAILED);
  return withCaseWrite(failedRoot, async () => {
    await mkdir(failedRoot, { recursive: true });
    const { path, handle } = await reserveFailedPath(dropDir, zipRelpath, member);
    try {
      await fill(handle);
    } catch (e) {
      await handle.close().catch(() => undefined);
      await rm(path, { force: true });
      throw e;
    }
    await handle.close();
    return relative(dropDir, path);
  });
}

/** Move a staged member into the zip's failed folder; returns its path relative to drop/. */
export async function moveStagedToFailed(
  dropDir: string,
  zipRelpath: string,
  member: string,
  stagedPath: string,
): Promise<string> {
  return withCaseWrite(join(dropDir, DROP_FAILED), async () => {
    const { path, handle } = await reserveFailedPath(dropDir, zipRelpath, member);
    await handle.close();
    await rename(stagedPath, path); // replaces the reservation we just created, never follows a link
    return relative(dropDir, path);
  });
}

/** An exclusively created staging file in drop/.hunt-zip-staging/. */
export async function createStagingFile(dropDir: string): Promise<{ path: string; handle: FileHandle }> {
  const dir = join(dropDir, HUNT_ZIP_STAGING);
  await withCaseWrite(dir, () => mkdir(dir, { recursive: true }));
  const path = join(dir, `${randomUUID()}.part`);
  return { path, handle: await open(path, "wx") };
}

/** Remove what an interrupted run left in the staging folder (called once per sweep, before imports). */
export async function clearStaging(dropDir: string): Promise<void> {
  const dir = join(dropDir, HUNT_ZIP_STAGING);
  await withCaseWrite(dir, () => rm(dir, { recursive: true, force: true })).catch(() => undefined);
}
