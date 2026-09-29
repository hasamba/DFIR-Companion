import { constants, type BigIntStats } from "node:fs";
import { open, readdir, realpath, stat, type FileHandle } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path";
import { perUserEnvFile, resolveEnvFilePath } from "../settings/envManager.js";
import { openedPath } from "./handlePath.js";
import { treeHoldsInode } from "./inodeSearch.js";

/**
 * The deny-list for reads of a server path someone named (#1792): /import-file,
 * /import-mac-login-item and POST /custody, and the custody re-hashes of those recorded paths —
 * verify, export and transfer (#1841). It sits in storage/ so analysis/custody.ts can use it; the
 * routes' import policy stays in routes/serverPathGuard.ts.
 *
 * Reading an operator-named path is the design — large evidence lives anywhere on the host, so an
 * allow-list root would break the documented use. But two places on the host are never evidence,
 * and copying them into a case hands them to every case reader (GET /cases/:id/evidence/:file, case
 * exports): the Companion's own configuration, whose API keys GET /settings/env masks even for
 * admins, and the case storage itself (other cases, case.json, state, the instance secret). A
 * relative path is refused too: it resolved against the server's working directory.
 *
 * The guard OPENS the file and judges the open handle (#1834): the route then reads that handle and
 * nothing else, so the bytes judged are the bytes read. Judging a path and letting the route
 * re-open it left a window in which the path could be swapped for a symlink to a protected file.
 * The env file is matched by identity (device + inode) so a hardlink cannot pass, and a file with a
 * second hard link is refused when that other name is a protected file. Where the handle's folder
 * comes from: storage/handlePath.ts.
 */

export interface ServerPathRefusal {
  status: 400 | 403 | 409;
  error: string;
}

export interface ServerPathPolicy {
  casesRoot: string;
  /** Folders inside the cases root the route may still read, e.g. the target case's drop folder. */
  allowUnder: string[];
  /** Names the allowed folders in the refusal, e.g. "this case's drop folder". */
  allowedLabel: string;
}

/** An open, judged file. The caller owns `handle`, reads only from it, and closes it. */
export interface GuardedFile {
  handle: FileHandle;
  /** Where the open inode lives — what the deny-list judged. */
  realPath: string;
  stat: BigIntStats;
}

export type ServerPathOpen =
  { refusal: ServerPathRefusal; file?: undefined } | { refusal?: undefined; file: GuardedFile };

const CONFIG_REFUSAL =
  "refused: that file is the Companion's own configuration (it holds the API keys) — it is never read as evidence";
const NOT_A_FILE = "refused: that path is not a regular file";
const CHANGED =
  "refused: the file changed while it was being checked (moved, replaced or deleted) — nothing was read; try again";
const HARDLINKED =
  "refused: that file is a second name (a hard link) for a file in the Companion's case storage or configuration";

// Only where the platform defines them (Windows has neither): never follow a final-component link
// swapped in after realpath, and never block on a FIFO swapped in after the pre-open stat.
const optionalFlag = (flag: number | undefined): number => flag ?? 0;
const OPEN_FLAGS =
  constants.O_RDONLY |
  optionalFlag((constants as Record<string, number | undefined>).O_NOFOLLOW) |
  optionalFlag((constants as Record<string, number | undefined>).O_NONBLOCK);

function inside(root: string, p: string): boolean {
  const norm = (s: string) => (process.platform === "win32" ? s.toLowerCase() : s);
  const rel = relative(norm(root), norm(p));
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
}

async function real(p: string): Promise<string> {
  return realpath(p).catch(() => resolve(p));
}

function envFiles(): string[] {
  return [resolveEnvFilePath(), perUserEnvFile()].filter((f): f is string => Boolean(f));
}

async function isCompanionConfig(at: string, st: BigIntStats): Promise<boolean> {
  for (const envFile of envFiles()) {
    const envReal = await real(envFile);
    // Backups and variants beside the live file (.env.bak, .env.old) hold the same keys.
    if (dirname(envReal) === dirname(at) && basename(at).toLowerCase().startsWith(".env")) return true;
    const e = await stat(envReal, { bigint: true }).catch(() => null);
    if (e && e.dev === st.dev && e.ino === st.ino) return true;
  }
  const perUser = perUserEnvFile();
  return perUser !== null && inside(await real(dirname(perUser)), at);
}

/**
 * A multi-link file whose other name is protected: a case file, or an `.env*` file beside a live env
 * file, or anything in the per-user config dir. Other multi-link evidence (deduplicated or
 * hard-linked collections) is read as before. Walks only for nlink > 1 — see storage/inodeSearch.ts.
 */
async function aliasOfProtected(st: BigIntStats, casesRootReal: string): Promise<boolean> {
  if (st.nlink <= 1n) return false;
  if (await treeHoldsInode(casesRootReal, st)) return true;
  const perUser = perUserEnvFile();
  if (perUser !== null && (await treeHoldsInode(await real(dirname(perUser)), st))) return true;
  for (const envFile of envFiles()) {
    const dir = dirname(await real(envFile));
    const names = await readdir(dir).catch(() => [] as string[]);
    for (const name of names.filter((n) => n.toLowerCase().startsWith(".env"))) {
      if (await treeHoldsInode(join(dir, name), st)) return true;
    }
  }
  return false;
}

async function judgeOpened(
  handle: FileHandle,
  target: string,
  st: BigIntStats,
  policy: ServerPathPolicy,
): Promise<{ refusal: ServerPathRefusal } | { at: string }> {
  if (!st.isFile()) return { refusal: { status: 400, error: NOT_A_FILE } };
  const at = await openedPath(handle, target, st);
  if (at === null || st.nlink === 0n) return { refusal: { status: 409, error: CHANGED } };
  if (await isCompanionConfig(at, st)) return { refusal: { status: 403, error: CONFIG_REFUSAL } };
  const casesRootReal = await real(policy.casesRoot);
  if (await aliasOfProtected(st, casesRootReal)) return { refusal: { status: 403, error: HARDLINKED } };
  if (!inside(casesRootReal, at)) return { at };
  const allowed = await Promise.all(policy.allowUnder.map(async (dir) => inside(await real(dir), at)));
  if (allowed.some(Boolean) && st.nlink === 1n) return { at };
  return {
    refusal: {
      status: 403,
      error: `refused: that file is inside the Companion's case storage, which is not evidence — only ${policy.allowedLabel} may be read from there`,
    },
  };
}

/**
 * Open a caller-named server path and judge the OPEN handle. Returns the refusal, or the file for
 * the route to read — from its handle only. Throws what realpath/open/stat throw (a missing file),
 * so the route keeps its own "cannot read file" message. A refused or failed open closes the handle.
 */
export async function openServerPath(filePath: string, policy: ServerPathPolicy): Promise<ServerPathOpen> {
  if (!isAbsolute(filePath))
    return {
      refusal: { status: 400, error: "path must be an absolute path to a file on the Companion machine" },
    };
  const target = await realpath(filePath);
  // Never open a device or a FIFO in the ordinary case; the fstat below covers a swap after this.
  if (!(await stat(target)).isFile()) return { refusal: { status: 400, error: NOT_A_FILE } };
  const handle = await open(target, OPEN_FLAGS);
  try {
    const st = await handle.stat({ bigint: true });
    const verdict = await judgeOpened(handle, target, st, policy);
    if ("at" in verdict) return { file: { handle, realPath: verdict.at, stat: st } };
    await handle.close();
    return { refusal: verdict.refusal };
  } catch (err) {
    await handle.close().catch(() => undefined);
    throw err;
  }
}
