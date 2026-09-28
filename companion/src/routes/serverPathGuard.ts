import { realpath, stat } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path";
import { perUserEnvFile, resolveEnvFilePath } from "../settings/envManager.js";

/**
 * The deny-list for routes that read a server path the caller names (#1792): /import-file,
 * /import-mac-login-item and POST /custody.
 *
 * Reading an operator-named path is the design — large evidence lives anywhere on the host, so an
 * allow-list root would break the documented use. But two places on the host are never evidence,
 * and copying them into a case hands them to every case reader (GET /cases/:id/evidence/:file, case
 * exports): the Companion's own configuration, whose API keys GET /settings/env masks even for
 * admins, and the case storage itself (other cases, case.json, state, the instance secret). A
 * relative path is refused too: it resolved against the server's working directory.
 *
 * Symlinks are resolved first, the env file is matched by identity (device + inode) so a hardlink
 * cannot pass either, and a hardlinked file inside an allowed folder is refused. A file that cannot
 * be resolved is let through: the route's own read then fails with its usual message.
 */

export interface ServerPathRefusal {
  status: 400 | 403;
  error: string;
}

export interface ServerPathPolicy {
  casesRoot: string;
  /** Folders inside the cases root the route may still read, e.g. the target case's drop folder. */
  allowUnder: string[];
  /** Names the allowed folders in the refusal, e.g. "this case's drop folder". */
  allowedLabel: string;
}

const CONFIG_REFUSAL =
  "refused: that file is the Companion's own configuration (it holds the API keys) — it is never read as evidence";

function inside(root: string, p: string): boolean {
  const norm = (s: string) => (process.platform === "win32" ? s.toLowerCase() : s);
  const rel = relative(norm(root), norm(p));
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
}

async function real(p: string): Promise<string> {
  return realpath(p).catch(() => resolve(p));
}

async function isCompanionConfig(target: string): Promise<boolean> {
  const t = await stat(target, { bigint: true });
  const envFiles = [resolveEnvFilePath(), perUserEnvFile()].filter((f): f is string => Boolean(f));
  for (const envFile of envFiles) {
    const envReal = await real(envFile);
    // Backups and variants beside the live file (.env.bak, .env.old) hold the same keys.
    if (dirname(envReal) === dirname(target) && basename(target).toLowerCase().startsWith(".env"))
      return true;
    const e = await stat(envReal, { bigint: true }).catch(() => null);
    if (e && e.dev === t.dev && e.ino === t.ino) return true;
  }
  const perUser = perUserEnvFile();
  return perUser !== null && inside(await real(dirname(perUser)), target);
}

/** The refusal for a caller-named server path, or null when the route may read it. */
export async function refuseServerPath(
  filePath: string,
  policy: ServerPathPolicy,
): Promise<ServerPathRefusal | null> {
  if (!isAbsolute(filePath))
    return { status: 400, error: "path must be an absolute path to a file on the Companion machine" };
  let target: string;
  try {
    target = await realpath(filePath);
  } catch {
    return null; // missing or unreadable: the route's own read reports it
  }
  if (await isCompanionConfig(target)) return { status: 403, error: CONFIG_REFUSAL };
  if (!inside(await real(policy.casesRoot), target)) return null;
  const allowed = await Promise.all(policy.allowUnder.map(async (dir) => inside(await real(dir), target)));
  const { nlink } = await stat(target);
  if (allowed.some(Boolean) && nlink === 1) return null;
  return {
    status: 403,
    error: `refused: that file is inside the Companion's case storage, which is not evidence — only ${policy.allowedLabel} may be read from there`,
  };
}

/** The /import-file and /import-mac-login-item guard: in case storage, only the target case's drop folder. */
export function refuseImportPath(
  filePath: string,
  store: { casesRoot: string; caseDir(caseId: string): string },
  caseId: string,
): Promise<ServerPathRefusal | null> {
  return refuseServerPath(filePath, {
    casesRoot: store.casesRoot,
    allowUnder: [join(store.caseDir(caseId), "drop")], // composition/dropFolder.ts dropDirOf
    allowedLabel: "this case's drop folder",
  });
}
