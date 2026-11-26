import type { Dirent } from "node:fs";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { ARCHIVED_DIRNAME } from "../storage/caseIncarnation.js";
import { isValidCaseId } from "../storage/caseStore.js";

/**
 * Which cases are linked to a client (#2941) — the guard in front of deleting a client. A destructive
 * check, so it never takes "could not read" for "not linked":
 *   - it walks the case FOLDERS, not the case list: a case whose case.json is damaged is skipped by
 *     the list, but its `state/hunt-client.json` still names the client;
 *   - it reads the active root, then `_archived/`, then the active root again, so a case archived or
 *     restored while the scan runs is still seen in one of the three reads;
 *   - a link file that is missing where the folder was is read again at the case's current place (it
 *     may just have moved); a link file that cannot be parsed counts as linked ("unreadable");
 *   - any other read error is thrown, and the caller refuses the delete.
 */
export interface LinkedCase {
  caseId: string;
  name: string;
  unreadable?: true;
}

export interface CaseFolders {
  readonly casesRoot: string;
  stateDir(caseId: string): string;
  getCaseMeta(caseId: string): Promise<{ name?: string } | null>;
}

const LINK_FILE = "hunt-client.json";
const UNREADABLE = Symbol("unreadable");

async function caseFolders(dir: string, skip: string | null): Promise<string[]> {
  let entries: Dirent[];
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw err;
  }
  return entries
    .filter((e) => e.isDirectory() && e.name !== skip && isValidCaseId(e.name))
    .map((e) => e.name);
}

/** The client id a link file names, null when there is no link, UNREADABLE when it cannot be parsed. */
async function readLink(path: string): Promise<string | null | typeof UNREADABLE | undefined> {
  let raw: string;
  try {
    raw = await readFile(path, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return undefined; // not here (now)
    throw err;
  }
  try {
    const v = JSON.parse(raw) as { clientId?: unknown } | null;
    return typeof v?.clientId === "string" ? v.clientId || null : null;
  } catch {
    return UNREADABLE;
  }
}

async function caseName(cases: CaseFolders, caseId: string): Promise<string> {
  const meta = await cases.getCaseMeta(caseId).catch(() => null);
  return typeof meta?.name === "string" && meta.name ? meta.name : caseId;
}

export async function findLinkedCases(cases: CaseFolders, clientId: string): Promise<LinkedCase[]> {
  const root = cases.casesRoot;
  const archived = join(root, ARCHIVED_DIRNAME);
  const seen = new Map<string, string>(); // case id → the folder it was first seen in
  for (const dir of [root, archived, root]) {
    for (const name of await caseFolders(dir, dir === root ? ARCHIVED_DIRNAME : null))
      if (!seen.has(name)) seen.set(name, join(dir, name));
  }
  const out: LinkedCase[] = [];
  for (const [caseId, folder] of seen) {
    const here = await readLink(join(folder, "state", LINK_FILE));
    const link = here === undefined ? await readLink(join(cases.stateDir(caseId), LINK_FILE)) : here;
    if (link === UNREADABLE) out.push({ caseId, name: await caseName(cases, caseId), unreadable: true });
    else if (link === clientId) out.push({ caseId, name: await caseName(cases, caseId) });
  }
  return out.sort((a, b) => a.caseId.localeCompare(b.caseId));
}
