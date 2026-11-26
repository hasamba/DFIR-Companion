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
 *   - it takes snapshots of the active root plus `_archived/` until two snapshots in a row agree
 *     (at most MAX_SNAPSHOTS, else it throws), and checks every case seen in any of them. Archive and
 *     restore take case locks this check cannot hold, so this is what keeps a case moved mid-scan in
 *     view: to be missed it would have to move twice inside EACH of two identical snapshots;
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
export const MAX_SNAPSHOTS = 5;
export const FOLDERS_KEPT_MOVING =
  "Cases kept moving between the active and archived folders while checking which cases use this client. Try again.";

/** Case-folder names in `dir`, leaving out `skip`. Swappable so a test can move folders mid-scan. */
export type ListCaseFolders = (dir: string, skip: string | null) => Promise<string[]>;

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

/** One look at both folders: case id → its folder (active wins when a case shows in both). */
async function snapshot(root: string, list: ListCaseFolders): Promise<Map<string, string>> {
  const archived = join(root, ARCHIVED_DIRNAME);
  const snap = new Map<string, string>();
  for (const [dir, skip] of [
    [root, ARCHIVED_DIRNAME],
    [archived, null],
  ] as const) {
    for (const name of await list(dir, skip)) if (!snap.has(name)) snap.set(name, join(dir, name));
  }
  return snap;
}

const snapshotKey = (snap: Map<string, string>): string => [...snap.values()].sort().join("\n");

export async function findLinkedCases(
  cases: CaseFolders,
  clientId: string,
  list: ListCaseFolders = caseFolders,
): Promise<LinkedCase[]> {
  const seen = new Map<string, string>(); // case id → the folder it was first seen in
  let previous: string | null = null;
  for (let i = 0; ; i++) {
    if (i === MAX_SNAPSHOTS) throw new Error(FOLDERS_KEPT_MOVING);
    const snap = await snapshot(cases.casesRoot, list);
    for (const [id, folder] of snap) if (!seen.has(id)) seen.set(id, folder);
    const key = snapshotKey(snap);
    if (key === previous) break;
    previous = key;
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
