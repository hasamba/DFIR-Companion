import type { Dirent } from "node:fs";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { ARCHIVED_DIRNAME } from "../storage/caseIncarnation.js";
import { heldStill, type FolderMoveState } from "../storage/caseFolderMoves.js";
import { isValidCaseId } from "../storage/caseStore.js";

/**
 * Which cases are linked to a client (#2941) — the guard in front of deleting a client. A destructive
 * check, so it never takes "could not read" for "not linked":
 *   - it walks the case FOLDERS, not the case list: a case whose case.json is damaged is skipped by
 *     the list, but its `state/hunt-client.json` still names the client;
 *   - archive and restore move case folders under a lock this check cannot hold, so it reads the case
 *     store's move counter before it looks and again after it has read every link file (#2945). When
 *     a move started or was in flight anywhere in that window it looks again (at most MAX_ATTEMPTS,
 *     else it throws). A look that held still saw every case where it is, so a missing link file
 *     means no link — a case moved twice and back still counts as a move;
 *   - a link file that cannot be parsed counts as linked ("unreadable");
 *   - any other read error is thrown, and the caller refuses the delete.
 */
export interface LinkedCase {
  caseId: string;
  name: string;
  unreadable?: true;
}

export interface CaseFolders {
  readonly casesRoot: string;
  readonly folderMoves: { state(): FolderMoveState };
  getCaseMeta(caseId: string): Promise<{ name?: string } | null>;
}

const LINK_FILE = "hunt-client.json";
const UNREADABLE = Symbol("unreadable");
export const MAX_ATTEMPTS = 5;
export const FOLDERS_KEPT_MOVING =
  "Cases kept moving between the active and archived folders while checking which cases use this client. Try again.";

/** Case-folder names in `dir`, leaving out `skip`. Swappable so a test can move folders mid-scan. */
export type ListCaseFolders = (dir: string, skip: string | null) => Promise<string[]>;

export async function listCaseFolders(dir: string, skip: string | null): Promise<string[]> {
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
async function readLink(path: string): Promise<string | null | typeof UNREADABLE> {
  let raw: string;
  try {
    raw = await readFile(path, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
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

/** One look: every case folder in both places, and the cases whose link file names `clientId`. */
async function look(cases: CaseFolders, clientId: string, list: ListCaseFolders): Promise<LinkedCase[]> {
  const out: LinkedCase[] = [];
  for (const [caseId, folder] of await snapshot(cases.casesRoot, list)) {
    const link = await readLink(join(folder, "state", LINK_FILE));
    if (link === UNREADABLE) out.push({ caseId, name: await caseName(cases, caseId), unreadable: true });
    else if (link === clientId) out.push({ caseId, name: await caseName(cases, caseId) });
  }
  return out;
}

export async function findLinkedCases(
  cases: CaseFolders,
  clientId: string,
  list: ListCaseFolders = listCaseFolders,
): Promise<LinkedCase[]> {
  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
    const before = cases.folderMoves.state();
    const found = await look(cases, clientId, list);
    if (heldStill(before, cases.folderMoves.state()))
      return found.sort((a, b) => a.caseId.localeCompare(b.caseId));
  }
  throw new Error(FOLDERS_KEPT_MOVING);
}
