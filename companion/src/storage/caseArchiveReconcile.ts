/**
 * Startup self-heal for the archive crash window (#2437).
 *
 * Archive and restore each move the case folder and then relabel case.json, as two steps under the
 * metadata lock. A crash between them leaves the two disagreeing: a folder under _archived/ that
 * still says "closed", or an active folder that says "archived" — which no route can reopen
 * (archived) or restore (not under _archived/). Both are frozen, so nothing was ever written to them;
 * this puts each back into the one consistent state, archived, so Restore works again.
 *
 * Run once at startup, not on every case listing: listCases runs on every dashboard poll, and moving
 * folders there would race the dashboard. Best-effort per case: one failure never stops the rest.
 */
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaseStore } from "./caseStore.js";
import { ARCHIVED_DIRNAME } from "./caseIncarnation.js";

async function listDirs(dir: string): Promise<string[]> {
  try {
    const entries = await readdir(dir, { withFileTypes: true });
    return entries.filter((e) => e.isDirectory() && e.name !== ARCHIVED_DIRNAME).map((e) => e.name);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw err;
  }
}

async function statusAt(dir: string): Promise<string | undefined | null> {
  try {
    return (JSON.parse(await readFile(join(dir, "case.json"), "utf8")) as { status?: string }).status;
  } catch {
    return null; // no readable case.json: not a case
  }
}

/** Ids whose folder place and label disagree. Read-only; the store re-checks under its lock. */
async function disagreeing(store: CaseStore): Promise<string[]> {
  const root = store.casesRoot;
  const out: string[] = [];
  for (const id of await listDirs(root)) {
    if ((await statusAt(join(root, id))) === "archived") out.push(id);
  }
  for (const id of await listDirs(join(root, ARCHIVED_DIRNAME))) {
    const status = await statusAt(join(root, ARCHIVED_DIRNAME, id));
    if (status !== null && status !== "archived") out.push(id);
  }
  return out;
}

/**
 * Reconcile every disagreeing case to "archived". Returns how many changed. A case that fails is
 * reported through `onError` and skipped.
 */
export async function reconcileArchiveLabels(
  store: CaseStore,
  onError: (caseId: string, err: Error) => void,
): Promise<number> {
  let healed = 0;
  for (const id of await disagreeing(store)) {
    try {
      if (await store.reconcileArchiveLabel(id)) healed += 1;
    } catch (err) {
      onError(id, err as Error);
    }
  }
  return healed;
}
