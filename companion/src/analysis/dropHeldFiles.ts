import { lstat, mkdir, open, readdir, realpath, rename, utimes } from "node:fs/promises";
import { dirname, extname, join, relative, sep } from "node:path";
import { DROP_HELD, DROP_SKIPPED } from "./dropScan.js";
import { withCaseWrite } from "../storage/caseIncarnation.js";
import { isSafeDropRelpath } from "../storage/dropRelpath.js";
import type { HuntHeldStore } from "./huntHeldStore.js";

/**
 * The files of drop/_held/ (#2755): list them, and move a drop file within drop/ keeping its path below
 * a reserved folder and its modification time. A move never overwrites (`_N` on a taken name) and
 * refuses a destination that resolves outside drop/.
 */

const posix = (p: string): string => p.replace(/\\/g, "/");

export interface HeldListing {
  rel: string;
  size: number;
  mtimeMs: number;
}

/** Every regular file under drop/_held/ (links are not followed). */
export async function listHeld(dropDir: string): Promise<HeldListing[]> {
  const root = join(dropDir, DROP_HELD);
  const out: HeldListing[] = [];
  const walk = async (dir: string): Promise<void> => {
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const full = join(dir, e.name);
      if (e.isDirectory()) await walk(full);
      else if (e.isFile() && !e.name.startsWith(".")) {
        const st = await lstat(full).catch(() => null);
        if (st?.isFile())
          out.push({ rel: posix(relative(dropDir, full)), size: st.size, mtimeMs: st.mtimeMs });
      }
    }
  };
  await walk(root);
  return out;
}

/** The free path for `rel` (adding `_N` before the extension when it is taken). */
async function freeTarget(dropDir: string, rel: string): Promise<string> {
  const target = join(dropDir, ...rel.split("/"));
  const ext = extname(target);
  const stem = target.slice(0, target.length - ext.length);
  for (let n = 0; n < 1000; n++) {
    const path = n === 0 ? target : `${stem}_${n}${ext}`;
    const taken = await lstat(path).then(
      () => true,
      () => false,
    );
    if (!taken) return path;
  }
  throw new Error(`no free name for ${rel}`);
}

/**
 * Move one drop file from `fromRel` to `toRel` (both relative to drop/), keeping its modification time.
 * Never overwrites; returns where it landed (relative to drop/).
 */
export async function moveWithinDrop(dropDir: string, fromRel: string, toRel: string): Promise<string> {
  if (!isSafeDropRelpath(fromRel) || !isSafeDropRelpath(toRel))
    throw new Error("unsafe drop path (security)");
  return withCaseWrite(dropDir, async () => {
    const from = join(dropDir, ...fromRel.split("/"));
    const st = await lstat(from);
    if (!st.isFile()) throw new Error(`${fromRel} is not a regular file`);
    await mkdir(dirname(join(dropDir, ...toRel.split("/"))), { recursive: true });
    const target = await freeTarget(dropDir, toRel);
    const [realDrop, realParent] = await Promise.all([realpath(dropDir), realpath(dirname(target))]);
    if (realParent !== realDrop && !realParent.startsWith(realDrop + sep))
      throw new Error(`refused to move outside drop/ (security): ${toRel}`);
    // Reserve the name exclusively, then rename over the reservation (never follows a link).
    const handle = await open(target, "wx");
    await handle.close();
    await rename(from, target);
    await utimes(target, st.atime, st.mtime).catch(() => undefined);
    return posix(relative(dropDir, target));
  });
}

/** Where a held file goes on Import anyway (back to its drop path) or Skip (under `_skipped/`). */
export function releaseTarget(heldRel: string, decision: "import" | "skip"): string {
  const inDrop = heldRel.slice(`${DROP_HELD}/`.length);
  return decision === "import" ? inDrop : `${DROP_SKIPPED}/${inDrop}`;
}

export interface HeldDecisionResult {
  rel: string;
  to?: string;
  error?: string;
}

/**
 * Carry out the analyst's decision on one held file (#2755): move it back into drop/ (import) or to
 * `_skipped/` (skip), approve it where it can be imported from (its drop path; for Skip, once moved back
 * out of `_skipped/`), and remember a bundle hunt's decision for its later collects.
 */
export async function decideHeldFile(
  store: HuntHeldStore,
  caseId: string,
  dropDir: string,
  rel: string,
  decision: "import" | "skip",
): Promise<HeldDecisionResult> {
  if (!isSafeDropRelpath(rel) || !rel.startsWith(`${DROP_HELD}/`)) return { rel, error: "not a held file" };
  const info = (await store.load(caseId)).held.find((h) => h.rel === rel);
  try {
    const to = await moveWithinDrop(dropDir, rel, releaseTarget(rel, decision));
    const st = await lstat(join(dropDir, ...to.split("/")));
    const approvedPath = decision === "import" ? to : to.slice(`${DROP_SKIPPED}/`.length);
    await store.approve(caseId, { relpath: approvedPath, size: st.size, mtimeMs: st.mtimeMs }, rel);
    if (info?.origin === "hunt" && info.huntId)
      await store.decideHunt(caseId, info.huntId, info.artifact, decision);
    return { rel, to };
  } catch (err) {
    return { rel, error: (err as Error).message };
  }
}
