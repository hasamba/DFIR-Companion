import { randomUUID } from "node:crypto";
import { mkdir, open, realpath, rename, rm } from "node:fs/promises";
import { basename, dirname, join, sep } from "node:path";
import { decideHeldFile, listHeld, moveWithinDrop } from "../analysis/dropHeldFiles.js";
import { DROP_HELD, type DropFileStat } from "../analysis/dropScan.js";
import { appendDropLog, formatDropLogLines, type DropLogEntry } from "../analysis/dropLog.js";
import {
  huntArtifactLimitsFromEnv,
  planHolds,
  type HuntArtifactLimits,
} from "../analysis/huntArtifactLimits.js";
import type { HuntPlan } from "../analysis/veloHuntLayout.js";
import { isApproved, type HeldMeta, type HuntHeldStore } from "../analysis/huntHeldStore.js";
import { withCaseWrite } from "../storage/caseIncarnation.js";
import { isSafeDropRelpath } from "../storage/dropRelpath.js";
import { readHeadNoFollow } from "../storage/noFollowRead.js";
import { severalPcs } from "./dropResultClients.js";
import { logLine } from "../logging/serverLogger.js";

/**
 * Held hunt results as drop-folder files (#2755). A result over the hunt artifact size limits waits as
 * a file under `drop/_held/<the path it would have in drop/>` — the walker never enters `_held/`.
 * Import anyway moves it back to that path (approved, so it imports); Skip moves it to `_skipped/`
 * (approved too, so moving it back into drop/ imports it). Every move keeps the file's path below the
 * reserved folder, so a hunt member keeps the client folder its host is read from, never overwrites
 * (`_N` on a taken name), and refuses a destination that resolves outside drop/.
 */

const MB = 1024 * 1024;
const posix = (p: string): string => p.replace(/\\/g, "/");

/** Put one drop file on hold: move it to `_held/<rel>` and record what the dashboard shows. */
export async function holdDropFile(
  store: HuntHeldStore,
  caseId: string,
  dropDir: string,
  rel: string,
  meta: HeldMeta,
): Promise<string> {
  const heldRel = await moveWithinDrop(dropDir, posix(rel), `${DROP_HELD}/${posix(rel)}`);
  await store.putHeld(caseId, { ...meta, rel: heldRel });
  return heldRel;
}

/**
 * Write a held file's text atomically (temp + rename, replacing an earlier version of the same file).
 * The temp name is unique per save, so a leftover from a crash never blocks the next one (#2764).
 */
export async function writeHeldText(dropDir: string, heldRel: string, text: string): Promise<void> {
  if (!isSafeDropRelpath(heldRel) || !heldRel.startsWith(`${DROP_HELD}/`))
    throw new Error("unsafe held path");
  await withCaseWrite(dropDir, async () => {
    const target = join(dropDir, ...heldRel.split("/"));
    await mkdir(dirname(target), { recursive: true });
    const [realDrop, realParent] = await Promise.all([realpath(dropDir), realpath(dirname(target))]);
    if (!realParent.startsWith(realDrop + sep)) throw new Error("refused to write outside drop/ (security)");
    const tmp = join(dirname(target), `.${basename(target)}.${randomUUID()}.tmp`);
    try {
      const h = await open(tmp, "wx");
      try {
        await h.writeFile(text, "utf8");
      } finally {
        await h.close();
      }
      await rename(tmp, target);
    } catch (e) {
      await rm(tmp, { force: true });
      throw e;
    }
  });
}

export interface SweepHoldDeps {
  store: HuntHeldStore;
  caseId: string;
  dropDir: string;
  resolveImportKind: (filename: string, text: string) => string;
}

/**
 * Release held files the per-file rules no longer hold (#2805): one PC's result file from a hunt zip
 * or folder, held when an artifact's files were summed across PCs (or across one PC's files), whose own
 * size is within the per-PC limit. Released exactly like Import anyway: back into drop/, approved, so
 * the next sweep imports it. A bundle hunt's held copy is re-measured by its next collect instead.
 */
export async function releaseOutdatedHolds(
  d: Pick<SweepHoldDeps, "store" | "caseId" | "dropDir">,
): Promise<number> {
  const { hostMb } = huntArtifactLimitsFromEnv();
  const known = new Map((await d.store.load(d.caseId)).held.map((h) => [h.rel, h]));
  let released = 0;
  for (const f of await listHeld(d.dropDir).catch(() => [])) {
    const info = known.get(f.rel);
    if (!info || info.origin === "hunt" || info.origin === "file" || !info.host) continue;
    if (hostMb > 0 && f.size > hostMb * MB) continue;
    const r = await decideHeldFile(d.store, d.caseId, d.dropDir, f.rel, "import");
    if (r.error) logLine(`[drop] could not release ${f.rel}: ${r.error}`);
    else released++;
  }
  if (released) logLine(`[drop] released ${released} held file(s) now within the per-file size limits`);
  return released;
}

/**
 * The sweep's hold step, after hunt folders were prepared: finish an unzipped folder's pending holds,
 * and hold a single Velociraptor result file over the per-PC limit (only files that large are sniffed;
 * approved files never). Returns `ready` without the files that went on hold.
 */
export async function applyDropHolds(
  d: SweepHoldDeps,
  ready: readonly DropFileStat[],
): Promise<DropFileStat[]> {
  await releaseOutdatedHolds(d);
  const state = await d.store.load(d.caseId);
  const limits = huntArtifactLimitsFromEnv();
  const pending = new Map(state.pending.map((p) => [p.relpath, p.meta]));
  const held = new Set<string>();
  const log: DropLogEntry[] = [];
  const done: string[] = [];
  for (const f of ready) {
    const rel = posix(f.relpath);
    if (isApproved(state, f)) continue;
    let meta = pending.get(rel);
    if (!meta && f.size > smallestLimitMb(limits) * MB) meta = await singleFileHold(d, f, limits);
    if (!meta) continue;
    try {
      const where = await holdDropFile(d.store, d.caseId, d.dropDir, f.relpath, meta);
      log.push({
        status: "SKIPPED",
        relpath: rel,
        reason: `held over the hunt artifact size limit — in ${where}`,
      });
      if (pending.has(rel)) done.push(rel);
    } catch (e) {
      logLine(`[drop] could not hold ${rel}: ${(e as Error).message}`);
    }
    held.add(f.relpath); // a pending hold that failed to move stays out of this sweep too
  }
  if (done.length) await d.store.setPending(d.caseId, [], done);
  if (log.length)
    await appendDropLog(d.dropDir, formatDropLogLines(log, new Date().toISOString())).catch(() => undefined);
  return ready.filter((f) => !held.has(f.relpath));
}

/** Below this no limit can apply, so the file is not even opened. */
function smallestLimitMb(limits: HuntArtifactLimits): number {
  const on = [limits.hostMb, limits.totalMb].filter((n) => n > 0);
  return on.length ? Math.min(...on) : Infinity;
}

/**
 * A single dropped file the importer would read as Velociraptor results, over the limit for what it
 * holds (#2805): one PC's results against `hostMb`, several PCs' results against `totalMb`.
 */
async function singleFileHold(
  d: SweepHoldDeps,
  f: DropFileStat,
  limits: HuntArtifactLimits,
): Promise<HeldMeta | undefined> {
  const head = await readHeadNoFollow(join(d.dropDir, f.relpath), 8192).catch(() => undefined);
  if (!head) return undefined;
  const name = basename(f.relpath);
  const text = head.toString("utf8");
  if (d.resolveImportKind(name, text) !== "velociraptor") return undefined;
  const several = await severalPcs(join(d.dropDir, f.relpath), name).catch(() => false);
  const limitMb = several ? limits.totalMb : limits.hostMb;
  if (!(limitMb > 0) || f.size <= limitMb * MB) return undefined;
  const artifact = name.replace(/\.(jsonl?|csv)$/i, "");
  return {
    ...{ origin: "file", source: posix(f.relpath), artifact, host: "", bytes: f.size, groupBytes: f.size },
    ...{ reason: several ? "total" : "host", limitMb },
  };
}

/**
 * An unzipped hunt folder's imports over the limits (#2755): chosen from the WHOLE plan, recorded as
 * pending before any moves (a crash part-way is finished by applyDropHolds from that record, never
 * recomputed from what is left), then moved to `_held/`. Approved files are not held again. Returns
 * every import that must not be released this sweep.
 */
export async function holdFolderPlan(
  d: SweepHoldDeps,
  plan: HuntPlan,
  listing: readonly DropFileStat[],
): Promise<ReadonlySet<string>> {
  const state = await d.store.load(d.caseId);
  const byPath = new Map(listing.map((f) => [posix(f.relpath), f]));
  const sized = plan.imports.flatMap((i) => {
    const f = byPath.get(i.path);
    return f && !isApproved(state, f) ? [{ ...i, bytes: f.size }] : [];
  });
  const chosen = planHolds(sized, huntArtifactLimitsFromEnv());
  const already = state.pending.filter((p) => plan.imports.some((i) => i.path === p.relpath));
  if (!chosen.length && !already.length) return new Set();
  const add = chosen
    .filter((h) => !already.some((p) => p.relpath === h.path))
    .map((h) => ({
      relpath: h.path,
      meta: {
        ...{ origin: "folder" as const, source: plan.root || h.path, artifact: h.artifact, host: h.host },
        ...{ bytes: h.bytes, groupBytes: h.groupBytes, reason: h.reason, limitMb: h.limitMb },
      },
    }));
  if (add.length) await d.store.setPending(d.caseId, add);
  const all = [...already, ...add];
  const done: string[] = [];
  for (const p of all) {
    if (!byPath.has(p.relpath)) continue;
    try {
      await holdDropFile(d.store, d.caseId, d.dropDir, byPath.get(p.relpath)!.relpath, p.meta);
      done.push(p.relpath);
    } catch (e) {
      logLine(`[drop] could not hold ${p.relpath}: ${(e as Error).message} — retried on the next sweep`);
    }
  }
  if (done.length) await d.store.setPending(d.caseId, [], done);
  return new Set(all.map((p) => p.relpath));
}
