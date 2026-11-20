/**
 * A Velociraptor hunt export dropped as a `.zip` (#2714). Until this, `.zip` was only a raw tool input
 * (SO-CRATES), so a hunt zip was never read. Now the central directory is listed first; if it holds
 * a hunt (analysis/veloHuntLayout.ts), only the members to import are read — streamed from disk,
 * ZIP64 included — and nothing else is inflated. A zip that holds no hunt goes back to the tool
 * routing exactly as before.
 *
 * - One member failing never stops the rest. A failed member is extracted to
 *   `_failed/<zip relpath minus .zip>/<member>` with its reason in drop-log.txt, so the analyst can
 *   drop just that file back in.
 * - The zip goes to `_processed/` when at least one member imported (this run or an interrupted
 *   earlier one), else to `_failed/` — the sweep's usual move, from the outcome returned here.
 * - A crash or restart mid-zip resumes from the ledger (composition/dropHuntZipLedger.ts).
 * - Refused, never read or extracted: unsafe names (traversal, absolute, drive, `:`, control
 *   characters, reserved Windows names), symlink and encrypted members, duplicate names, a member
 *   whose compression ratio marks it as a bomb. A total to import over HUNT_ZIP_MAX_TOTAL_BYTES
 *   refuses the whole zip.
 * - A member over DFIR_DROP_MAX_BYTES is staged on disk and handed to the drop streamer (Velociraptor
 *   JSON Lines, cloud exports, Plaso — #2336, #2705); anything else that large fails, extracted.
 */
import { basename, extname } from "node:path";
import type { DropFileStat } from "../analysis/dropScan.js";
import { appendDropLog, formatDropLogLines, type DropLogEntry } from "../analysis/dropLog.js";
import { huntSkipSummary, planHuntExports, type HuntPlan } from "../analysis/veloHuntLayout.js";
import { isSafeZipEntryPath } from "../analysis/caseRestore.js";
import { createImportDebugRecorder, type ImportDebugRecorder } from "../analysis/importDebug.js";
import { logLine } from "../logging/serverLogger.js";
import { openNoFollow } from "../storage/noFollowRead.js";
import { listZipMembers, openZip, type ZipFile, type ZipMember } from "../storage/zipMembers.js";
import { huntZipId, openHuntZipLedger, type HuntZipLedger, type MemberOutcome } from "./dropHuntZipLedger.js";
import { failedMembersFolder } from "./dropHuntExtract.js";
import { importHuntMember, type HuntMemberDeps } from "./dropHuntMember.js";
import type { DropOutcome } from "./dropBatch.js";
import type { ModelCallHooks } from "./importIngest.js";
import type { HuntProgress } from "./dropSweepProgress.js";
import type { HuntHeldStore } from "../analysis/huntHeldStore.js";
import { NO_HOLDS, resolveZipHolds } from "./dropHuntHold.js";

/** The most a hunt zip may inflate to across the members it imports (the zip-bomb bound). */
export const HUNT_ZIP_MAX_TOTAL_BYTES = 64 * 1024 ** 3;
/** Highest inflated-to-compressed ratio for one member past HUNT_ZIP_RATIO_MIN_BYTES. */
export const HUNT_ZIP_MAX_RATIO = 1000;
export const HUNT_ZIP_RATIO_MIN_BYTES = 1024 * 1024;
/** Non-hunt zips remembered so their central directory is not re-read every poll. */
const NOT_HUNT_MEMORY = 2000;

const ZIP_MAGIC = Buffer.from([0x50, 0x4b, 0x03, 0x04]);

/** A `.zip` whose head is a zip local header — worth listing for a hunt. */
export function isZipCandidate(relpath: string, head: Buffer | undefined): boolean {
  return extname(relpath).toLowerCase() === ".zip" && !!head && head.subarray(0, 4).equals(ZIP_MAGIC);
}

export interface HuntZipDeps extends HuntMemberDeps {
  stateDir: (caseId: string) => string;
  /** Result files held over the size limits until the analyst decides (#2746). */
  held?: HuntHeldStore;
}

export interface HuntZipArgs {
  caseId: string;
  dropDir: string;
  fullPath: string;
  file: DropFileStat;
  modelCall?: ModelCallHooks;
  /** The zip's result-file count for the Jobs row (#2742); never called for a zip with none to import. */
  onProgress?: (p: HuntProgress) => void;
}

/** Null: not a hunt export — the caller routes the zip as it always has. */
export type HandleHuntZip = (args: HuntZipArgs) => Promise<DropOutcome | null>;

export function createHuntZipHandler(deps: HuntZipDeps): HandleHuntZip {
  const notHunt = new Set<string>();
  // Outcomes this process knows but may not have written (a ledger append failed), by archive id:
  // a retry in the same process never imports such a member twice.
  const remembered = new Map<string, Map<string, MemberOutcome>>();
  return async (args) => {
    const key = `${args.fullPath}\0${args.file.size}\0${args.file.mtimeMs}`;
    if (notHunt.has(key)) return null;
    const handle = await openNoFollow(args.fullPath);
    try {
      let zip: ZipFile;
      let members: ZipMember[];
      try {
        zip = await openZip(handle);
        members = await listZipMembers(zip);
      } catch {
        remember(notHunt, key); // unreadable as a zip: the tool routing names whatever is wrong
        return null;
      }
      const run = prepareRun(members);
      if (!run) {
        remember(notHunt, key);
        return null;
      }
      return await processHunt(deps, args, zip, members, run, remembered);
    } finally {
      await handle.close().catch(() => undefined); // never zip.close(): it closes this descriptor
    }
  };
}

function remember(set: Set<string>, key: string): void {
  if (set.size >= NOT_HUNT_MEMORY) set.clear();
  set.add(key);
}

interface HuntRun {
  plans: HuntPlan[];
  byName: Map<string, ZipMember>;
  refused: { name: string; reason: string }[];
}

/** Refuse unsafe members, plan the rest; null when the archive holds no hunt. */
function prepareRun(members: readonly ZipMember[]): HuntRun | null {
  const files = members.filter((m) => !m.dir);
  const counts = new Map<string, number>();
  for (const m of files) counts.set(m.name, (counts.get(m.name) ?? 0) + 1);
  const refused: HuntRun["refused"] = [];
  const byName = new Map<string, ZipMember>();
  for (const m of files) {
    const reason =
      m.refusal ??
      (counts.get(m.name)! > 1 ? "duplicate member name" : undefined) ??
      (isSafeZipEntryPath(m.name) ? undefined : "unsafe member name") ??
      bombReason(m);
    if (reason) refused.push({ name: m.name, reason: `${reason} — refused (security)` });
    else byName.set(m.name, m);
  }
  const plans = planHuntExports([...byName.keys()]);
  return plans.length ? { plans, byName, refused } : null;
}

function bombReason(m: ZipMember): string | undefined {
  const { uncompressedSize: size, compressedSize: packed } = m.entry;
  if (size < HUNT_ZIP_RATIO_MIN_BYTES) return undefined;
  return size / Math.max(1, packed) > HUNT_ZIP_MAX_RATIO ? "compression ratio of a zip bomb" : undefined;
}

async function processHunt(
  deps: HuntZipDeps,
  args: HuntZipArgs,
  zip: ZipFile,
  members: readonly ZipMember[],
  run: HuntRun,
  remembered: Map<string, Map<string, MemberOutcome>>,
): Promise<DropOutcome> {
  const zipRel = args.file.relpath.replace(/\\/g, "/");
  const imports = run.plans.flatMap((p) => p.imports.map((i) => i.path));
  const total = imports.reduce((n, name) => n + run.byName.get(name)!.entry.uncompressedSize, 0);
  if (total > HUNT_ZIP_MAX_TOTAL_BYTES) {
    return {
      ok: false,
      reason: `hunt export would inflate to ${Math.round(total / 1024 ** 3)} GB (> ${HUNT_ZIP_MAX_TOTAL_BYTES / 1024 ** 3} GB bound) — refused (security); unzip it and drop the per-client folders`,
    };
  }
  const id = huntZipId(zipRel, args.file.size, members);
  const ledger = await openHuntZipLedger(deps.stateDir(args.caseId), id, {
    relpath: zipRel,
    size: args.file.size,
  });
  const memo = remembered.get(id) ?? new Map<string, MemberOutcome>();
  remembered.set(id, memo);
  for (const [name, o] of memo) if (!ledger.done.has(name)) ledger.done.set(name, o);
  const log: DropLogEntry[] = [];
  const holds = deps.held
    ? await resolveZipHolds({
        ...{ store: deps.held, caseId: args.caseId, archiveId: id, zipRel, file: args.file },
        ...{ plans: run.plans, byName: run.byName, ledger, log },
      })
    : NO_HOLDS;
  const now = imports.filter((n) => !holds.undecided.has(n) && !holds.skipped.has(n));
  const { fresh, interrupted } = await importMembers(deps, args, zip, run, now, ledger, log, zipRel, memo);
  for (const r of run.refused) {
    if (ledger.done.has(r.name)) continue;
    log.push({ status: "FAILED", relpath: `${zipRel}!${r.name}`, reason: r.reason });
    await ledger.record(r.name, { ok: false, reason: r.reason }).catch(() => undefined);
  }
  const skips = run.plans.flatMap((p) => p.skips);
  if (fresh && skips.length) {
    log.push({
      status: "SKIPPED",
      relpath: zipRel,
      reason: `Velociraptor hunt export: ${skips.length} member(s) not read — ${huntSkipSummary(skips)}`,
    });
  }
  if (log.length) {
    await appendDropLog(args.dropDir, formatDropLogLines(log, new Date().toISOString())).catch((e) =>
      logLine(`[drop] log append failed: ${(e as Error).message}`),
    );
  }
  const waiting = await holds.finish(!interrupted);
  if (interrupted) return { ok: false, deferred: interrupted }; // stays in drop/; the next sweep resumes
  if (waiting) {
    const what = `${waiting} result file(s) held over the hunt artifact size limit`;
    return { ok: false, deferred: `${what} — Import anyway or Skip in the dashboard` };
  }
  remembered.delete(id);
  return outcome(imports, ledger.done, run.refused.length, zipRel);
}

/** Import every planned member not already in the ledger; true when this run did any work. */
async function importMembers(
  deps: HuntZipDeps,
  args: HuntZipArgs,
  zip: ZipFile,
  run: HuntRun,
  imports: readonly string[],
  ledger: HuntZipLedger,
  log: DropLogEntry[],
  zipRel: string,
  memo: Map<string, MemberOutcome>,
): Promise<{ fresh: boolean; interrupted?: string }> {
  let fresh = false;
  const total = imports.length;
  // Handled = recorded in the ledger (or this process's memo), imported or failed; refusals are not imports.
  let handled = imports.filter((n) => ledger.done.has(n)).length;
  if (total) args.onProgress?.({ done: handled, total });
  for (const name of imports) {
    if (ledger.done.has(name)) continue;
    fresh = true;
    args.onProgress?.({ done: handled, total, current: name });
    const debug: ImportDebugRecorder = createImportDebugRecorder();
    const res: MemberOutcome = await importHuntMember(deps, {
      caseId: args.caseId,
      dropDir: args.dropDir,
      zipRelpath: zipRel,
      zip,
      member: run.byName.get(name)!,
      modelCall: args.modelCall,
      debug,
    });
    memo.set(name, res);
    args.onProgress?.({ done: ++handled, total });
    if (!res.ok) log.push({ status: "FAILED", relpath: `${zipRel}!${name}`, reason: res.reason });
    try {
      await ledger.record(name, res);
    } catch (e) {
      // Without a record a restart would import this member again: stop, keep the zip in drop/,
      // and let the next sweep resume (this process remembers the member meanwhile).
      const why = `could not record progress (${(e as Error).message}); the rest resumes on the next sweep`;
      logLine(`[drop] ${zipRel}: ${why}`);
      return { fresh, interrupted: why };
    }
  }
  return { fresh };
}

function outcome(
  imports: readonly string[],
  done: ReadonlyMap<string, MemberOutcome>,
  refused: number,
  zipRel: string,
): DropOutcome {
  const ok = imports.filter((n) => done.get(n)?.ok).length;
  const skipped = imports.filter((n) => done.get(n)?.skipped).length; // #2746: the analyst's call
  const failed = imports.length - ok - skipped + refused;
  const where = `see drop-log.txt; failed members are in ${failedMembersFolder(zipRel)}/`;
  const notes = imports.flatMap((n) => {
    const o = done.get(n);
    return o?.ok && o.warning ? [`${n}: ${o.warning}`] : [];
  });
  const caveat = notes.length ? notes.join(" | ") : undefined;
  if (ok === 0 && failed === 0 && skipped > 0)
    return { ok: true, warning: `all ${skipped} hunt result file(s) were over the size limit and skipped` };
  if (ok === 0) {
    return {
      ok: false,
      reason: imports.length
        ? `no hunt result imported from ${basename(zipRel)} (${failed} failed — ${where})`
        : `hunt export holds no result file to import (${refused} member(s) refused)`,
    };
  }
  const summary = failed
    ? `${ok} of ${imports.length} hunt result file(s) imported, ${failed} failed — ${where}`
    : undefined;
  const warning = [summary, caveat].filter(Boolean).join(" | ");
  return warning ? { ok: true, warning } : { ok: true };
}
