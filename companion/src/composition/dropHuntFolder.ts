/**
 * An unzipped Velociraptor hunt export in the drop folder (#2714). The sweep imports one copy of
 * each artifact (analysis/veloHuntLayout.ts) and moves every other copy, the per-client metadata and
 * `hunt_info.json` to `drop/_skipped/<full relpath>`. Nothing is deleted.
 *
 * WHOLE HUNTS ONLY. A hunt is handled on a sweep where every one of its listed members has settled;
 * otherwise all its members wait. A half-copied tree would otherwise import a hunt-wide copy before
 * the per-client files it duplicates arrive. (A file that has not appeared at all cannot be waited
 * for — the manual tells analysts to drop the zip, or move a finished folder in as one operation.)
 *
 * COPIES FIRST, THEN METADATA, THEN IMPORTS. The move is the dedup, so the order is what makes a crash
 * safe: once the duplicate copies are gone, whatever is left can only import once, even if the
 * metadata that marks the folder as a hunt was moved too. A copy that cannot be moved holds the whole
 * hunt (imports and metadata) until a later sweep moves it, so a left-behind copy is never imported
 * beside the copy that was chosen.
 *
 * A member that is stuck (handled, but its move out of drop/ failed — #2281) still counts when the
 * plan picks a copy, but never holds the hunt and is never imported again.
 */
import type { DropFileStat, StuckDropFile } from "../analysis/dropScan.js";
import { DROP_SKIPPED } from "../analysis/dropScan.js";
import { appendDropLog, formatDropLogLines, type DropLogEntry } from "../analysis/dropLog.js";
import { huntSkipSummary, planHuntExports, type HuntPlan } from "../analysis/veloHuntLayout.js";
import { logLine } from "../logging/serverLogger.js";

export interface HuntDropInput {
  dropDir: string;
  /** Every file the sweep listed (settled or not). */
  listing: readonly DropFileStat[];
  /** The settled files, stuck ones already removed. */
  ready: readonly DropFileStat[];
  stuck: ReadonlyMap<string, StuckDropFile>;
  /** Move one file (native relpath) to drop/_skipped/<relpath>. */
  skipMove: (relpath: string) => Promise<void>;
  /**
   * Put the plan's imports over the hunt artifact size limits on hold (#2755); returns every import
   * (posix path) that must not be released — held now, or chosen to be held but not yet moved.
   */
  hold?: (plan: HuntPlan) => Promise<ReadonlySet<string>>;
}

const posix = (relpath: string): string => relpath.replace(/\\/g, "/");

/**
 * `ready` with every hunt member removed except the imports of the hunts handled this sweep, whose
 * copies and metadata have been moved to `_skipped/`. One SKIPPED drop-log line per handled hunt.
 */
export async function prepareHuntDrops(input: HuntDropInput): Promise<DropFileStat[]> {
  const native = new Map(input.listing.map((f) => [posix(f.relpath), f.relpath]));
  const plans = planHuntExports([...native.keys()]);
  if (plans.length === 0) return [...input.ready];
  const readySet = new Set(input.ready.map((f) => posix(f.relpath)));
  const stuck = new Set([...input.stuck.keys()].map(posix));
  const members = new Set(plans.flatMap((p) => p.members));
  const released = new Set<string>();
  const log: DropLogEntry[] = [];
  for (const plan of plans) {
    const live = plan.members.filter((m) => !stuck.has(m));
    if (!live.every((m) => readySet.has(m))) continue; // not settled as a whole yet
    const moved = await moveSkips(plan, stuck, native, input.skipMove);
    if (moved === null) continue; // a copy is still in place: hold the hunt
    const onHold = (await input.hold?.(plan)) ?? new Set<string>(); // after the copies moved (#2755)
    for (const imp of plan.imports) if (!stuck.has(imp.path) && !onHold.has(imp.path)) released.add(imp.path);
    if (moved.length) log.push(skippedLine(plan, moved));
  }
  if (log.length) {
    await appendDropLog(input.dropDir, formatDropLogLines(log, new Date().toISOString())).catch((e) =>
      logLine(`[drop] log append failed: ${(e as Error).message}`),
    );
  }
  return input.ready.filter((f) => {
    const p = posix(f.relpath);
    return !members.has(p) || released.has(p);
  });
}

/** The skips moved (copies first, then metadata), or null when a copy could not be moved. */
async function moveSkips(
  plan: HuntPlan,
  stuck: ReadonlySet<string>,
  native: ReadonlyMap<string, string>,
  skipMove: HuntDropInput["skipMove"],
): Promise<HuntPlan["skips"] | null> {
  const todo = plan.skips.filter((s) => !stuck.has(s.path));
  const copies = todo.filter((s) => s.reason !== "metadata");
  const metadata = todo.filter((s) => s.reason === "metadata");
  const moved: HuntPlan["skips"] = [];
  for (const group of [copies, metadata]) {
    for (const s of group) {
      try {
        await skipMove(native.get(s.path) ?? s.path);
        moved.push(s);
      } catch (e) {
        logLine(`[drop] could not move ${s.path} to ${DROP_SKIPPED}/: ${(e as Error).message}`);
        if (s.reason !== "metadata") return null; // never import beside a copy left in place
      }
    }
  }
  return moved;
}

function skippedLine(plan: HuntPlan, moved: HuntPlan["skips"]): DropLogEntry {
  return {
    status: "SKIPPED",
    relpath: plan.root ? `${plan.root}/` : "./",
    reason:
      `Velociraptor hunt export: ${plan.imports.length} result file(s) to import, ` +
      `${moved.length} moved to ${DROP_SKIPPED}/ — ${huntSkipSummary(moved)}`,
  };
}
