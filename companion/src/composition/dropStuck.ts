/**
 * Handled drop files that could not be moved out of drop/ (#2281).
 *
 * THE MOVE IS THE DEDUP (see dropFolder.ts): an imported file goes to _processed/, a failed one to
 * _failed/, and the scanner never sees it again. When the move fails — a Windows lock held by AV or
 * a sync client, a read-only _processed/, the #2270 "changed size while being moved" refusal — the
 * file stays in the watched area, and the settle check would import it again two polls later and
 * every two polls after that. This tracker remembers such a file by size + mtime, so the sweep can
 * hold it back while it is unchanged (analysis/dropScan.ts `excludeStuck`) and finish the move once
 * whatever blocked it is gone.
 *
 * Memory only, like the settle map: after a server restart a still-stuck file is imported once more.
 */
import { basename, dirname, join } from "node:path";
import { lstat } from "node:fs/promises";
import { isSafeDropRelpath } from "../storage/dropRelpath.js";
import { CaseKeyedMap, type PerCaseMap } from "../storage/caseKeyedState.js";
import type { StuckDropFile } from "../analysis/dropScan.js";
import { logLine } from "../logging/serverLogger.js";

export interface DropStuckTracker {
  /** Per case (keyed like the settle map, #1866): relpath → the stat it had when its move failed. */
  readonly stuck: PerCaseMap<Map<string, StuckDropFile>>;
  /** Remember a file whose move failed, if it is still a regular file inside drop/. */
  record(dropDir: string, relpath: string, ok: boolean): Promise<void>;
  /** Retry the move (only the move — never the import) of each held file; quiet when it fails again. */
  retry(
    dropDir: string,
    held: ReadonlyMap<string, StuckDropFile>,
    move: (dropDir: string, relpath: string, ok: boolean) => Promise<void>,
  ): Promise<void>;
}

export function createDropStuckTracker(casesRoot: () => string): DropStuckTracker {
  const stuck = new CaseKeyedMap<Map<string, StuckDropFile>>(casesRoot);

  async function record(dropDir: string, relpath: string, ok: boolean): Promise<void> {
    // Only a relpath inside drop/: a refused traversal relpath (#919) must not even be stat'd.
    if (!isSafeDropRelpath(relpath)) return;
    const st = await lstat(join(dropDir, relpath)).catch(() => null);
    if (!st?.isFile()) return;
    const caseId = basename(dirname(dropDir)); // dropDirOf: <caseDir>/drop, active or archived
    const next = new Map(stuck.get(caseId) ?? []);
    next.set(relpath, { size: st.size, mtimeMs: st.mtimeMs, ok });
    stuck.set(caseId, next);
  }

  async function retry(
    dropDir: string,
    held: ReadonlyMap<string, StuckDropFile>,
    move: (dropDir: string, relpath: string, ok: boolean) => Promise<void>,
  ): Promise<void> {
    for (const [relpath, s] of held) {
      // A moved file leaves the listing, so excludeStuck drops its entry on the next sweep.
      await move(dropDir, relpath, s.ok).then(
        () => logLine(`[drop] moved previously stuck ${relpath}`),
        () => {},
      );
    }
  }

  return { stuck, record, retry };
}

/** Join the reasons a sweep has for one file into its single drop-log / drop-status entry. */
export function joinReasons(...parts: (string | undefined)[]): string {
  return parts.filter(Boolean).join("; ");
}
