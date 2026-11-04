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
import { isSafeDropRelpath, resolveInsideDropDir } from "../storage/dropRelpath.js";
import { CaseKeyedMap, type PerCaseMap } from "../storage/caseKeyedState.js";
import type { DropFingerprint, ProcessedVersion, StuckDropFile } from "../analysis/dropScan.js";

export type { DropFingerprint, ProcessedVersion };
import { logLine } from "../logging/serverLogger.js";

export interface DropStuckTracker {
  /** Per case (keyed like the settle map, #1866): relpath → the stat it had when its move failed. */
  readonly stuck: PerCaseMap<Map<string, StuckDropFile>>;
  /**
   * Remember a file whose move failed, if it is still a regular file inside drop/ — and, when the
   * caller knows which version it imported (`processed`), only if the file is still that version.
   * `processed: null` means the caller looked and could not tell: never remember it then (#2283).
   */
  record(dropDir: string, relpath: string, ok: boolean, processed?: ProcessedVersion): Promise<void>;
  /**
   * The version a caller is about to process, for `record` (#2283): size + mtime of a regular file
   * whose parent is inside drop/ on disk, else null — a traversal relpath, a symlinked parent or a
   * symlink at the file itself, a missing file, a stat error.
   */
  fingerprint(dropDir: string, relpath: string): Promise<DropFingerprint | null>;
  /** Retry the move (only the move — never the import) of each held file; quiet when it fails again. */
  retry(
    dropDir: string,
    held: ReadonlyMap<string, StuckDropFile>,
    move: (dropDir: string, relpath: string, ok: boolean, processed?: ProcessedVersion) => Promise<void>,
  ): Promise<void>;
}

export function createDropStuckTracker(casesRoot: () => string): DropStuckTracker {
  const stuck = new CaseKeyedMap<Map<string, StuckDropFile>>(casesRoot);

  async function record(
    dropDir: string,
    relpath: string,
    ok: boolean,
    processed?: ProcessedVersion,
  ): Promise<void> {
    // Unverified version: holding it back could archive records nobody processed (#2283).
    if (processed === null) return;
    // Only a relpath inside drop/: a refused traversal relpath (#919) must not even be stat'd.
    if (!isSafeDropRelpath(relpath)) return;
    const st = await lstat(join(dropDir, relpath)).catch(() => null);
    if (!st?.isFile()) return;
    // Changed since it was imported (a writer still appending, the #2270 growth refusal): holding
    // it back would let the move retry archive the new records unread. Leave it to settle and be
    // imported again — a duplicate of the old part beats lost evidence.
    if (processed && (st.size !== processed.size || st.mtimeMs !== processed.mtimeMs)) return;
    const caseId = basename(dirname(dropDir)); // dropDirOf: <caseDir>/drop, active or archived
    const next = new Map(stuck.get(caseId) ?? []);
    next.set(relpath, { size: st.size, mtimeMs: st.mtimeMs, ok });
    stuck.set(caseId, next);
  }

  async function retry(
    dropDir: string,
    held: ReadonlyMap<string, StuckDropFile>,
    move: (dropDir: string, relpath: string, ok: boolean, processed?: ProcessedVersion) => Promise<void>,
  ): Promise<void> {
    for (const [relpath, s] of held) {
      // A moved file leaves the listing, so excludeStuck drops its entry on the next sweep.
      await move(dropDir, relpath, s.ok, s).then(
        () => logLine(`[drop] moved previously stuck ${relpath}`),
        () => {},
      );
    }
  }

  async function fingerprint(dropDir: string, relpath: string): Promise<DropFingerprint | null> {
    try {
      // realpath containment of the parent (#919), then lstat so a link at the file is not a file.
      const st = await lstat(await resolveInsideDropDir(dropDir, relpath));
      return st.isFile() ? { size: st.size, mtimeMs: st.mtimeMs } : null;
    } catch {
      return null;
    }
  }

  return { stuck, record, retry, fingerprint };
}

/** Join the reasons a sweep has for one file into its single drop-log / drop-status entry. */
export function joinReasons(...parts: (string | undefined)[]): string {
  return parts.filter(Boolean).join("; ");
}
