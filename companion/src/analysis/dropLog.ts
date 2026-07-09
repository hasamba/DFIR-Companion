// Pure formatting of drop-folder event lines, plus a thin append helper for the folder-visible
// history file `drop/drop-log.txt`. Mirrors the pure-logic/IO split used by dropScan.ts and
// dropStatus.ts: the walk + import + move stay in the server.ts closure, this module only formats
// and appends. Written directly into the drop folder (unlike drop-status.json, which lives in
// case state) so an analyst can see what happened to dropped files without opening the dashboard.

import { appendFile } from "node:fs/promises";
import { join } from "node:path";

/** The log file's basename inside `drop/`. Also added to dropScan.ts's IGNORED_BASENAMES. */
export const DROP_LOG_FILE = "drop-log.txt";

export type DropLogStatus = "IMPORTED" | "FAILED" | "PENDING";

export interface DropLogEntry {
  status: DropLogStatus;
  relpath: string;
  /** Present for FAILED and PENDING; optional for IMPORTED (e.g. "via <tool>" when resolved from pending). */
  reason?: string;
}

// "IMPORTED" is the longest status (8 chars); pad the others to match for column alignment.
const STATUS_WIDTH = 8;

// Collapse embedded newlines (and surrounding whitespace) to a single space so one logical event
// never splits across multiple physical lines in drop-log.txt. Real Error messages (Node/Zod/parser)
// are frequently multi-line, so this is applied at the one chokepoint all callers funnel through.
function sanitize(s: string): string {
  return s.replace(/\s*[\r\n]+\s*/g, " ").trim();
}

/** One formatted line per entry: "<iso-timestamp>  <STATUS>  <relpath>[  — <reason>]". Pure, no I/O. */
export function formatDropLogLines(entries: readonly DropLogEntry[], at: string): string[] {
  return entries.map((e) => {
    const status = e.status.padEnd(STATUS_WIDTH);
    const relpath = sanitize(e.relpath);
    const reason = e.reason ? `  — ${sanitize(e.reason)}` : "";
    return `${at}  ${status}  ${relpath}${reason}`;
  });
}

/** Append pre-formatted lines to drop/drop-log.txt, creating the file if it doesn't exist yet. */
export async function appendDropLog(dropDir: string, lines: readonly string[]): Promise<void> {
  if (lines.length === 0) return;
  await appendFile(join(dropDir, DROP_LOG_FILE), lines.join("\n") + "\n", "utf8");
}

/** Given one sweep's outcomes and the relpaths already logged as PENDING for this case, returns the
 *  DropLogEntry[] to append this sweep and the updated "already logged pending" set (a pending file
 *  logs once; it drops out once resolved by the caller, so if it becomes pending again later it will
 *  log again). Pure — the caller replaces its stored set with `nextLoggedPending`, no mutation here. */
export function buildSweepLogEntries(
  sweep: {
    imported: readonly string[];
    failed: readonly { relpath: string; reason: string }[];
    pendingRawInputs: readonly { relpath: string; ext: string; configured: boolean }[];
  },
  loggedPending: ReadonlySet<string>,
): { entries: DropLogEntry[]; nextLoggedPending: Set<string> } {
  const entries: DropLogEntry[] = [
    ...sweep.imported.map((relpath): DropLogEntry => ({ status: "IMPORTED", relpath })),
    ...sweep.failed.map((f): DropLogEntry => ({ status: "FAILED", relpath: f.relpath, reason: f.reason })),
    ...sweep.pendingRawInputs
      .filter((p) => !loggedPending.has(p.relpath))
      .map((p): DropLogEntry => ({
        status: "PENDING",
        relpath: p.relpath,
        reason: p.configured
          ? `awaiting tool run for ${p.ext} (drop banner: Run)`
          : `no tool configured for ${p.ext} (drop banner: Configure)`,
      })),
  ];
  const nextLoggedPending = new Set(loggedPending);
  for (const p of sweep.pendingRawInputs) nextLoggedPending.add(p.relpath);
  return { entries, nextLoggedPending };
}
