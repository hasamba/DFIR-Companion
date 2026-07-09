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
