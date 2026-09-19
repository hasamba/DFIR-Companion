// Per-row NTFS time hints for an MFT-shaped Velociraptor row (Windows.NTFS.MFT, DetectRaptor
// *.Detection.MFT): two independent reads of the $STANDARD_INFORMATION / $FILE_NAME stamps, applied
// to the mapped event in place. Lives outside velociraptorImport.ts, which sits at its size cap.
//
//   1. Timestomp — $SI Created earlier than $FN Created (backdating) or a zeroed sub-second on $SI.
//      Graded Medium + T1070.006 by timestompDetect (see its header for the reasoning).
//   2. Copied binary — $SI LastModified EARLIER than $SI Created. A file cannot be modified before it
//      exists; a copy can look that way because NTFS gives the copy a fresh Created ($SI and $FN) but
//      keeps the source's LastModified. That is what a renamed LOLBin or a dropped tool looks like
//      (every decoy in the ELPACO scenario, #1422). It is a LEAD, not a verdict: installers copy
//      binaries all day, so it changes no grade and adds no technique — the location and name rules
//      already grade attacker tools. It is distinct from timestomping: nothing was backdated.
//
// Both read the RAW strings (not pickTime, which drops the sub-second precision the truncation
// signal needs) and skip directories. The copy check reuses the timestomp threshold so clock jitter
// never fires it.

import { getCI, getPath, str } from "./siemImport.js";
import type { MappedEvent } from "./siemImport.js";
import { worst } from "./siemImport.js";
import { detectTimestomp, timestompThresholdMs } from "./timestompDetect.js";

type Row = Record<string, unknown>;

export interface CopiedBinaryVerdict {
  note: string;
}

const isoSecond = (ms: number): string => new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");

// $SI LastModified more than `thresholdMs` before $SI Created → the file was copied here.
export function detectCopiedBinary(
  siCreated: string | null | undefined,
  siModified: string | null | undefined,
  thresholdMs: number = timestompThresholdMs(),
): CopiedBinaryVerdict | null {
  const created = Date.parse((siCreated ?? "").toString());
  const modified = Date.parse((siModified ?? "").toString());
  if (!Number.isFinite(created) || !Number.isFinite(modified)) return null;
  if (modified + thresholdMs >= created) return null;
  return {
    note:
      `copied binary: modified ${isoSecond(modified)}, created ${isoSecond(created)} — a file cannot ` +
      `be modified before it exists; the copy kept its source's modified time`,
  };
}

// Top-level or nested spelling of one $SI/$FN column, as the artifact version emits it.
function stamp(row: Row, top: string, nested: string): string {
  return str(getCI(row, top)) || str(getPath(row, nested));
}

export function applyMftTimeHints(row: Row, m: MappedEvent): void {
  const isDir = getCI(row, "IsDir");
  if (isDir === true || str(isDir).toLowerCase() === "true") return;
  const si = stamp(row, "Created0x10", "SITimestamps.Created0x10");
  if (!si) return;
  const fn = stamp(row, "Created0x30", "FNTimestamps.Created0x30");
  const notes: string[] = [];
  if (fn) {
    const v = detectTimestomp(si, fn);
    if (v) {
      m.severity = worst(m.severity, v.severity);
      for (const id of v.mitre) if (!m.mitre.includes(id)) m.mitre.push(id);
      notes.push(v.note);
    }
  }
  const copy = detectCopiedBinary(si, stamp(row, "LastModified0x10", "SITimestamps.LastModified0x10"));
  if (copy) notes.push(copy.note);
  if (notes.length) m.description = `${m.description} — ${notes.join(" — ")}`.slice(0, 1200);
}
