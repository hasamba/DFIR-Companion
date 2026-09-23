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
//   The copy note LEADS with its verdict — "copied file, not timestomp" — and appears only when $FN
//   was compared and no timestomp fired on the row (#1558). Scenario 019's model read five copies of
//   cmd.exe, all carrying cmd.exe's 2025-12-05 modified time, as five timestomps: the old note put
//   its meaning last, where the prompt clip cut it, and never said "not timestomping".
//
//   3. Shared source mtime (markSharedSourceMtime, a cross-row pass over one import) — 2+ copied
//      rows with one modified second are copies of ONE source file. Each gets a registered derived
//      note, so the prompt clip keeps it (#1558).
//
// Both read the RAW strings (not pickTime, which drops the sub-second precision the truncation
// signal needs) and skip directories. The copy check reuses the timestomp threshold so clock jitter
// never fires it.

import { getCI, getPath, str } from "./siemImport.js";
import type { MappedEvent } from "./siemImport.js";
import { worst } from "./siemImport.js";
import { detectTimestomp, timestompThresholdMs } from "./timestompDetect.js";
import { appendDerivedNote } from "./derivedNote.js";

type Row = Record<string, unknown>;

export interface CopiedBinaryVerdict {
  note: string;
  modified: string; // the $SI LastModified second, the source file's own — the cross-row group key
}

// Registered in DERIVED_NOTE_NAMES, so the base-text clip and the prompt clip keep it (#1558).
export const SHARED_SOURCE_MTIME_MARKER = "[shared source mtime:";
const COPIED_VERDICT =
  "copied file, not timestomp ($SI Created = $FN Created; modified time inherited from the source)";
const UNCHECKED_COPY_VERDICT = "copied file ($FN not collected, timestomp not checked)";
// The source modified second of each event that carries the copied-file note. Keyed by identity,
// so an adversary-chosen description can never enrol a row in a group.
const copiedMtime = new WeakMap<MappedEvent, string>();

const isoSecond = (ms: number): string => new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");

// $SI LastModified more than `thresholdMs` before $SI Created → the file was copied here. The note
// claims "not timestomp", so apply it only after $FN was compared and no timestomp fired.
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
      `${COPIED_VERDICT}: modified ${isoSecond(modified)}, created ${isoSecond(created)} — a file ` +
      `cannot be modified before it exists`,
    modified: isoSecond(modified),
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
  const v = fn ? detectTimestomp(si, fn) : null;
  if (v) {
    m.severity = worst(m.severity, v.severity);
    for (const id of v.mitre) if (!m.mitre.includes(id)) m.mitre.push(id);
    m.description = `${m.description} — ${v.note}`.slice(0, 1200);
    return; // a timestomped row keeps its label alone: "not timestomp" beside it would contradict it
  }
  const copy = detectCopiedBinary(si, stamp(row, "LastModified0x10", "SITimestamps.LastModified0x10"));
  if (!copy) return;
  // Without $FN the timestomp check never ran, so the note states the copy and makes no
  // "not timestomp" claim it cannot back (#1558).
  const note = fn ? copy.note : copy.note.replace(COPIED_VERDICT, UNCHECKED_COPY_VERDICT);
  m.description = `${m.description} — ${note}`.slice(0, 1200);
  copiedMtime.set(m, copy.modified);
}

/**
 * Cross-row pass over ONE import's mapped events (#1558): when 2+ copied-file rows share a modified
 * second, they are copies of one source file, and each gets a `[shared source mtime: …]` note. Runs
 * before aggregation, after every row is mapped. Unmarked events come back as the same objects;
 * a marked one is a new object.
 */
export function markSharedSourceMtime(events: readonly MappedEvent[]): MappedEvent[] {
  const counts = new Map<string, number>();
  for (const e of events) {
    const k = copiedMtime.get(e);
    if (k) counts.set(k, (counts.get(k) ?? 0) + 1);
  }
  return events.map((e) => {
    const k = copiedMtime.get(e);
    const n = k ? (counts.get(k) ?? 0) : 0;
    if (n < 2) return e;
    const note = `${n} copies of one source file, not timestomping`;
    return { ...e, description: appendDerivedNote(e.description, SHARED_SOURCE_MTIME_MARKER, note) };
  });
}
