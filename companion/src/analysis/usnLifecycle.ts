// File lifecycle from the NTFS change journal (#909 item 7).
//
// The USN journal records every change to every file, and the importer was keeping a name and a
// reason string. That is enough to say "something happened to evil.exe" and not enough to say what
// — which is the entire question when a dropped payload is renamed to blend in, an archive is
// staged and moved, or Prefetch is deleted to hide an execution.
//
// What makes lifecycle reconstruction possible is the FILE REFERENCE: a 64-bit value combining the
// MFT entry number with a sequence number. It is the file's identity, and it survives renames — so
// a RENAME_OLD_NAME record and the RENAME_NEW_NAME that follows it describe one file under two
// names, and pairing them is how you learn that `invoice.pdf.exe` became `svchost.exe`.
//
// ─────────────────────────── FIVE THINGS THAT LOOK LIKE FACTS AND ARE NOT ───────────────────────
//
//  1. REASONS ACCUMULATE. A record's Reason field is not "what just happened" — it is the union of
//     everything that has happened to that file since the journal last closed it. A record carrying
//     FILE_CREATE|DATA_EXTEND|CLOSE does not mean three things happened at that instant, and the
//     order of the flags within one record is not a sequence. Microsoft documents this explicitly.
//     So this module reports which reasons a record carried and never invents an ordering inside
//     one.
//  2. THE ENTRY NUMBER IS REUSED. NTFS reallocates MFT entries. Two records sharing an entry number
//     are the same file only if the SEQUENCE number also matches — that is what the sequence number
//     is for. Keying on the entry alone stitches a deleted file's history onto whatever took its
//     place.
//  3. A HARD LINK gives one file reference several names and parents. A "rename" that is really a
//     second link looks identical from a single record.
//  4. THE JOURNAL ROLLS OVER. Old records are discarded, so the first record for a file is very
//     often not its creation. An absent create is not evidence the file was not created.
//  5. AN MFT TIMESTAMP IS NOT A DELETION TIME, and a $LogFile sequence number is not a clock. The
//     journal's own UpdateTimestamp is the only wall-clock this module will use.

import type { Severity } from "./stateTypes.js";

/** One parsed journal record. */
export interface UsnRecord {
  name: string;
  entry: string; // MFT entry number
  sequence: string; // MFT sequence number — the half that makes the entry unique
  parentEntry: string;
  parentSequence: string;
  usn: string; // the journal's own ordering value; NOT a timestamp
  timestamp: string; // ISO, from the record's UpdateTimestamp
  reasons: string[]; // normalized reason flags carried by this record
  volume: string; // which volume this journal came from
}

/** The identity that survives a rename. */
export function fileReference(r: Pick<UsnRecord, "volume" | "entry" | "sequence">): string {
  // Volume included: entry 12345 on C: and on D: are different files, and a collection can contain
  // journals from both.
  return `${r.volume}|${r.entry}-${r.sequence}`;
}

// Parsers disagree on spelling: the Win32 constants are FILE_CREATE, MFTECmd writes FileCreate, and
// some exports drop the separators entirely. The lookup is keyed on the LETTERS ONLY, so all three
// spellings land on the same canonical reason.
const REASON_ALIASES: Record<string, string> = {
  filecreate: "FILE_CREATE",
  create: "FILE_CREATE",
  filedelete: "FILE_DELETE",
  delete: "FILE_DELETE",
  renameoldname: "RENAME_OLD_NAME",
  renamenewname: "RENAME_NEW_NAME",
  dataoverwrite: "DATA_OVERWRITE",
  dataextend: "DATA_EXTEND",
  datatruncation: "DATA_TRUNCATION",
  close: "CLOSE",
  basicinfochange: "BASIC_INFO_CHANGE",
  securitychange: "SECURITY_CHANGE",
  hardlinkchange: "HARD_LINK_CHANGE",
  streamchange: "STREAM_CHANGE",
  objectidchange: "OBJECT_ID_CHANGE",
  indexablechange: "INDEXABLE_CHANGE",
  compressionchange: "COMPRESSION_CHANGE",
  encryptionchange: "ENCRYPTION_CHANGE",
  reparsepointchange: "REPARSE_POINT_CHANGE",
  namedstreamchange: "NAMED_STREAM_CHANGE",
  extendedattributechange: "EA_CHANGE",
};

/** Split and normalize a reason string. The separator varies by parser. */
export function parseReasons(raw: string): string[] {
  const out = new Set<string>();
  for (const part of String(raw ?? "").split(/[|,;+\s]+/)) {
    const k = part.trim().toLowerCase().replace(/[^a-z]/g, "");
    if (!k) continue;
    out.add(REASON_ALIASES[k] ?? part.trim().toUpperCase());
  }
  return [...out];
}

export interface RenamePair {
  reference: string;
  oldName: string;
  newName: string;
  timestamp: string;
  volume: string;
  severity: Severity;
  note: string;
}

// An extension that changes what the operating system will DO with the file. A rename that only
// changes the stem is housekeeping; one that turns a document into an executable, or an executable
// into something that looks like a document, is the shape worth reporting.
const EXECUTABLE_EXT = /\.(?:exe|dll|scr|com|bat|cmd|ps1|vbs|js|jse|wsf|hta|msi|cpl|sys)$/i;

function ext(name: string): string {
  const m = /\.[^.]+$/.exec(name.trim());
  return m ? m[0].toLowerCase() : "";
}

/**
 * Pair RENAME_OLD_NAME with the RENAME_NEW_NAME that follows it.
 *
 * Matched on the FILE REFERENCE — entry AND sequence — never the entry alone, because NTFS reuses
 * entries and keying on one stitches a deleted file's history onto its replacement.
 *
 * An unpaired half is dropped rather than guessed at. The journal rolls over, so a collection
 * routinely begins or ends mid-rename, and inventing the missing name would be fabricating the one
 * fact the pair exists to establish.
 */
export function pairRenames(records: readonly UsnRecord[]): RenamePair[] {
  const pending = new Map<string, UsnRecord>();
  const out: RenamePair[] = [];

  // Journal order, not wall-clock: two records can share a timestamp, and the USN is what orders
  // them. It is a byte offset into the journal, and it is NOT a time.
  const ordered = [...records].sort((a, b) => {
    const d = (Number(a.usn) || 0) - (Number(b.usn) || 0);
    return d !== 0 ? d : 0;
  });

  for (const r of ordered) {
    const ref = fileReference(r);
    if (r.reasons.includes("RENAME_OLD_NAME")) {
      pending.set(ref, r);
      continue;
    }
    if (!r.reasons.includes("RENAME_NEW_NAME")) continue;
    const old = pending.get(ref);
    if (!old) continue; // the other half rolled out of the journal — see the header
    pending.delete(ref);
    if (old.name === r.name) continue; // a hard-link change can look like this; it is not a rename

    const from = ext(old.name);
    const to = ext(r.name);
    const becameExecutable = !EXECUTABLE_EXT.test(old.name) && EXECUTABLE_EXT.test(r.name);
    const stoppedLookingExecutable = EXECUTABLE_EXT.test(old.name) && !EXECUTABLE_EXT.test(r.name);
    const changedKind = from !== to && (becameExecutable || stoppedLookingExecutable);

    out.push({
      reference: ref,
      oldName: old.name,
      newName: r.name,
      // The journal's own timestamp on the record that completed the rename.
      timestamp: r.timestamp,
      volume: r.volume,
      severity: changedKind ? "Low" : "Info",
      note:
        `renamed from ${old.name} to ${r.name}` +
        (becameExecutable
          ? " — the file was not executable before the rename and is afterwards"
          : stoppedLookingExecutable
            ? " — an executable was renamed to something that does not look like one"
            : "") +
        ". Renames are ordinary; this records the pairing, not an intent.",
    });
  }
  return out;
}

export interface LifecycleSummary {
  reference: string;
  names: string[]; // every name this reference was seen under, in journal order
  reasons: string[]; // the union of reasons across its records
  first: string; // earliest record timestamp
  last: string; // latest record timestamp
  createdSeen: boolean;
  deletedSeen: boolean;
  note: string;
}

/**
 * Everything the journal recorded about one file reference.
 *
 * `createdSeen` and `deletedSeen` mean the journal CONTAINED such a record — not that the file was
 * or was not created or deleted. The journal rolls over, so their absence says nothing, and the
 * note says so rather than leaving the reader to assume.
 */
export function summarizeLifecycle(records: readonly UsnRecord[]): LifecycleSummary[] {
  const byRef = new Map<string, UsnRecord[]>();
  for (const r of records) {
    const ref = fileReference(r);
    const list = byRef.get(ref) ?? [];
    list.push(r);
    byRef.set(ref, list);
  }

  const out: LifecycleSummary[] = [];
  for (const [ref, list] of byRef) {
    list.sort((a, b) => (Number(a.usn) || 0) - (Number(b.usn) || 0));
    const names: string[] = [];
    const reasons = new Set<string>();
    for (const r of list) {
      if (!names.includes(r.name)) names.push(r.name);
      for (const x of r.reasons) reasons.add(x);
    }
    const times = list.map((r) => r.timestamp).filter(Boolean).sort();
    const createdSeen = reasons.has("FILE_CREATE");
    const deletedSeen = reasons.has("FILE_DELETE");

    out.push({
      reference: ref,
      names,
      reasons: [...reasons],
      first: times[0] ?? "",
      last: times[times.length - 1] ?? "",
      createdSeen,
      deletedSeen,
      note:
        `${names.length > 1 ? `known under ${names.length} names (${names.join(" → ")})` : names[0] ?? "(unnamed)"}` +
        `; journal reasons: ${[...reasons].join(", ") || "none recorded"}` +
        (createdSeen ? "" : "; no creation record is present, which the journal's rollover alone explains") +
        (deletedSeen ? "; a deletion record is present" : "") +
        ". Reasons accumulate within a record, so their order inside one is not a sequence.",
    });
  }
  return out;
}
