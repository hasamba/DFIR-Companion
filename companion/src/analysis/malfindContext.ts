// What a malfind row actually observed, stated so an analyst can weigh it (#909 item 4).
//
// malfind reports memory regions that are PRIVATE and EXECUTABLE. That is the shape of process
// injection, and it is also the shape of every JIT compiler, several AV engines, .NET, and any
// program that generates code at runtime. The row is a region description, not a verdict.
//
// The Companion already knew this in one place and not another: the memory next-step guidance
// acknowledges the benign JIT/AV cases, while the importer stamped every malfind row High T1055 and
// said nothing else. This module closes that gap by attaching the region's OBSERVED characteristics
// and what they do and do not support — the severity policy is unchanged.
//
// ─────────────────────────── THE RULE ABOUT ABSENCE ───────────────────────────
//
// A missing MZ header, a non-RWX protection, or an empty preview NEVER establishes that a region is
// clean, and this module must never phrase them that way. malfind captures a short preview from the
// START of a region; shellcode does not begin with MZ, a reflectively-loaded image can be mapped
// without its header, and the preview says nothing at all about the remaining bytes. So a weak
// indicator lowers CONFIDENCE, and is reported as "does not corroborate", never as "is clean".
//
// The distinction the whole module exists to preserve: observed region characteristics are facts;
// confirmed malicious injection is a conclusion. These notes only ever report the first.

export type Row = Record<string, unknown>;

/** How much the region's own characteristics corroborate injection. Never a verdict. */
export type MalfindConfidence = "corroborated" | "baseline" | "uncorroborated";

/**
 * Evidence about the SAME process from other tables in the SAME memory image. The issue asks for
 * confidence to be strengthened by process context, network behaviour and independent detections;
 * without this the note could only ever tell the analyst to go and check those themselves.
 */
export interface MalfindCorroboration {
  networkPid?: boolean; // this PID also appears in the image's connection table
  suspiciousCommandLine?: boolean; // this PID's command line graded suspicious
}

export interface MalfindContext {
  confidence: MalfindConfidence;
  observations: string[]; // the facts read off the row, in the order they were checked
  note: string; // the full sentence: observations then the closing
  // A SHORT clause placed immediately after the lead, because synthesis and the case reports
  // truncate a description at 240 characters. With the caveat only at the end, those surfaces saw
  // the categorical opening and none of the qualification — the exact inconsistency this item is
  // meant to remove.
  summary: string;
}

function getCI(row: Row, key: string): unknown {
  for (const k of Object.keys(row)) if (k.toLowerCase() === key.toLowerCase()) return row[k];
  return undefined;
}

function cell(row: Row, keys: string[]): string {
  for (const k of keys) {
    const v = getCI(row, k);
    if (v !== undefined && v !== null) {
      const s = String(v).trim();
      if (s && !/^(?:-|n\/?a|none|unknown)$/i.test(s)) return s;
    }
  }
  return "";
}

// Writable AND executable at once. The combination is what makes a region interesting: code that
// can rewrite itself, or a buffer that was written and then run.
const RWX_RE = /execute_?read_?write|\brwx\b|PAGE_EXECUTE_READWRITE/i;
// Executable but not writable — still private executable memory, but a weaker shape.
const EXEC_RE = /execute/i;
// VAD tags are POOL tags, not a private-versus-mapped classification: Volatility casts both VadS
// and VadF to _MMVAD_SHORT, and only the longer VAD structures carry the mapped-file fields. So the
// tag is reported as context and never used to decide. `PrivateMemory` is the field malfind itself
// tests, and it is read INDEPENDENTLY of the tag — gating it behind "no tag" meant that on standard
// Volatility 3 rows, which always carry a tag, the authoritative value was never consulted.
const PRIVATE_MEM_KEYS = ["PrivateMemory", "private_memory", "Private"];

// The preview malfind prints. Any of these columns may carry it depending on tool and renderer.
const PREVIEW_KEYS = ["Hexdump", "hexdump", "Disasm", "disasm", "Data", "data", "Bytes", "bytes"];
// Volatility 3 also emits a scalar `Notes` column carrying its OWN read of the first bytes —
// "MZ header", "Function prologue". On a text-rendered import the multiline hexdump is dropped by
// the row parser, so Notes is often the only content evidence that survives; reading it is what
// stops the note claiming no preview existed when one did.
const NOTE_KEYS = ["Notes", "notes", "Note", "note"];

/** True when the captured preview starts with an MZ image header. */
function startsWithMz(preview: string): boolean {
  const p = preview.trim();
  if (!p) return false;
  if (/^MZ/.test(p)) return true;
  // Volatility's text hexdump prefixes each row with an ADDRESS: "0x1f0000  4d 5a 90 00". Strip a
  // leading 0x-address and any separator, then require 4d 5a as the FIRST bytes. The previous
  // pattern allowed one arbitrary leading byte, so "90 4d 5a ..." — a region starting with a NOP —
  // was reported as beginning with an image header.
  const body = p.replace(/^0x[0-9a-f]+\s*[:|]?\s*/i, "");
  return /^4d\s*5a/i.test(body);
}

/**
 * Read the region characteristics off a malfind row.
 *
 * Returns the observations and a note. Severity is NOT this module's business: the caller keeps
 * whatever policy it has, and this only explains what the row does and does not show.
 */
export function malfindContext(row: Row, corroboration: MalfindCorroboration = {}): MalfindContext {
  const protection = cell(row, ["Protection", "protection", "Prot"]);
  const tag = cell(row, ["Tag", "tag", "VadTag", "vad_tag"]);
  const preview = cell(row, PREVIEW_KEYS);
  const pluginNote = cell(row, NOTE_KEYS);
  const commit = cell(row, ["CommitCharge", "commit_charge"]);
  const privateMem = cell(row, PRIVATE_MEM_KEYS);

  const observations: string[] = [];
  // Two separate counts, because they are different kinds of evidence.
  //
  // `selection` counts the characteristics malfind SELECTED the region on: private, and executable.
  // Every row it returns has them by construction, so treating them as corroboration made every row
  // "corroborated" — including MsMpEng.exe, the textbook benign case. They establish the baseline,
  // not confidence.
  //
  // `independent` counts evidence malfind did NOT select on: an image header in the content, a
  // network connection held by the same process, a suspicious command line. Only these can raise
  // confidence, which is what the issue means by strengthening it with process context, network
  // behaviour or independent detections.
  let selection = 0;
  let independent = 0;

  if (protection) {
    if (RWX_RE.test(protection)) {
      observations.push(`writable and executable (${protection})`);
      selection++;
    } else if (EXEC_RE.test(protection)) {
      observations.push(`executable but not writable (${protection})`);
    } else {
      observations.push(`protection recorded as ${protection}, which does not corroborate injection`);
    }
  } else {
    observations.push("protection was not recorded");
  }

  // The authoritative field, read on its own terms.
  if (privateMem) {
    if (/^(?:1|true|yes)$/i.test(privateMem)) {
      observations.push("private memory — no file on disk explains it");
      selection++;
    } else if (/^(?:0|false|no)$/i.test(privateMem)) {
      observations.push("file-backed, which many legitimate loaders produce");
    }
  }
  // The tag is context only — see PRIVATE_MEM_KEYS.
  if (tag) observations.push(`VAD tag ${tag}`);

  if (pluginNote && /mz\s*header/i.test(pluginNote)) {
    observations.push(`the tool reported "${pluginNote}" for the first bytes`);
    independent++;
  } else if (preview && startsWithMz(preview)) {
    observations.push("the captured preview begins with an MZ image header");
    independent++;
  } else if (pluginNote) {
    observations.push(`the tool reported "${pluginNote}" for the first bytes`);
  } else if (!preview) {
    observations.push(
      "no content preview reached the import, so the region's contents are unknown from this row alone",
    );
  } else {
    observations.push(
      "the captured preview does not begin with an MZ header — this does not indicate the region " +
        "is clean, because shellcode has no header and the preview covers only the start of the region",
    );
  }

  if (corroboration.networkPid) {
    observations.push("the same process also holds a network connection in this image");
    independent++;
  }
  if (corroboration.suspiciousCommandLine) {
    observations.push("the same process also has a suspicious command line in this image");
    independent++;
  }

  if (commit) observations.push(`commit charge ${commit}`);

  const confidence: MalfindConfidence =
    independent >= 1 ? "corroborated" : selection >= 1 ? "baseline" : "uncorroborated";

  const closing =
    confidence === "corroborated"
      ? "Evidence beyond malfind's own selection criteria points the same way. Confirm with the " +
        "process context, its network behaviour, and any independent detection before concluding."
      : confidence === "baseline"
        ? "This is suspicious memory requiring interpretation rather than a verdict. JIT " +
          "compilers, .NET and some AV engines produce the same shape."
        : "The region's own characteristics do not corroborate injection, and they do not clear it " +
          "either. malfind only reports a region it already found suspicious, so this still needs " +
          "examining — the row simply carries nothing further to weigh it with.";

  const summary =
    confidence === "corroborated"
      ? "independent evidence points the same way; confirm before concluding"
      : confidence === "baseline"
        ? "suspicious memory requiring interpretation rather than a verdict — JIT, .NET and some AV produce this same shape"
        : "the region's own characteristics neither corroborate nor clear it";

  return {
    confidence,
    observations,
    summary,
    note: `${observations.join("; ")}. ${closing}`,
  };
}
