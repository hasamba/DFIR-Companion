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

export interface MalfindContext {
  confidence: MalfindConfidence;
  observations: string[]; // the facts read off the row, in the order they were checked
  note: string; // the sentence appended to the event description
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
// Volatility's VAD tags: VadS is private memory; Vad / VadF are mapped, file-backed.
const PRIVATE_TAG_RE = /^vads$/i;
const MAPPED_TAG_RE = /^vad[fm]?$/i;

// The preview malfind prints. Any of these columns may carry it depending on tool and renderer.
const PREVIEW_KEYS = ["Hexdump", "hexdump", "Disasm", "disasm", "Data", "data", "Bytes", "bytes"];

/** True when the captured preview starts with an MZ image header. */
function startsWithMz(preview: string): boolean {
  const p = preview.trim();
  if (!p) return false;
  // A hexdump renders it as the bytes 4d 5a; a disassembly or raw capture may show the characters.
  return /^(?:[0-9a-f]{2}\s+)?4d\s*5a/i.test(p) || /^MZ/.test(p);
}

/**
 * Read the region characteristics off a malfind row.
 *
 * Returns the observations and a note. Severity is NOT this module's business: the caller keeps
 * whatever policy it has, and this only explains what the row does and does not show.
 */
export function malfindContext(row: Row): MalfindContext {
  const protection = cell(row, ["Protection", "protection", "Prot"]);
  const tag = cell(row, ["Tag", "tag", "VadTag", "vad_tag"]);
  const preview = cell(row, PREVIEW_KEYS);
  const commit = cell(row, ["CommitCharge", "commit_charge"]);
  const isFile = cell(row, ["File", "FileObject", "Mapped", "PrivateMemory", "private_memory"]);

  const observations: string[] = [];
  let strong = 0;

  if (protection) {
    if (RWX_RE.test(protection)) {
      observations.push(`writable and executable (${protection})`);
      strong++;
    } else if (EXEC_RE.test(protection)) {
      observations.push(`executable but not writable (${protection})`);
    } else {
      // NOT "clean". A region malfind reported without an executable protection is unusual enough
      // to say plainly, and it still does not clear the region.
      observations.push(`protection recorded as ${protection}, which does not corroborate injection`);
    }
  } else {
    observations.push("protection was not recorded");
  }

  if (tag) {
    if (PRIVATE_TAG_RE.test(tag)) {
      observations.push(`private memory (${tag}) — no file on disk explains it`);
      strong++;
    } else if (MAPPED_TAG_RE.test(tag)) {
      observations.push(`file-backed mapping (${tag}), which many legitimate loaders produce`);
    } else {
      observations.push(`VAD tag ${tag}`);
    }
  }

  // `PrivateMemory: 1` is the Volatility 3 spelling of the same fact the VAD tag carries.
  if (!tag && isFile) {
    if (/^(?:1|true|yes)$/i.test(isFile)) {
      observations.push("private memory — no file on disk explains it");
      strong++;
    } else if (/^(?:0|false|no)$/i.test(isFile)) {
      observations.push("file-backed, which many legitimate loaders produce");
    }
  }

  if (!preview) {
    observations.push(
      "no content preview was captured, so the region's contents are unknown from this row alone",
    );
  } else if (startsWithMz(preview)) {
    observations.push("the captured preview begins with an MZ image header");
    strong++;
  } else {
    // The single most important sentence in this file.
    observations.push(
      "the captured preview does not begin with an MZ header — this does not indicate the region " +
        "is clean, because shellcode has no header and the preview covers only the start of the region",
    );
  }

  if (commit) observations.push(`commit charge ${commit}`);

  const confidence: MalfindConfidence = strong >= 2 ? "corroborated" : strong === 1 ? "baseline" : "uncorroborated";

  const closing =
    confidence === "corroborated"
      ? "Several characteristics line up with injection. Confirm with the process context, its " +
        "network behaviour, and any independent detection before concluding."
      : confidence === "baseline"
        ? "This is suspicious memory requiring interpretation, not a confirmed injection. JIT " +
          "compilers, .NET and some AV engines produce the same shape."
        : "The region's own characteristics do not corroborate injection, and they do not clear it " +
          "either. Treat this as a region to examine, not as a finding in itself.";

  return {
    confidence,
    observations,
    note: `${observations.join("; ")}. ${closing}`,
  };
}
