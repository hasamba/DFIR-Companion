/**
 * Is this DECODED import text really a binary file (#1802)?
 *
 * The text import path (dashboard upload, /import-file) used to send any binary it did not name to
 * the generic csv/log buckets — an .exe became a "log" and, with AI on, went to the model as one.
 * The drop folder already refuses binaries with `looksBinary` (dropScan.ts), but that judges RAW
 * bytes and treats a NUL as decisive, which would refuse every UTF-16 Windows export. This judges
 * the text AFTER the BOM-aware decode (decodeImportedText / the browser's readAsText), where a
 * UTF-16 file with a BOM has no NULs left.
 *
 * Two signals, either one decides:
 *  1. A container magic at the very start (PE, ELF, zip, gzip, raw EVTX, SQLite, PDF). The PE check
 *     needs a control or undecodable char right after "MZ", so a text line that starts "MZ" passes.
 *  2. The share of control content in the head. A run of NULs counts once, so a log with a
 *     NUL-padded block from an unclean shutdown still imports, while NUL-interleaved text (UTF-16
 *     with no BOM, read as UTF-8) and executables do not. Undecodable chars (U+FFFD) count only
 *     toward the looser second threshold, so text with some non-UTF-8 names still imports.
 */

const SAMPLE_CHARS = 8192;
const CONTROL_RATIO = 0.1;
const CONTROL_OR_UNDECODABLE_RATIO = 0.3;
const REPLACEMENT = 0xfffd;

// %PDF- too: a PDF can be all printable ASCII, so the ratio alone lets it through as a "log".
const MAGICS = ["\x7fELF", "PK\x03\x04", "PK\x05\x06", "ElfFile\0", "SQLite format 3\0", "%PDF-"];

function isControl(c: number): boolean {
  // TAB, LF, VT, FF, CR and ESC (ANSI colour in logs) are text.
  return (
    (c < 0x20 && c !== 0x09 && c !== 0x0a && c !== 0x0b && c !== 0x0c && c !== 0x0d && c !== 0x1b) ||
    c === 0x7f
  );
}

function hasBinaryMagic(head: string): boolean {
  if (MAGICS.some((m) => head.startsWith(m))) return true;
  // gzip 1F 8B: 0x8B is not valid UTF-8, so it arrives as U+FFFD (or as itself from a Latin-1 read).
  if (head.charCodeAt(0) === 0x1f && (head.charCodeAt(1) === REPLACEMENT || head.charCodeAt(1) === 0x8b))
    return true;
  if (!head.startsWith("MZ")) return false;
  for (let i = 2; i < Math.min(head.length, 6); i++) {
    const c = head.charCodeAt(i);
    if (c === 0 || c === REPLACEMENT || isControl(c)) return true;
  }
  return false;
}

/** True when the decoded text is a binary file rather than a text import. */
export function looksLikeBinaryText(text: string): boolean {
  const head = text.slice(0, SAMPLE_CHARS);
  if (head.length === 0) return false;
  if (hasBinaryMagic(head)) return true;
  let units = 0;
  let control = 0;
  let undecodable = 0;
  for (let i = 0; i < head.length; i++) {
    const c = head.charCodeAt(i);
    if (c === 0 && i > 0 && head.charCodeAt(i - 1) === 0) continue; // a NUL run counts once
    units++;
    if (c === 0 || isControl(c)) control++;
    else if (c === REPLACEMENT) undecodable++;
  }
  return control / units > CONTROL_RATIO || (control + undecodable) / units > CONTROL_OR_UNDECODABLE_RATIO;
}

/** The refusal sentence for a binary sent to a text import, or undefined when the text is text. */
export function binaryContentImportHint(filename: string, text: string): string | undefined {
  if (!looksLikeBinaryText(text)) return undefined;
  return (
    `"${filename}" is a binary file, not a text import — nothing in it was read or assessed. ` +
    "Run it through its parser first (a raw .evtx through Hayabusa, Chainsaw or EvtxECmd; a disk or " +
    "memory image through its tool) and import the CSV or JSON output. Text saved as UTF-16 without " +
    "a byte-order mark, or in a legacy code page, also lands here: re-save it as UTF-8"
  );
}
