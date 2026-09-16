// Byte-native detection for macOS Background Task Management files (#1013) — the one place this
// codebase currently recognizes a BINARY import kind rather than a text one. Filename is the only
// reliable signal for WHICH artifact this is (a keyed-archive bplist carries no in-content marker
// distinguishing it from any other keyed-archived plist — matches this codebase's own LEAPP
// precedent: "LEAPP TSVs carry no in-content marker; the filename is the only signal"); the real
// `bplist00` magic on the raw bytes is required too, so a mismatched-magic file under a matching
// name is rejected, never coerced.

const BTM_LEGACY_NAME = /backgrounditems\.btm$/i;
const BTM_MODERN_NAME = /BackgroundItems-v\d+\.btm$/i;

export function looksLikeMacBtmFilename(filename: string): boolean {
  return BTM_LEGACY_NAME.test(filename) || BTM_MODERN_NAME.test(filename);
}

export function isBplistMagic(headBytes: Buffer): boolean {
  return headBytes.length >= 8 && headBytes.toString("ascii", 0, 8) === "bplist00";
}

/** The one binary import kind this codebase currently detects — filename plus real magic, both required. */
export function detectBinaryImportKind(filename: string, headBytes: Buffer): "macloginitem" | null {
  if (looksLikeMacBtmFilename(filename) && isBplistMagic(headBytes)) return "macloginitem";
  return null;
}
