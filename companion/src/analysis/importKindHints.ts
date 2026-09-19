// The actionable reasons a unified text import can give back when detection says "unknown", in
// the order they are tried. Each is a real, specific mismatch an analyst can act on — never a
// guess at what the file might be.

import { capaFlavorHintFor } from "./capaResultImport.js";
import {
  looksLikeMacLoginItemFilename,
  looksLikeUndecodedMacLoginItemFilename,
  MAC_LOGIN_ITEM_FILENAMES,
} from "./macBinaryDetect.js";
import { isBinaryPlist } from "./macosPersistence.js";

/**
 * The v1 SessionLoginItems.sfl, a login-item container this codebase names but does not decode
 * (#1360). Without this the text path sniffed a text-read of the bplist as a BINARY LAUNCHD PLIST
 * and minted a "not read, run plutil -convert xml1" row — the wrong artifact, and a dead end.
 * Mirrored word for word in public/js/dashboard-values.js undecodedBinaryImportHint, which refuses
 * the picked file before it is read; a test holds the two sentences in lockstep.
 */
export function undecodedBinaryImportHint(filename: string): string | undefined {
  if (!looksLikeUndecodedMacLoginItemFilename(filename)) return undefined;
  return (
    `"${filename}": SessionLoginItems.sfl (v1, macOS 10.11–10.12) is not decoded; the .sfl2 list ` +
    "(macOS 10.13 and later) is — nothing in this file was read or assessed"
  );
}

/**
 * A macOS login-item container named like one but arriving as TEXT (#1301). The real artifact is a
 * binary plist; a `plutil -convert xml1` export or a text-read of the binary must not be minted as
 * a launchd-job record — the text path refuses these names outright (importIngest.ts
 * resolveImportKind), and this is the message that goes with the refusal.
 */
export function binaryArtifactHintFor(filename: string): string | undefined {
  const undecoded = undecodedBinaryImportHint(filename);
  if (undecoded) return undecoded;
  if (!looksLikeMacLoginItemFilename(filename)) return undefined;
  return (
    `"${filename}" is a binary macOS login-item container (${MAC_LOGIN_ITEM_FILENAMES}) — upload the ` +
    "original binary file (the dashboard sends it byte-native to /import-binary), or name its " +
    "server path via /import-mac-login-item; a text or XML conversion is not decoded"
  );
}

/**
 * ANY binary plist arriving as text (#1392). #1360 gated one name; every other bplist — an MRU
 * .sfl2, an arbitrary app's .plist, a .bookmark — still reached the macOS-persistence sniffer,
 * which claimed the `bplist0` magic and minted a Medium LAUNCHD "not read" row under the wrong
 * artifact label. The magic is refused at the text boundary (importIngest.ts resolveImportKind),
 * and this is its message. Tried AFTER the name-gated hints, which know more about the file.
 */
export function binaryPlistImportHint(filename: string, text: string): string | undefined {
  if (!isBinaryPlist(text)) return undefined;
  return (
    `"${filename}" is a binary property list (bplist00), not a text import — nothing in it was read or ` +
    `assessed. A login-item container (${MAC_LOGIN_ITEM_FILENAMES}) is decoded byte-native: upload the ` +
    "original file (the dashboard sends it to /import-binary) or name its server path via " +
    "/import-mac-login-item. Any other plist: convert it BEFORE upload with " +
    "plutil -convert xml1 -o <file>.xml <file>, then import the XML"
  );
}

/** The first specific hint that applies, else undefined so the caller prints its generic list. */
export function unknownImportHintFor(filename: string, text: string): string | undefined {
  return capaFlavorHintFor(text) ?? binaryArtifactHintFor(filename) ?? binaryPlistImportHint(filename, text);
}

/** The unified /import route's generic "unknown" sentence: every supported format, so the analyst can see what was tried. */
export const UNIFIED_IMPORT_UNKNOWN_MESSAGE =
  "could not detect the file type — not recognized as any supported import (THOR / SIEM-EDR / Chainsaw-EVTX / Hayabusa / Velociraptor / Suricata-Zeek / KAPE / Cyber Triage / M365-Entra / AWS / GCP-Azure / Plaso / Sandbox / Volatility-Rekall memory / Email-eml-msg / auditd / journald / sysdig-Falco / syslog / CSV / log)";

/** The /import-file route's generic sentence: the sniff read only a bounded head, so the list is not repeated. */
export const IMPORT_FILE_UNKNOWN_MESSAGE =
  "could not detect the file type — not recognized as any supported import format";

/**
 * The 400 body for an upload detection could not place. A specific hint is a sentence about THIS
 * file that the analyst must read — the dashboard shows a `refused` sentence verbatim in its batch
 * summary instead of folding it into "N file(s) failed / unrecognized" (#1392). The generic
 * sentence is not marked: it is the same for every unrecognized file and the count says enough.
 */
export function unknownImportResponse(
  filename: string,
  text: string,
  generic: string,
): { error: string; refused?: true } {
  const hint = unknownImportHintFor(filename, text);
  return hint ? { error: hint, refused: true } : { error: generic };
}
