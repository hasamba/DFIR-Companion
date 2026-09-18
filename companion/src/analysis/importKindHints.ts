// The actionable reasons a unified text import can give back when detection says "unknown", in
// the order they are tried. Each is a real, specific mismatch an analyst can act on — never a
// guess at what the file might be.

import { capaFlavorHintFor } from "./capaResultImport.js";
import { looksLikeMacLoginItemFilename, MAC_LOGIN_ITEM_FILENAMES } from "./macBinaryDetect.js";

/**
 * A macOS login-item container named like one but arriving as TEXT (#1301). The real artifact is a
 * binary plist; a `plutil -convert xml1` export or a text-read of the binary must not be minted as
 * a launchd-job record — the text path refuses these names outright (importIngest.ts
 * resolveImportKind), and this is the message that goes with the refusal.
 */
export function binaryArtifactHintFor(filename: string): string | undefined {
  if (!looksLikeMacLoginItemFilename(filename)) return undefined;
  return (
    `"${filename}" is a binary macOS login-item container (${MAC_LOGIN_ITEM_FILENAMES}) — upload the ` +
    "original binary file (the dashboard sends it byte-native to /import-binary), or name its " +
    "server path via /import-mac-login-item; a text or XML conversion is not decoded"
  );
}

/** The first specific hint that applies, else undefined so the caller prints its generic list. */
export function unknownImportHintFor(filename: string, text: string): string | undefined {
  return capaFlavorHintFor(text) ?? binaryArtifactHintFor(filename);
}
