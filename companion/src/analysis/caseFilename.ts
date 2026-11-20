// File names built from a case NAME (#2769). The name is free text an analyst typed — any length,
// any script — but a file name is capped at 255 BYTES on ext4, NTFS and APFS. An uncapped name made
// archive and delete-with-archive fail with ENAMETOOLONG. The full name stays in the case metadata;
// only the file name is shortened.

// Windows-illegal filename characters (also unsafe cross-platform): < > : " / \ | ? * and control
// chars. caseId itself never needs this — isValidCaseId's allowlist already guarantees it is
// filesystem-safe — but the case name is free text.
const UNSAFE_FILENAME_CHARS = /[<>:"/\\|?*\x00-\x1f]/g;

/**
 * The most bytes a whole file name built here may take. Well under the 255-byte limit, because
 * writeBufferAtomic first writes `<name>.<uuid>.tmp` (41 more bytes) and then renames it.
 */
export const MAX_CASE_FILENAME_BYTES = 200;

/** The longest prefix of `text` that fits in `maxBytes` of UTF-8, never splitting a code point. */
function truncateUtf8(text: string, maxBytes: number): string {
  let used = 0;
  let out = "";
  for (const codePoint of text) {
    const size = Buffer.byteLength(codePoint, "utf8");
    if (used + size > maxBytes) break;
    used += size;
    out += codePoint;
  }
  return out;
}

/**
 * `"<caseId> - <name><suffix>"`, or `"<caseId><suffix>"` when the case has no distinct name. The
 * name is sanitised and then shortened so the whole result stays within MAX_CASE_FILENAME_BYTES;
 * the caseId and the suffix are always kept whole. A short name comes out unchanged.
 */
export function caseNamedFilename(caseId: string, name: string | null | undefined, suffix: string): string {
  const trimmed = (name ?? "").trim();
  if (!trimmed || trimmed === caseId) return `${caseId}${suffix}`;
  const prefix = `${caseId} - `;
  const room = MAX_CASE_FILENAME_BYTES - Buffer.byteLength(prefix + suffix, "utf8");
  const sanitized = trimmed.replace(UNSAFE_FILENAME_CHARS, "_");
  const cut = truncateUtf8(sanitized, room);
  // A cut can end on a space or a dot, which reads as a typo before the suffix. Only a shortened
  // name is tidied, so a short name keeps its byte-identical file name.
  const safeName = cut === sanitized ? cut : cut.replace(/[ .]+$/, "");
  if (!safeName) return `${caseId}${suffix}`;
  return `${prefix}${safeName}${suffix}`;
}
