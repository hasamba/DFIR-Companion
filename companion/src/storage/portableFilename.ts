/**
 * Filename portability — rewriting a name so the strictest filesystem a recipient uses can create
 * it, which is Windows.
 *
 * This lives in storage/ rather than beside either archive writer because both need it and neither
 * may import the other: a case archive and the ZIP writer sit in different analysis tiers. The
 * rules here are about filesystems, not about ZIP, so storage/ is where they belong.
 *
 * A case directory routinely holds names Windows refuses. The drop folder keeps a dropped file's
 * original name forever under drop/_processed/, and analysts drop files straight out of Windows
 * collections. Writing such a name into an archive means extraction on Windows either fails
 * outright or, for a colon, silently writes an NTFS alternate data stream — the file disappears
 * from the extracted tree with no error at all.
 *
 * Only a name being WRITTEN somewhere new is rewritten. The path bytes are read from must keep the
 * real on-disk spelling, or the read finds nothing.
 */

// Characters Windows refuses in a filename, plus the control range no platform wants. The forward
// slash is in the set too: inside a single segment it is content, not a separator.
const UNPORTABLE_SEGMENT_CHARS = /[<>:"/\\|?*\x00-\x1f]/g;

// Reserved device names. With or without an extension, CON, NUL, LPT1 and friends do not resolve to
// a file on Windows at all, so a name matching one cannot be created.
const WINDOWS_RESERVED_SEGMENT = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$/i;

/**
 * Rewrite one path segment so Windows can create a file with that name.
 *
 * Each substitution keeps the segment's length, so two names that differ before sanitizing usually
 * still differ after. Where they do not, the caller must refuse to write rather than let one file
 * overwrite the other. An ordinary name comes back unchanged, non-ASCII included — Windows accepts
 * those.
 */
export function portableZipSegment(segment: string): string {
  if (!segment) return "_";
  let out = segment.replace(UNPORTABLE_SEGMENT_CHARS, "_");
  // Windows strips trailing dots and spaces, so "notes." and "notes" resolve to one file. Padding
  // with "_" instead of trimming keeps the two names distinct, which the caller's collision check
  // needs in order to see two entries rather than one.
  out = out.replace(/[.\s]+$/, (run) => "_".repeat(run.length));
  if (WINDOWS_RESERVED_SEGMENT.test(out)) out = `_${out}`;
  return out;
}

/**
 * Rewrite a whole archive entry path, segment by segment.
 *
 * Backslashes fold to forward slashes first — an archive entry has exactly one path syntax — and
 * empty segments are dropped so a doubled slash does not invent a directory.
 */
export function portableZipEntryPath(path: string): string {
  return path
    .replace(/\\/g, "/")
    .split("/")
    .filter((seg) => seg !== "")
    .map(portableZipSegment)
    .join("/");
}
