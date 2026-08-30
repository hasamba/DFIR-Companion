// What a filename may be, on every platform an archive from this tool might be opened on.
//
// A case directory is written under the host's rules. On Linux those admit names Windows refuses
// outright — a colon, a backslash, a trailing dot, a reserved device name — and analysts produce
// them routinely: the evidence drop folder keeps a dropped file's original name forever, under
// drop/_processed/, and a Windows collection is exactly where "evidence:2026.evtx" comes from.
//
// Those names are fine while they stay on the host. They stop being fine the moment they are
// packed into an archive, because the archive is opened somewhere else (#675). Both exporters
// reduce their entry names through this module before writing them.

// Characters Windows refuses in a filename, plus the control range no platform accepts. The same
// set caseExportArchive's download-filename sanitizer uses.
const UNPORTABLE_NAME_CHARS = /[<>:"/\\|?*\x00-\x1f]/g;

// Device names Windows reserves. CON, NUL, LPT1 — with or without an extension — do not resolve to
// a file at all, so a file of that name cannot be created.
const WINDOWS_RESERVED_NAME = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$/i;

/**
 * Rewrite ONE path segment so every platform can create a file by that name.
 *
 * Deliberately total, never throwing: an archive writer needs a name for every file it holds, and
 * refusing to name one would drop evidence. A caller that renames must say so — see how
 * caseExportArchive records the original path in its manifest and refuses an archive whose renamed
 * entries collide.
 */
export function portableFilename(name: string): string {
  const cleaned = name
    .replace(UNPORTABLE_NAME_CHARS, "_")
    // Windows strips a trailing dot or space silently, which folds two distinct names into one
    // file — the same aliasing the case import's duplicate guard exists to catch.
    .replace(/[.\s]+$/, "");
  if (cleaned === "" || cleaned === "." || cleaned === "..") return "_";
  return WINDOWS_RESERVED_NAME.test(cleaned) ? `_${cleaned}` : cleaned;
}

/**
 * Rewrite a whole forward-slash path segment by segment. The separators survive; only the names
 * between them change.
 */
export function portableFilePath(path: string): string {
  return path.split("/").map(portableFilename).join("/");
}
