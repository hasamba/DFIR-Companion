// The one definition of "this file sits somewhere a legitimately-installed binary does not".
//
// Three copies of this idea had drifted apart: persistenceSniperImport.ts carried a pair of regexes
// tuned for command-line VALUES, binaryRenameImport.ts grew a looser directory-anywhere test, and
// data/tags.yaml encodes a third as a content rule. They already disagreed — a path one importer
// called staged the other did not — so a fix to either left the rest wrong. The directory list and
// the extension list live here once; the two matching styles are separate exports because they
// answer genuinely different questions, not because they drifted.
//
// Pure, no I/O.

// World-writable / transient locations malware commonly drops into. Kept as one alternation so the
// two matchers below can never diverge on WHICH directories count.
const STAGING_DIRS = "temp|tmp|appdata\\\\local\\\\temp|programdata|public|windows\\\\temp";

// The same list with forward slashes allowed, for the bare-path matcher.
const STAGING_DIRS_ANY_SEP = String.raw`temp|tmp|appdata[\\/]local[\\/]temp|programdata|public|windows[\\/]temp|perflogs|\$recycle\.bin`;

// Executable-ish extensions. An archive or a document in Temp is ordinary; a binary is not.
export const STAGING_EXT =
  "exe|dll|com|bat|cmd|ps1|vbs|vbe|js|jse|wsf|wsh|msi|scr|cpl|ocx|sys|drv|hta|jar|py|pyw|msc|lnk";

// ── Command-line VALUES ────────────────────────────────────────────────────────
// A persistence value routinely mixes "path + trailing arguments" into one blob with no reliable
// delimiter ("rundll32.exe \"C:\\ProgramData\\x.dll\",stow"), so only two shapes reliably identify
// the row's OWN target: the LEADING drive-letter path, or a fully QUOTED one anywhere in the string.
// An unquoted reference later in an argument list matches neither on purpose — "msiexec.exe /i
// C:\\Windows\\Temp\\update.msi" runs msiexec, not the staged .msi, and flagging it was a real false
// positive. `(?:[^\\]+\\)*` allows real intermediate segments (the common Temp layout is
// C:\\Users\\<name>\\AppData\\Local\\Temp\\…) while `[^\\]*?` after the directory still requires the
// file to sit DIRECTLY in it, which keeps a deep vendor path like Defender's Platform\\<ver>\\
// MpCmdRun.exe from matching. The trailing `(?![.\w])` rejects only what is actually wrong — another
// dot, or a continuing word character from a longer extension — because a bare `\b` matched an
// extension prefix inside a multi-dot filename ("readme.hta.txt" is a .txt file) and an allow-list of
// terminators silently dropped cmd.exe operators ("evil.exe&calc.exe").
const STAGED_LEADING_RE = new RegExp(
  `^[A-Za-z]:\\\\(?:[^\\\\]+\\\\)*(?:${STAGING_DIRS})\\\\[^\\\\]*?\\.(?:${STAGING_EXT})(?![.\\w])`,
  "i",
);
const STAGED_QUOTED_RE = new RegExp(
  `["'][A-Za-z]:\\\\(?:[^\\\\"']+\\\\)*(?:${STAGING_DIRS})\\\\[^\\\\"']*?\\.(?:${STAGING_EXT})["']`,
  "i",
);

/**
 * Does a persistence VALUE (a path that may carry trailing arguments, or a comma-joined list) name a
 * staged executable as its own target? See the note above for why only the leading and quoted shapes
 * count.
 */
export function isStagedCommandValue(text: string): boolean {
  return STAGED_LEADING_RE.test(text) || STAGED_QUOTED_RE.test(text);
}

// ── Bare paths ─────────────────────────────────────────────────────────────────
// A file-stat artifact hands over a clean path with no arguments to disambiguate, so the leading /
// quoted anchoring above is unnecessary and would reject a perfectly clear UNC or forward-slash path.
// Here the directory may appear anywhere in the path, and Downloads/Desktop/Documents join the list —
// user-writable locations that a command-line value would rarely name but a dropped binary often sits
// in. No extension gate: the caller already knows it is looking at a binary.
const STAGED_PATH_RE = new RegExp(
  String.raw`[\\/](?:${STAGING_DIRS_ANY_SEP}|users[\\/][^\\/]+[\\/](?:downloads|desktop|documents))[\\/]`,
  "i",
);

/** Does a bare filesystem path sit in a staging / world-writable directory? */
export function isStagedPath(path: string): boolean {
  return STAGED_PATH_RE.test(path);
}

// Vendor-owned install roots — where an installer renaming its own helper is ordinary. Note this is
// NOT the inverse of staging: a path can be neither (an app installed under C:\Tools), which is the
// ambiguous middle callers should treat as neutral rather than as evidence either way.
const VENDOR_ROOT_RE =
  /^[A-Za-z]:[\\/](?:program files(?: \(x86\))?|windows[\\/](?:system32|syswow64|winsxs))[\\/]/i;

/** Is this path inside a vendor/OS-owned install root? */
export function isVendorRootPath(path: string): boolean {
  return VENDOR_ROOT_RE.test(path);
}
