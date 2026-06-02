// Turn a browser tab title into a filesystem-safe slug for screenshot filenames.
// Keeps Latin letters, digits, dot, underscore and hyphen; everything else (spaces,
// Unicode, OS-reserved characters like <>:"/\|?*, control chars, etc.) collapses
// to a single hyphen. Truncates so filenames stay well under filesystem limits.
//
// Examples:
//   "Velociraptor — Hunts"            → "Velociraptor-Hunts"
//   "VirusTotal: hash a1b2c3"         → "VirusTotal-hash-a1b2c3"
//   "  C:\\Windows\\System32  "       → "C-Windows-System32"
//   "💀 attacker.exe"                 → "attacker.exe"
//   ""                                → ""

const MAX_SLUG_LENGTH = 60;

export function slugifyTitle(title: string, maxLength: number = MAX_SLUG_LENGTH): string {
  if (!title) return "";
  const collapsed = title
    .normalize("NFKD")            // separate combining marks so we can drop non-ASCII cleanly
    .replace(/[^A-Za-z0-9._-]+/g, "-") // unsafe / non-ASCII → hyphen
    .replace(/-+/g, "-")          // collapse repeats
    .replace(/^[-._]+|[-._]+$/g, ""); // trim leading/trailing punctuation
  if (collapsed.length === 0) return "";
  // Truncate, then trim any orphan trailing punctuation introduced by the cut.
  return collapsed.slice(0, maxLength).replace(/[-._]+$/g, "");
}
