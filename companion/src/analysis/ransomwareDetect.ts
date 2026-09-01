// Ransomware impact (T1486) detection from a file NAME or path.
//
// The eval cases 003 (Trigona), 004 (Akira) and 005 (The Gentlemen) all end in ransomware, and the
// evidence is dense in the collection — `.trigona` ×121, `akira_readme` + `.akira` ×48,
// `gentlemen_locker` ×52. Yet no imported event carried T1486. The reason is structural, not a
// missing rule list: the encryption sweep and the ransom-note drop live in `Windows.NTFS.MFT` and
// `Windows.Forensics.Usn`, which the mappers grade `Info`. The per-file event cap keeps the
// MOST-SEVERE events, so 275k+ Info MFT rows sort below everything and the incident-relevant ones
// fall off the end — the impact is present in the data and absent from the graded timeline.
//
// Grading these rows above Info is what puts them back on the timeline (and makes them survive the
// cap). This is a POSITIVE detection: it RAISES severity on an attacker-chosen name, which the
// veloDetectionNoise "never trust an attacker signal" rule permits — that rule guards DEMOTIONS
// (hiding evidence), and the failure mode here is the opposite (an attacker who names their note
// innocuously simply is not flagged by THIS rule; other signals still apply).

import type { Severity } from "./stateTypes.js";

export interface RansomwareSignal {
  severity: Severity;
  mitre: string[];
  note: string;
}

// Known ransomware file extensions — an encrypted file is renamed to one of these, and the string
// exists on a victim host essentially nowhere else. DELIBERATELY curated to DISTINCTIVE family tags:
// a generic word or a real file extension (`.inc` MDAC include files, `.play`, `.hive`, `.royal`,
// `.basta`) is NOT included — it produced a false T1486 on a WinSxS component. Widen with
// DFIR_RANSOM_EXTS (comma-separated) when a new family's tag is known and distinctive.
const RANSOM_EXTS = new Set(
  [
    "akira",
    "trigona",
    "gentlemen",
    "lockbit",
    "blackcat",
    "alphv",
    "blacksuit",
    "sodinokibi",
    "wannacry",
    "wncry",
    "wcry",
    "phobos",
    "rhysida",
    "nokoyawa",
    "bianlian",
    "blackbasta",
    "darkside",
    "blackbyte",
    "hellokitty",
    "cuba",
    "quantum",
    "royalransom",
    "cl0p",
    "lockbit3",
    "babuk",
    "conti",
    "revil",
    "ryuk",
    "medusalocker",
    "qilinransom",
    ...(process.env.DFIR_RANSOM_EXTS ?? "").split(","),
  ]
    .map((e) => e.trim().toLowerCase().replace(/^\./, ""))
    .filter(Boolean),
);

// Family tags that are ALSO an ordinary English word or a product name. These CANNOT go in
// RANSOM_EXTS: that set additionally feeds the `<family>_readme` / `_locker` / `_note` note matcher
// below, which is deliberately unscoped so a note is found wherever it is dropped — a bare word
// there fires on any path. So they are carried separately and matched only on the shape ransomware
// actually leaves: a second extension APPENDED to a still-intact original name
// (`QuarterlyPlan.docx.LYNX`), never a single-extension `notes.lynx`, and never under a protected
// OS directory. Widen with DFIR_RANSOM_EXTS_STRICT.
//
// `lynx` is here because scenario 011 (The DFIR Report, "Cat's Got Your Files", 2025-12-17) showed
// the cost of omitting it. Lynx is an active family (the INC Ransom successor) whose impact phase
// leaves NO process or Sigma evidence — the encrypted names in the MFT are the only signal there is,
// and dropping the tag cost the entire T1486 conclusion on a case where the files were collected and
// sitting in the import.
const WORD_COLLISION_EXTS = new Set(
  ["lynx", ...(process.env.DFIR_RANSOM_EXTS_STRICT ?? "").split(",")]
    .map((e) => e.trim().toLowerCase().replace(/^\./, ""))
    .filter(Boolean),
);

// The victim file's own extension, still in place under an appended family tag. An ALLOWLIST of
// real user-data types, not a heuristic about what an extension "looks like": every shape-based rule
// tried here was wrong in one direction or the other. Letters-first with a two-character minimum
// rejected `archive.7z.LYNX` and `main.c.LYNX`, both ordinary victim files. Relaxing it to "contains
// a letter" then accepted `lib.v1.lynx`, `pkg.rc1.lynx` and `bin.x64.lynx` — version fragments, the
// exact thing the rule exists to reject. There is no shape that separates `7z` from `x64`, so the
// question is settled by naming the types ransomware actually encrypts instead of guessing.
//
// Scoped to USER DATA on purpose: documents, media, archives, databases, mail, source, backups and
// virtual disks. Ransomware targets those; it skips the OS. A type absent here means a `.lynx`
// rename of it is not flagged as encryption — extend the list when one is missing. An analyst who
// needs a family tag matched with no victim-extension requirement at all puts it in DFIR_RANSOM_EXTS
// instead, which is the unconditional set; this list only gates the word-collision tags.
const VICTIM_EXTS = new Set(
  // documents, spreadsheets, presentations
  (
    "doc docx docm dot dotx odt rtf txt md pdf xps wpd pages tex " +
    "xls xlsx xlsm xlsb xlt xltx ods csv tsv numbers ppt pptx pptm pps ppsx odp key " +
    // images, audio, video
    "jpg jpeg png gif bmp tif tiff svg webp heic raw cr2 nef psd ai eps " +
    "mp3 mp4 avi mov wmv mkv flv wav flac m4a m4v mpg mpeg webm " +
    // archives
    "zip zipx 7z rar tar gz tgz bz2 xz iso cab arj lzh " +
    // databases and mail
    "mdb accdb db sqlite sqlite3 sql dbf myd frm ibd ldf mdf dmp pst ost msg eml nsf edb " +
    // source and configuration
    "c h cpp cc hpp cs java py js ts jsx tsx go rb php pl sh ps1 " +
    "html htm css json xml yml yaml ini cfg conf properties toml " +
    "aspx asp jsp cshtml jsonl ndjson rdp one vsd vsdx mpp pub wps " +
    // backups, virtual disks, engineering, misc data
    "bak backup bkf vmdk vmx vhd vhdx vdi ova ovf qcow2 vbk vib vrb " +
    "dwg dxf step stp log dat pem crt p12 pfx"
  ).split(" "),
);

// A ransom-NOTE filename. Kept strict (the ransom vocabulary must appear) so an ordinary `README.txt`
// in a source tree is not flagged: a bare readme needs a decrypt/restore/recover/ransom token, an
// encryption claim, or a `!`-prefixed shout — the shapes real notes actually take.
const RANSOM_NOTE_RE =
  /how[\s_-]*to[\s_-]*(?:decrypt|restore|recover|unlock|back)|(?:decrypt|restore|recover|unlock)[\s_-]*(?:your|my|the|all)?[\s_-]*files?|your[\s_-]*files?[\s_-]*(?:are|have|were)?[\s_-]*(?:been[\s_-]*)?(?:encrypted|locked|stolen)|ransom[\s_-]*note|read[\s_-]*me[\s_-]*(?:to[\s_-]*)?(?:decrypt|restore|recover)|(?:decrypt|recover)[\s_-]*instruction|^!+.*(?:readme|recover|restore|decrypt)|_readme_|restore[\s_-]*my[\s_-]*files/i;

function baseName(p: string): string {
  return p.trim().split(/[\\/]/).pop() ?? p.trim();
}

// Protected OS locations. Ransomware encrypts USER data; the OS keeps System32/WinSxS/servicing
// under lock, so a "family extension" seen HERE is a coincidental component name (e.g. a WinSxS MDAC
// folder), never an encrypted victim file. Scoping the extension match away from these dirs is not a
// demotion on an attacker signal — the attacker cannot avoid encrypting user files by NOT touching
// System32, and the ransom-NOTE match (which can legitimately land anywhere) is left unscoped.
const SYSTEM_DIR_RE = /\\Windows\\(?:System32|SysWOW64|WinSxS|servicing|assembly|Microsoft\.NET)\\/i;

/**
 * Does this file name / path indicate ransomware impact? Returns a High T1486 signal, or null.
 */
export function ransomwareSignal(nameOrPath: string): RansomwareSignal | null {
  const name = baseName(nameOrPath).toLowerCase();
  if (!name) return null;

  // 1. Encrypted file: the LAST extension is a known family tag (`report.docx.akira`, `db.trigona`).
  const ext = name.includes(".") ? name.slice(name.lastIndexOf(".") + 1) : "";
  if (ext && RANSOM_EXTS.has(ext) && !SYSTEM_DIR_RE.test(nameOrPath)) {
    return {
      severity: "High",
      mitre: ["T1486"],
      note: `file encrypted with the .${ext} ransomware extension`,
    };
  }

  // 1b. A word-collision tag (`.lynx`) additionally needs the rename shape — the victim file's own
  // extension still present beneath the appended one — before it counts as encryption.
  if (ext && WORD_COLLISION_EXTS.has(ext) && !SYSTEM_DIR_RE.test(nameOrPath)) {
    const stem = name.slice(0, name.length - ext.length - 1);
    const inner = stem.includes(".") ? stem.slice(stem.lastIndexOf(".") + 1) : "";
    if (VICTIM_EXTS.has(inner)) {
      return {
        severity: "High",
        mitre: ["T1486"],
        note: `file encrypted with the .${ext} ransomware extension`,
      };
    }
  }

  // 2. A ransom note by its own name, or a `<family>_readme` note (akira_readme.txt).
  const family = [...RANSOM_EXTS].find(
    (f) =>
      name.includes(`${f}_readme`) ||
      name.includes(`${f}-readme`) ||
      name.includes(`${f}_locker`) ||
      name.includes(`${f}_note`),
  );
  if (family) {
    return { severity: "High", mitre: ["T1486"], note: `ransom note / locker for the ${family} family` };
  }
  if (RANSOM_NOTE_RE.test(name)) {
    return { severity: "High", mitre: ["T1486"], note: "ransom note" };
  }
  return null;
}

/** Is either family-extension set aware of `ext` (without the dot)? Exposed for tests. */
export function isRansomExtension(ext: string): boolean {
  const e = ext.trim().toLowerCase().replace(/^\./, "");
  return RANSOM_EXTS.has(e) || WORD_COLLISION_EXTS.has(e);
}
