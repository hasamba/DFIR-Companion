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
//
// The one place that reasoning breaks is the DETECTION STACK, which names its rules after the attacks
// they catch — see isDetectionStackPath.

import type { Severity } from "./stateTypes.js";
import { isCollectorOwnedLocation, isDetectionContentPath } from "./detectionStackPaths.js";

export interface RansomwareSignal {
  severity: Severity;
  mitre: string[];
  note: string;
}

// Known ransomware file extensions — an encrypted file is renamed to one of these, and the string
// exists on a victim host essentially nowhere else. DELIBERATELY curated to DISTINCTIVE family tags:
// a generic word or a real file extension (`.inc` MDAC include files, `.play`, `.hive`, `.royal`,
// `.basta`, `.lynx`) is NOT included — it produced a false T1486 on a WinSxS component. Widen with
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
// System32. The ransom-NOTE match can legitimately land anywhere on a HOST, so it is scoped away
// from the detection stack instead — see isDetectionStackPath.
const SYSTEM_DIR_RE = /\\Windows\\(?:System32|SysWOW64|WinSxS|servicing|assembly|Microsoft\.NET)\\/i;

/**
 * Is this path part of the DETECTION STACK rather than the host under investigation?
 *
 * A Sigma rule name reads like ransom vocabulary. Velociraptor unpacks its own compiled-Sigma tree
 * into `\Program Files\Velociraptor\Tools\tmp*\signatures\sigma\…` for the duration of a hunt, and
 * `proc_creation_win_wbadmin_restore_file.yms` contains "restore_file" — which RANSOM_NOTE_RE reads
 * as "restore … file" and grades High/T1486. On a real 100k-row `Windows.NTFS.MFT` collection that
 * rule file was the ONLY T1486 finding: every ransomware hit on the host's timeline was the
 * collector's own signature, describing an attack rather than recording one.
 *
 * Reuses detectionStackPaths — the predicates the Velociraptor, THOR and YARA ingest paths already
 * share — so all four agree on what "the tool found itself" means. Takes only the two an intruder
 * cannot pick a NAME to satisfy:
 *
 *   isDetectionContentPath   the file IS rule content — `.yms` (Velociraptor's own compiled-Sigma
 *                            format, which exists nowhere else on a Windows host), or a
 *                            `.yml`/`.evtx`/`.etl` inside a detection tree.
 *   isCollectorOwnedLocation the collector's own install tree.
 *
 * Deliberately NOT isDetectionToolLocation: that one also matches the published sample-corpus
 * directory names, which ARE attacker-choosable (see #720) — a note dropped in a folder the intruder
 * named `EVTX-ATTACK-SAMPLES` must still be found.
 *
 * The blast radius of a bypass is small either way. This gates the ransom-NOTE branches only, and
 * only declines to RAISE them: an attacker who parks `RESTORE-MY-FILES.txt` under `\Velociraptor\`
 * loses one High on that copy, while the same note in every encrypted directory — and every file
 * renamed to a family extension, anywhere — still grades High. Nothing is dropped; the row is still
 * ingested, still counted, still findable.
 */
function isDetectionStackPath(nameOrPath: string): boolean {
  return isDetectionContentPath(nameOrPath) || isCollectorOwnedLocation(nameOrPath);
}

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

  // 2. A ransom note by its own name, or a `<family>_readme` note (akira_readme.txt).
  //
  // The note branches — and ONLY these — skip the detection stack, which names its rules after the
  // attacks they catch. The extension branch above deliberately runs first and unguarded: a file
  // renamed to `.akira` under `\Program Files\Velociraptor\` is impact evidence, no rule pack
  // ships a family tag as an extension, and losing that row would hide the encryption sweep in the
  // one directory an analyst is least likely to re-check.
  if (isDetectionStackPath(nameOrPath)) return null;

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

/** Is the family-extension set aware of `ext` (without the dot)? Exposed for tests. */
export function isRansomExtension(ext: string): boolean {
  return RANSOM_EXTS.has(ext.trim().toLowerCase().replace(/^\./, ""));
}
