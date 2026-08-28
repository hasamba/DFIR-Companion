// Telling a rule pack's OWN files apart from evidence.
//
// A keyword scanner over $MFT (DetectRaptor's Windows.Detection.MFT and the like) matches FILE
// NAMES. That means it fires on the rule pack itself: every Sigma rule is named after the tool it
// hunts (`proc_creation_win_hktl_mimikatz_command_line.yml`), and so is every sample log shipped to
// test those rules against (`sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx`). On one
// benchmark collection that was 54 of 111 rows, 37 of them graded High — more false High detections
// than the case had real ones, and 44 file indicators named after tools nobody ran.
//
// The extension alone cannot decide this. `.yml` is an ordinary config format, and a staged
// `C:\Windows\Temp\stolen.evtx` is a genuine finding about an exfiltrated log. So the test has two
// halves: the file must carry detection content, AND the rule that fired must have matched its NAME
// rather than its LOCATION. A location rule keeps its grade whatever the extension.
//
// Kept out of velociraptorImport.ts, which is frozen at its current size by the file-size ledger
// (#384) — see check-file-size.mjs.
import { str, getCI, isObject } from "./siemImport.js";

type Row = Record<string, unknown>;

/**
 * A compiled or standalone signature FILE — Velociraptor's .yms, a YARA .yar/.yara, a .sigma.
 *
 * These formats exist only to carry detection logic, so a value naming one is never an observed
 * indicator whatever produced the row. Deliberately narrower than DETECTION_CONTENT_EXT below:
 * .yml/.yaml are ordinary config formats an attacker may also drop, so they are suppressed only
 * where the row's own verdict shows the match was against a rule pack.
 */
export function isRuleFilePath(v: string): boolean {
  return /\.(?:yms|yara?|sigma)$/i.test(v.trim());
}

// Formats a rule pack ships: its signature SOURCE (Sigma .yml/.yaml) and the sample logs it ships to
// test those signatures against (.evtx/.etl — EVTX-ATTACK-SAMPLES and the like).
const DETECTION_CONTENT_EXT = /\.(?:yms|ya?ml|yara?|sigma|evtx|etl)$/i;

// A PathRegex that matches anywhere, i.e. one that makes no location claim at all. Absent, empty,
// ".", ".*" and "^.*$" all mean the same thing here.
const TRIVIAL_PATH_REGEX = /^(?:\.|\.\*|\^\.\*\$)?$/;

/**
 * Does the rule that fired claim something about WHERE the file is, or only about what it is CALLED?
 *
 * DetectRaptor's keyword rules carry `PathRegex: "."` — match anywhere — because the finding is the
 * name. Its location rules ("Suspicious Location") carry a real directory alternation, and their
 * finding is the placement, which the file's TYPE cannot invalidate.
 */
export function ruleClaimsLocation(row: Row): boolean {
  const d = getCI(row, "Detection");
  const pathRegex = isObject(d) ? str(getCI(d, "PathRegex")).trim() : "";
  return pathRegex !== "" && !TRIVIAL_PATH_REGEX.test(pathRegex);
}

/**
 * Is this hit the rule pack matching its OWN content rather than evidence from the host?
 *
 * Both halves are required. The extension says the file carries detection logic or a bundled sample;
 * the trivial PathRegex says the rule matched the file's NAME, so the hit means only "a file is
 * called after this tool" — which is what every signature and every sample log in a rule bundle is
 * called. A location rule fails the second half and keeps its grade.
 */
export function isDetectionContentHit(row: Row, path: string): boolean {
  return DETECTION_CONTENT_EXT.test(path.trim()) && !ruleClaimsLocation(row);
}
