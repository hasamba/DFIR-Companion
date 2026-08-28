// Contextual grading for a Velociraptor YARA hit.
//
// velociraptorImport.mapYara used to stamp EVERY hit `High` ("a YARA hit is a real detection
// verdict"). On a real host-wide scan that buried the timeline: across the four eval collections
// 91% of the admitted YARA High events were unrelated to the incident — string remnants in
// `pagefile.sys` / `MEMORY.DMP`, the detector scanning its own rule tree and sample corpus, cached
// copies of other simulation scripts, and broad heuristic rules (`*_SUSP_*`, `INDICATOR_SUSPICIOUS_*`,
// a God-Mode test rule) firing on trusted OS binaries. Scenario 008, which had NO ransomware, still
// produced eight High "ransomware" YARA findings from memory strings.
//
// This module keeps the veloDetectionNoise design rule: EVERY branch here LOWERS a grade, never
// raises one, and it lowers only on signals the attacker does not choose. A rule that names a real
// malware family, hitting a normal on-disk path, is unchanged — it stays High. What moves:
//
//   self-scan / detector tooling  → Info   (out of the forensic timeline; the tool found itself)
//   volatile memory container     → Low    (a string in swapped memory is not proof of execution)
//   heuristic rule on a trusted    → Info   (a signed OS/AV binary matching a weak string)
//     OS/signed binary
//   heuristic rule elsewhere       → Medium (an anomaly worth review, not a confirmed verdict)
//
// The safety argument is the same one veloDetectionNoise makes: the demotion is bounded so a rule
// that named a technique keeps its grade. A STRONG (named-malware) rule is never lowered below High
// by the heuristic-rule branches — only by the volatile-container branch, and only to Low, because
// a family's strings sitting in the page file really is weaker evidence than the same strings in a
// dropped executable, whatever the rule's confidence.

import type { Severity } from "./stateTypes.js";
import { isDetectionToolLocation, isVolatileContainer } from "./veloDetectionNoise.js";

export interface YaraGrade {
  severity: Severity;
  /** true when the hit was inside a volatile memory container (pagefile / hiberfil / *.dmp). The
   *  caller aggregates these into one row per host so they never crowd the timeline. */
  volatile: boolean;
  /** short machine tag for the demotion reason, appended to the description so the analyst sees WHY. */
  reason: "" | "self-scan" | "volatile-container" | "heuristic-trusted" | "heuristic";
}

// A rule whose NAME marks it as a broad heuristic / anomaly / test rule rather than a named-malware
// signature. Matched case-insensitively as SUBSTRINGS — YARA rule names are underscore-delimited
// tokens (`SECUINFRA_SUSP_Powershell_...`), so a `\b` boundary fails between a letter and `_`; plain
// substring matching sidesteps that. Everything that does NOT match here stays High — the list only
// needs the demote-worthy shapes, and an unknown family rule is treated as a real verdict by default
// (fail closed toward keeping evidence).
const HEURISTIC_RULE =
  /SUSP|SUSPICIOUS|_SUS_|INDICATOR|ANOMALY|GODMODE|GOD_MODE|IDDQD|SMUGGLING|CARET|OBFUSCAT|NONEWINDOWSUA|REGKEYCOMB|REVERSED|WEBDOWNLOAD|DOWNLOAD_TEMP|REFERENCES_CONFIDENTIAL|POWERSHELL_(?:DOWNLOAD|CASE|WEB|LARGE)|_STRINGS?(?:_|$)|KEYWORD/i;

// Signed first-party locations where a weak string match is almost always the OS/AV product itself
// (the "Defender binary matches a Defender registry string" class), NOT an intrusion. Kept separate
// from isDetectionToolLocation because this one only demotes IN COMBINATION with a heuristic rule —
// a named-malware rule hitting System32 is a real finding (masquerade / DLL drop) and stays High.
const TRUSTED_OS_LOCATION =
  /\\Windows\\(?:System32|SysWOW64|WinSxS|servicing|SoftwareDistribution|Microsoft\.NET|assembly|Fonts|ImmersiveControlPanel)\\|\\Program Files( \(x86\))?\\(?:Windows Defender|Microsoft|WindowsApps|Common Files)\\|\\Microsoft\\Edge(WebView)?\\|\\WindowsDefender\\/i;

export function isHeuristicYaraRule(ruleName: string): boolean {
  return HEURISTIC_RULE.test(ruleName || "");
}

/**
 * Grade one YARA hit from its observed context: the rule name, the matched file path, and the owning
 * process name (either may be empty). Never returns a grade above High.
 */
export function gradeYaraHit(ruleName: string, path: string, procName: string): YaraGrade {
  const where = path || "";
  const proc = procName || "";

  // 1. The detector found its own tooling, rule tree, sample corpus, or a cached simulation repo —
  //    or the matched "process" is the Velociraptor collector itself. Not host evidence.
  if (isDetectionToolLocation(where) || isDetectionToolLocation(proc)) {
    return { severity: "Info", volatile: false, reason: "self-scan" };
  }

  // 2. A string inside a volatile memory container. It may mean the malware ran once, so it is kept
  //    (Low, and aggregated), but it is never proof on its own and never headlines the timeline.
  if (isVolatileContainer(where)) {
    return { severity: "Low", volatile: true, reason: "volatile-container" };
  }

  // 3. A broad heuristic / anomaly / test rule.
  if (isHeuristicYaraRule(ruleName)) {
    // …on a signed OS/AV binary is the classic self-inflicted false positive. Demote to Low, not
    // Info: a System32/WinSxS path IS attacker-influenceable (a masqueraded DLL, a BYOVD driver), so
    // the hit stays in the forensic timeline for review — it just leaves the suspicious (Medium+) tier.
    if (TRUSTED_OS_LOCATION.test(where)) {
      return { severity: "Low", volatile: false, reason: "heuristic-trusted" };
    }
    // …anywhere else is an anomaly worth a look, not a confirmed verdict.
    return { severity: "Medium", volatile: false, reason: "heuristic" };
  }

  // 4. A named-malware rule on a normal path — the case mapYara was built for. Unchanged.
  return { severity: "High", volatile: false, reason: "" };
}
