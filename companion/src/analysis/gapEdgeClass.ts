import { GAP_FINDING_ID_PREFIX, WAVES_FINDING_ID } from "./responseSchema.js";
import { SEVERITY_RANK, type ForensicEvent } from "./stateTypes.js";
import type { TimelineGap } from "./gapDetect.js";
import type { WavePattern } from "./activityWaves.js";

// What sits on either side of a silence (#1503).
//
// gapDetect.ts finds the silences and activityWaves.ts decides which of them separate two bursts of
// activity. Neither asks WHAT the bursts contain. A lab VM's build history — install media, base
// image, Vagrant/Chocolatey provisioning, then the first session months later — is four bursts of
// Info-graded OS rows separated by months, which is exactly the shape the wave detector was built
// to flag. Scenario 017 got five "dwell interval" findings, three Medium, describing the image
// build, and an open thread asking the analyst to resolve them.
//
// Two edge readings, both deterministic and both pure:
//   • PROVISIONING edges — both rows bounding the silence are OS servicing / image-build artifacts
//     (Windows Update, servicing stack, Chocolatey, sysprep…) graded Info/Low with no technique and
//     no finding of their own. The silence is idle time between two maintenance events, not a lead.
//   • ATTACKER edges — the two waves a dwell interval separates BOTH hold a High/Critical row, on the
//     same asset when the rows name one. Only such an interval earns the Medium dwell finding; a
//     quiet stretch between two benign bursts stays a panel row.
//
// The patterns are deliberately narrow. `msiexec.exe` and `setup.exe` are NOT here: an attacker
// installs things too, and an Amcache row proves presence, not provenance. A dual-use name only
// ever reads as provisioning when it sits under a servicing path, carries no grade and no finding.

const PROVISIONING_PATTERNS: ReadonlyArray<{ reason: string; re: RegExp }> = [
  { reason: "chocolatey", re: /\\programdata\\chocolatey\\|\bchoco(?:latey)?(?:\.exe)?\b/ },
  { reason: "vagrant", re: /\bvagrant\b/ },
  { reason: "sysprep/unattend", re: /\bsysprep\b|\\windows\\panther\\|\bunattend\.xml\b/ },
  {
    reason: "windows-update",
    re: /\\windows\\softwaredistribution\\|\bwuauclt\.exe\b|\bwusa\.exe\b|\bmousocoreworker\.exe\b|\busoclient\.exe\b|\bwindows update\b/,
  },
  {
    reason: "servicing",
    re: /\\windows\\servicing\\|\\windows\\winsxs\\|\btiworker\.exe\b|\btrustedinstaller\.exe\b/,
  },
  { reason: "installer/driverstore", re: /\\windows\\installer\\|\\windows\\system32\\driverstore\\/ },
];

// A finding minted BY gap analysis (a gap or waves finding from an earlier run) must not stop a
// row from reading as provisioning on the next run — that would let a wrong finding defend itself.
export function hasOwnFinding(e: ForensicEvent): boolean {
  return e.relatedFindingIds.some((id) => id !== WAVES_FINDING_ID && !id.startsWith(GAP_FINDING_ID_PREFIX));
}

// Why an event reads as an OS servicing / image-build artifact, or null when it does not. A row
// graded above Low, tagged with a technique, or backing a real finding never qualifies, whatever
// its name — the guard against suppressing a silence bounded by dual-use tooling.
export function provisioningReason(e: ForensicEvent): string | null {
  if (SEVERITY_RANK[e.severity] < SEVERITY_RANK.Low) return null;
  if (e.mitreTechniques.length > 0 || hasOwnFinding(e)) return null;
  const hay = `${e.path ?? ""} ${e.processName ?? ""} ${e.description}`.toLowerCase();
  for (const p of PROVISIONING_PATTERNS) if (p.re.test(hay)) return p.reason;
  return null;
}

// Attacker-graded: High or Critical. The product's own grade (importer + content tagger), which is
// what the forensic timeline is built on — findings are the OUTPUT of this pass, so gating on them
// would be circular.
function isSevere(e: ForensicEvent): boolean {
  return SEVERITY_RANK[e.severity] <= SEVERITY_RANK.High;
}

// The first DNS label, upper-cased — the key hostIdentity.shortHostName compares on.
export function assetKey(e: ForensicEvent): string {
  return (e.asset ?? "").trim().split(".")[0].toUpperCase();
}

// The assets that carry a High/Critical row in one wave. "" stands for rows that name no asset.
export function severeAssetsOf(wave: readonly ForensicEvent[]): Set<string> {
  const out = new Set<string>();
  for (const e of wave) if (isSevere(e)) out.add(assetKey(e));
  return out;
}

// Do two adjacent waves both hold attacker-graded activity on a common footing? Same asset when
// both sides name one; a side whose severe rows name no asset is environment-wide and matches any.
// A High on host A and a High on host B do not make a dwell interval between them.
export function attackerGradedInterval(before: ReadonlySet<string>, after: ReadonlySet<string>): boolean {
  if (before.size === 0 || after.size === 0) return false;
  if (before.has("") || after.has("")) return true;
  for (const a of before) if (after.has(a)) return true;
  return false;
}

// Corroboration for a complete gap (#1942). A silence alone is a lead: an idle lab VM between two
// runs is as dark as a cleared log. A complete gap earns High only when a Medium-or-higher row sits
// at either edge, or the case records a real anti-forensic event — a log clear (EID 1102 / 104) or an
// audit-policy change (EID 4719, T1562.002). The clear-text matcher is a copy of the one in
// collectionInventory.ts: that module sits in analysis/ai, which this detect-layer file may not
// import. A row that RECORDS a clear counts; a Prefetch row showing wevtutil.exe ran does not.
const CLEAR_TEXT_RE =
  /\b(?:security\s+audit\s+log\s+(?:was\s+)?cleared|event\s*log\s+(?:was\s+)?cleared|log\s+file\s+was\s+cleared|(?:security|system|application)\s+log\s+(?:was\s+)?cleared)\b/i;
// "EID 1102", "EventID: 104", "Event ID 4719", "(1102)". The digit guard keeps 11020 out.
const eidRe = (ids: string): RegExp =>
  new RegExp(String.raw`\b(?:eid|event\s*id)\s*[:#=]?\s*(?:${ids})(?!\d)|\((?:${ids})\)`, "i");
const CLEAR_EID_RE = eidRe("1102|104");
const AUDIT_OFF_EID_RE = eidRe("4719");
// A reboot or shutdown: 1074 (shutdown initiated), 6006 / 6005 (event-log service stop / start),
// 6008 (unexpected shutdown), 6009 / 4608 (boot) — or the canonical `boot` type objectAccess.ts sets.
const REBOOT_EID_RE = eidRe("1074|6005|6006|6008|6009|4608");
const REBOOT_TEXT_RE = /\bhas initiated the (?:restart|power off|shutdown)\b/i;

function rowText(e: ForensicEvent): string {
  return `${e.description} ${e.message ?? ""}`;
}

export function isAntiForensicRow(e: ForensicEvent): boolean {
  const text = rowText(e);
  if (CLEAR_TEXT_RE.test(text) || CLEAR_EID_RE.test(text) || AUDIT_OFF_EID_RE.test(text)) return true;
  return e.mitreTechniques.includes("T1562.002");
}

export function isRebootRow(e: ForensicEvent): boolean {
  if (e.canonical?.event.type === "boot") return true;
  const text = rowText(e);
  return REBOOT_EID_RE.test(text) || REBOOT_TEXT_RE.test(text);
}

const atLeastMedium = (e: ForensicEvent | undefined): boolean =>
  e !== undefined && SEVERITY_RANK[e.severity] <= SEVERITY_RANK.Medium;

// Grade one complete, non-wave gap. A reboot at either edge explains the silence, so it stays Low
// whatever else the case holds — the clear or the attack row is a finding of its own.
function gradeCompleteGap(
  before: ForensicEvent | undefined,
  after: ForensicEvent | undefined,
  antiForensic: boolean,
): Pick<TimelineGap, "severity" | "corroborated" | "rebootEdge"> {
  const reboot = (before !== undefined && isRebootRow(before)) || (after !== undefined && isRebootRow(after));
  const corroborated = !reboot && (antiForensic || atLeastMedium(before) || atLeastMedium(after));
  return { severity: corroborated ? "High" : "Low", corroborated, ...(reboot ? { rebootEdge: true } : {}) };
}

// Classify every gap's edges. Pure: returns new gap objects.
//   • `hostHistory` — the silence opens on a row of a renamed host's pre-provisioning history
//     (gapHostHistory.ts); `historyIds` are those rows.
//   • `attackerEdges` — set on a `betweenWaves` gap when the interval it marks is attacker-graded
//     (activityWaves.ts computes that per interval from the wave contents).
//   • `provisioningEdges` / `provisioningReason` — both bounding rows are servicing artifacts.
//     Two High waves around two idle edge rows are still two visits: attackerEdges wins, so the
//     dwell finding and the waves finding never disagree about the same window.
//   • `severity` / `corroborated` / `rebootEdge` — on a complete, non-wave gap only (#1942); see
//     gradeCompleteGap. Partial gaps and dwell intervals keep their grade.
export function classifyGapEdges(
  gaps: readonly TimelineGap[],
  events: readonly ForensicEvent[],
  pattern: WavePattern | null,
  historyIds: ReadonlySet<string> = new Set(),
): TimelineGap[] {
  const byId = new Map(events.map((e) => [e.id, e]));
  // A between-waves gap resumes at wave k's first event; the interval before it is intervals[k-1].
  const gradedByResume = new Map<string, boolean>();
  if (pattern) {
    pattern.waves.slice(1).forEach((w, i) => {
      gradedByResume.set(w.firstEventId, pattern.intervals[i]?.attackerGraded === true);
    });
  }
  const antiForensic = gaps.some((g) => g.complete) && events.some(isAntiForensicRow);
  return gaps.map((g) => {
    const before = byId.get(g.beforeEventId);
    const after = byId.get(g.afterEventId);
    const reasonBefore = before ? provisioningReason(before) : null;
    const reasonAfter = after ? provisioningReason(after) : null;
    const next: TimelineGap = { ...g };
    if (g.complete && !g.betweenWaves) Object.assign(next, gradeCompleteGap(before, after, antiForensic));
    if (historyIds.has(g.beforeEventId)) next.hostHistory = true;
    if (g.betweenWaves) next.attackerEdges = gradedByResume.get(g.afterEventId) === true;
    if (reasonBefore && reasonAfter && !next.attackerEdges) {
      next.provisioningEdges = true;
      next.provisioningReason =
        reasonBefore === reasonAfter ? reasonBefore : `${reasonBefore} → ${reasonAfter}`;
    }
    return next;
  });
}
