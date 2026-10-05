// Defender-tamper timing cap (#1941).
//
// A Defender-tamper finding was graded High or Critical even when its evidence could not place it in
// the incident. Two shapes, both seen on the lab corpus (INC-2026-028):
//   - console history: a PSReadLine line (`Set-MpPreference -DisableRealtimeMonitoring $true`) has no
//     per-line time. The row carries the history FILE's time, so "13:24" can be a weeks-old command.
//   - before the incident: EID 5001 "Real-time Protection Disabled" rows dated days or weeks before
//     the first attack burst.
// This module owns the predicates; findingGrounding.ts applies the cap. The cap only lowers a
// finding's grade to Medium and marks why. It never changes a row's severity: the rows stay in the
// forensic timeline as leads.
//
// The marker lives here, not in stateTypes.ts (at its size ledger): `FindingDefenderCap` is the one
// extra field, and `findingTamperTiming` is the one reader.

import type { Finding, ForensicEvent, Severity } from "./stateTypes.js";
import { capabilityTechniques } from "./findingTextTechniques.js";

export type TamperTiming = "date-unknown" | "before-incident";
export interface FindingDefenderCap {
  tamperTiming?: TamperTiming;
}

export const TAMPER_CAP_SEVERITY: Severity = "Medium";
export const BURST_SPAN_MS = 24 * 3600_000;
export const BEFORE_BURST_MARGIN_MS = 48 * 3600_000;
export const BURST_MIN_ROWS = 3;
const TAMPER_TECHNIQUE = "T1562.001";

export const DATE_UNKNOWN_REASON =
  "capped: the only evidence is PowerShell console history, which has no per-line time — the row carries the history file's time, so the command may be much older than the incident; date unknown";
export const BEFORE_INCIDENT_REASON =
  "capped: every cited event is dated more than 48 h before the main activity burst — before the incident; keep it as a lead";

const PSREADLINE_ARTIFACT = /psreadline/i;
const HISTORY_FILE = /(?:^|[\\/])consolehost_history\.txt$/i;
const DEFENDER_CMDLET = /\b(?:Set|Add)-MpPreference\b/i;
const SHELL_HISTORY_SOURCE = "Shell history";

/**
 * True for a row read out of a PowerShell console-history file: a Velociraptor PSReadline artifact,
 * a ConsoleHost_history.txt path, or a generic shell-history row carrying a Defender cmdlet (only a
 * PSReadLine file can hold one, and it never stores a per-line time).
 */
export function isConsoleHistoryRow(e: ForensicEvent): boolean {
  if (e.artifactName && PSREADLINE_ARTIFACT.test(e.artifactName)) return true;
  if (e.path && HISTORY_FILE.test(e.path.trim())) return true;
  if ((e.sources ?? []).includes(SHELL_HISTORY_SOURCE))
    return DEFENDER_CMDLET.test(`${e.description} ${e.message ?? ""}`);
  return false;
}

export interface IncidentBurst {
  start: number; // epoch ms of the first row in the densest window
  end: number; // start + BURST_SPAN_MS
  count: number;
}

/**
 * The densest 24 h window of dated High/Critical rows (console-history rows are undated, so they do
 * not count). Undefined below BURST_MIN_ROWS. Ties go to the earliest window.
 */
export function incidentBurst(events: readonly ForensicEvent[]): IncidentBurst | undefined {
  const times = events
    .filter((e) => (e.severity === "High" || e.severity === "Critical") && !isConsoleHistoryRow(e))
    .map((e) => Date.parse(e.timestamp))
    .filter((t) => Number.isFinite(t))
    .sort((a, b) => a - b);
  let best: IncidentBurst | undefined;
  let j = 0;
  for (let i = 0; i < times.length; i++) {
    while (j < times.length && times[j] - times[i] <= BURST_SPAN_MS) j++;
    const count = j - i;
    if (!best || count > best.count) best = { start: times[i], end: times[i] + BURST_SPAN_MS, count };
  }
  return best && best.count >= BURST_MIN_ROWS ? best : undefined;
}

/** A Defender-tamper finding: tagged T1562.001, or its own text names the tampering. */
export function isTamperFinding(f: Finding): boolean {
  if ((f.mitreTechniques ?? []).includes(TAMPER_TECHNIQUE)) return true;
  return capabilityTechniques(`${f.title ?? ""}\n${f.description ?? ""}`).includes(TAMPER_TECHNIQUE);
}

/**
 * Why a tamper finding cannot be placed in the incident, or null. `date-unknown` when every cited row
 * is console history; `before-incident` when every cited row is dated more than 48 h before the burst.
 */
export function tamperTimingOf(
  f: Finding,
  supporting: readonly ForensicEvent[],
  burst: IncidentBurst | undefined,
): TamperTiming | null {
  if (!supporting.length || !isTamperFinding(f)) return null;
  if (supporting.every(isConsoleHistoryRow)) return "date-unknown";
  if (!burst) return null;
  const cutoff = burst.start - BEFORE_BURST_MARGIN_MS;
  const before = supporting.every((e) => {
    const t = Date.parse(e.timestamp);
    return Number.isFinite(t) && t < cutoff;
  });
  return before ? "before-incident" : null;
}

/** The finding's tamper-timing marker, when it carries a valid one. */
export function findingTamperTiming(f: Finding): TamperTiming | undefined {
  const t = (f as Finding & FindingDefenderCap).tamperTiming;
  return t === "date-unknown" || t === "before-incident" ? t : undefined;
}
