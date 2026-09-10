// Turning a Linux persistence collection into timeline events (#908 item 5).
//
// The parsers are in linuxPersistence.ts and the grading is in linuxPersistRules.ts. This module is
// the seam between them and the case: it decides what becomes an event, what becomes an IOC, and
// what the import note tells the analyst about the parts it could not read.
//
// ─────────────────────────── WHY GRADED FINDINGS ONLY BECOME EVENTS ───────────────────────────
//
// A collection holds hundreds of ordinary lines. Every one of them is real evidence and every one is
// preserved — the uploaded file is stored intact, as every import is. What does NOT happen is one
// timeline row per line: a host's whole crontab on the timeline is the crontab, not an investigation.
// Only the graded findings become events, and each one carries the line it came from so the analyst
// reads the original text rather than a summary of it.
//
// ─────────────────────────── THE TIMESTAMP PROBLEM ───────────────────────────
//
// Most collections carry no modification times, so most of these events have no time of their own.
// An event with an invented timestamp is worse than one that says it has none: it puts a persistence
// mechanism at a moment in the attack it may have nothing to do with. Where the collection recorded
// an mtime, that is the event time. Where it did not, the event is stamped with the IMPORT time and
// its description says so, so nobody reads its position on the timeline as a finding.

import type { Severity } from "./stateTypes.js";
import { splitCollection, singleArtifact, type CollectedFile } from "./linuxPersistence.js";
import { analyzeLinuxCollection, type LinuxContext, type LinuxSignal } from "./linuxPersistRules.js";

export interface LinuxPersistEvent {
  timestamp: string;
  description: string;
  severity: Severity;
  mitreTechniques: string[];
  sources: string[];
  aggKey: string;
  path: string;
}

export interface LinuxPersistParse {
  files: CollectedFile[];
  signals: LinuxSignal[];
  events: LinuxPersistEvent[];
  iocs: { type: "file"; value: string }[];
  note: string;
}

/** Cap on IOCs from one collection. */
export const MAX_IOCS = 200;

const DESCRIPTION_MAX = 900;

/**
 * The window to judge "changed during the incident" against.
 *
 * Taken from the case's own High and Critical events, because that is the only definition the
 * importer can compute without asking the analyst. Fewer than two such events means the case has not
 * established a window yet, and no window is returned — the incident-time rule then simply does not
 * fire, which is the correct answer rather than a guessed one.
 */
export function incidentWindowFromTimeline(
  events: readonly { timestamp?: string; severity?: string }[],
): { start: string; end: string } | undefined {
  const times = events
    .filter((e) => e.severity === "High" || e.severity === "Critical")
    .map((e) => Date.parse(e.timestamp ?? ""))
    .filter((t) => Number.isFinite(t));
  if (times.length < 2) return undefined;
  return {
    start: new Date(Math.min(...times)).toISOString(),
    end: new Date(Math.max(...times)).toISOString(),
  };
}

/** Read an upload as a collection, or — when it carries no headers — as one named artifact. */
export function readCollection(filename: string, text: string): CollectedFile[] {
  const members = splitCollection(text);
  if (members.some((m) => m.kind !== "unknown")) return members;
  const base = (filename ?? "").split(/[\\/]/).pop() ?? "";
  return singleArtifact(base.replace(/\.(?:txt|log|out)$/i, ""), text);
}

function describe(s: LinuxSignal, label: string): string {
  const where = s.line > 1 ? `${s.artifact}:${s.line}` : s.artifact;
  return `${label} — ${where}: ${s.reason} Collected line: ${s.evidence}`.slice(0, DESCRIPTION_MAX);
}

/**
 * Turn graded signals into timeline events. Shared with the macOS importer (#908 item 6), which
 * grades different artifacts but has exactly the same timestamp problem and the same dedup need.
 */
export function signalsToEvents(
  signals: readonly LinuxSignal[],
  files: readonly CollectedFile[],
  fallbackTime: string,
  label: string,
  source: string,
  keyPrefix: string,
): LinuxPersistEvent[] {
  const mtimeOf = new Map(files.map((f) => [f.path, f.mtime]));
  return signals.map((s) => {
    const mtime = mtimeOf.get(s.artifact);
    const timed = !!mtime && Number.isFinite(Date.parse(mtime));
    return {
      timestamp: timed ? (mtime) : fallbackTime,
      description: timed
        ? describe(s, label)
        : `${describe(s, label)} [no collected timestamp — placed at the import time, not at a time this change is known to have happened]`.slice(
            0,
            DESCRIPTION_MAX,
          ),
      severity: s.severity,
      mitreTechniques: s.mitre,
      sources: [source],
      // The artifact, the line and the rule together. Re-importing the same collection, or the same
      // file collected twice by two tools, produces one row rather than a second copy.
      aggKey: `${keyPrefix}|${s.artifact}|${s.line}|${s.kind}|${s.mitre.join(",")}`,
      path: s.artifact,
    };
  });
}

/** The payload paths a set of signals named, deduplicated and capped. */
export function iocsFromSignals(signals: readonly LinuxSignal[]): { type: "file"; value: string }[] {
  const seen = new Set<string>();
  const out: { type: "file"; value: string }[] = [];
  for (const s of signals) {
    // The payload, not the artifact: /etc/crontab is on every host and is not an indicator.
    const value = s.target;
    if (!value || !value.startsWith("/") || seen.has(value)) continue;
    seen.add(value);
    if (out.length < MAX_IOCS) out.push({ type: "file", value });
  }
  return out;
}

/** What the import read, what it skipped, and what it could not date. */
export function collectionNote(
  files: readonly CollectedFile[],
  signals: readonly LinuxSignal[],
  label: string,
): string {
  const readable = files.filter((f) => f.kind !== "unknown");
  const skipped = files.length - readable.length;
  const undated = readable.filter((f) => !f.mtime).length;
  return (
    `${label} import: ${readable.length} artifact file(s) read` +
    (skipped ? `, ${skipped} member(s) skipped because their path names no artifact class this reads` : "") +
    `, ${signals.length} finding(s)` +
    (undated
      ? `. ${undated} of the files carried no modification time, so whether they changed during the incident could not be checked`
      : "")
  );
}

export function parseLinuxPersist(
  filename: string,
  text: string,
  ctx: LinuxContext = {},
  fallbackTime = new Date().toISOString(),
): LinuxPersistParse {
  const files = readCollection(filename, text);
  const signals = analyzeLinuxCollection(files, ctx);
  return {
    files,
    signals,
    events: signalsToEvents(
      signals,
      files,
      fallbackTime,
      "Linux persistence",
      "Linux persistence",
      "linuxpersist",
    ),
    iocs: iocsFromSignals(signals),
    note: collectionNote(files, signals, "Linux persistence"),
  };
}
