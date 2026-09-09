// Corroborating a timestomp against independent artifacts (#909 item 8).
//
// timestompDetect.ts compares $SI against $FN on a single MFT row. That is a good signal and a
// lonely one: both values live in the same record, so a tool that rewrites both defeats it, and a
// file legitimately copied from an older source trips it. What settles the question is an
// INDEPENDENT record of the same file's time — one the tool that rewrote the MFT did not touch:
//
//   • ShimCache keeps its own copy of a file's modification time, in the registry.
//   • The USN journal records that a timestamp changed, and when.
//   • A directory index ($I30) holds an older copy of the $FN times.
//
// A disagreement between the MFT and any of those is the corroboration. Agreement is not
// exoneration — a thorough tool rewrites more than one place — so this module raises confidence and
// never lowers it.
//
// ─────────────────────────── IDENTITY, WHICH IS THE HARD PART ───────────────────────────
//
// Corroborating "the same file" across artifacts is only sound if it IS the same file. A matching
// basename is not identity: every host has a dozen `setup.exe`. So a comparison requires a FULL
// PATH match at minimum, and prefers a file reference where the artifact carries one. Anything less
// is refused rather than guessed, because a wrong pairing invents a discrepancy out of two
// unrelated files.
//
// ─────────────────────────── WEAK CLUES STAY WEAK ───────────────────────────
//
//   • A PE build timestamp is set by the compiler, is trivially forged, and legitimately differs
//     from every filesystem time. It is context, never evidence.
//   • MFT allocation order suggests when a record was created, and is disturbed by ordinary reuse.
//   • BASIC_INFO_CHANGE in the journal means the $STANDARD_INFORMATION attribute changed — which
//     covers read-only, hidden, archive and system flags as well as timestamps. On its own it
//     means "an attribute changed", and reading it as "the timestamps were rewritten" would flag
//     every file Windows marks archive.
//
// So none of those three can raise a verdict alone, and the code enforces that rather than trusting
// the caller.

import type { Severity } from "./stateTypes.js";

/** One artifact's record of a file's timestamp, and where it came from. */
export interface TimeObservation {
  source: "MFT" | "ShimCache" | "USN" | "I30" | "Prefetch" | "Amcache";
  /** Full path. A basename alone is refused — see the header. */
  path: string;
  /** The file reference, when the artifact carries one. Stronger identity than a path. */
  reference?: string;
  /** The modification time this artifact recorded, ISO. */
  modified?: string;
  /** The creation time this artifact recorded, ISO. */
  created?: string;
  /** For a USN observation: the reasons the record carried. */
  reasons?: string[];
}

export type CorroborationKind = "shimcache-disagrees" | "i30-disagrees" | "journal-timestamp-change";

export interface Corroboration {
  kind: CorroborationKind;
  source: TimeObservation["source"];
  detail: string;
}

export interface CorroboratedVerdict {
  severity: Severity;
  mitre: string[];
  corroborations: Corroboration[];
  note: string;
}

/** How far two independent records of one time may differ before it is a disagreement. */
export const TIME_TOLERANCE_MS = 2000;

function ms(v: string | undefined): number | null {
  if (!v) return null;
  const t = Date.parse(v);
  return Number.isNaN(t) ? null : t;
}

function normPath(p: string): string {
  return String(p ?? "")
    .trim()
    .toLowerCase()
    .replace(/^\\\\\?\\/, "")
    .replace(/\//g, "\\");
}

/**
 * Do two observations describe the same file?
 *
 * A file reference on both sides settles it. Otherwise a full path must match — and a value with no
 * directory separator is not a full path, so it is refused. Every host has a dozen `setup.exe`, and
 * pairing two of them invents a discrepancy from two unrelated files.
 */
export function sameFile(a: TimeObservation, b: TimeObservation): boolean {
  if (a.reference && b.reference) return a.reference === b.reference;
  const pa = normPath(a.path);
  const pb = normPath(b.path);
  if (!pa || !pb) return false;
  if (!pa.includes("\\") || !pb.includes("\\")) return false; // a bare name is not identity
  return pa === pb;
}

/**
 * Weigh an MFT-derived timestomp signal against independent records of the same file.
 *
 * `base` is what timestompDetect already concluded from $SI vs $FN — or null when it concluded
 * nothing, in which case corroboration can still surface a discrepancy the single-row check cannot
 * see.
 */
export function corroborateTimestomp(
  subject: TimeObservation,
  others: readonly TimeObservation[],
  base: { severity: Severity; note: string } | null,
): CorroboratedVerdict | null {
  const subjectModified = ms(subject.modified);
  const corroborations: Corroboration[] = [];

  for (const o of others) {
    if (o === subject) continue;
    if (!sameFile(subject, o)) continue;

    if (o.source === "ShimCache" && subjectModified !== null) {
      const shim = ms(o.modified);
      if (shim !== null && Math.abs(shim - subjectModified) > TIME_TOLERANCE_MS) {
        corroborations.push({
          kind: "shimcache-disagrees",
          source: "ShimCache",
          detail:
            `ShimCache recorded a modification time of ${o.modified} for this file while the MFT ` +
            `records ${subject.modified}. ShimCache keeps its copy in the registry, which a tool ` +
            "rewriting the MFT does not necessarily touch.",
        });
      }
    }

    if (o.source === "I30") {
      const idx = ms(o.created);
      const subjCreated = ms(subject.created);
      if (idx !== null && subjCreated !== null && Math.abs(idx - subjCreated) > TIME_TOLERANCE_MS) {
        corroborations.push({
          kind: "i30-disagrees",
          source: "I30",
          detail:
            `the directory index holds an older creation time (${o.created}) than the MFT record ` +
            `(${subject.created}). The index is updated separately from the record it describes.`,
        });
      }
    }

    if (o.source === "USN" && o.reasons?.includes("BASIC_INFO_CHANGE")) {
      corroborations.push({
        kind: "journal-timestamp-change",
        source: "USN",
        detail:
          "the journal recorded a BASIC_INFO_CHANGE for this file. That attribute covers the " +
          "read-only, hidden, archive and system flags as well as the timestamps, so on its own it " +
          "means an attribute changed — not that the times were rewritten.",
      });
    }
  }

  // BASIC_INFO_CHANGE cannot carry a verdict by itself, for the reason its own detail gives. With
  // nothing else, there is nothing to report that would not overstate the evidence.
  const independent = corroborations.filter((c) => c.kind !== "journal-timestamp-change");
  if (!base && independent.length === 0) return null;
  if (corroborations.length === 0) return null;

  // Corroboration RAISES. Two records of one file disagreeing is materially stronger than one
  // record disagreeing with itself, and Medium is where the single-row check already sits.
  const severity: Severity = independent.length > 0 ? "High" : (base?.severity ?? "Medium");

  return {
    severity,
    mitre: ["T1070.006"],
    corroborations,
    note:
      (base ? `${base.note} ` : "") +
      `Corroboration: ${corroborations.map((c) => c.detail).join(" ")}` +
      (independent.length === 0
        ? " Nothing independent of the MFT contradicts these times, so this remains a lead."
        : " An artifact independent of the MFT disagrees, which is harder to explain by ordinary" +
          " copying or restoration than the single-record signal alone.") +
      " Agreement elsewhere would not clear the file: a thorough tool rewrites more than one place.",
  };
}

// ─────────────────────────── the timeline pass ───────────────────────────

/** The marker this pass appends. Stripped by correlate.ts before a duplicate key is taken. */
export const TIMESTOMP_CORROBORATION_MARKER = "[timestomp corroboration:";

interface TimelineEventShape {
  description?: string;
  severity?: Severity;
  mitreTechniques?: string[];
  path?: string;
  sources?: string[];
  timestamp?: string;
  fileModified?: string;
}

const RANK: Record<string, number> = { Info: 0, Low: 1, Medium: 2, High: 3, Critical: 4 };

/**
 * Weigh every MFT-derived timestomp signal against what other artifacts recorded for the same file.
 *
 * Runs over the whole timeline because the artifacts arrive as SEPARATE imports — the MFT from one
 * CSV, ShimCache from another — so there is no earlier point at which both are in hand.
 *
 * Only ever raises, and is idempotent.
 */
export function corroborateTimestompsOnTimeline<T extends TimelineEventShape>(events: readonly T[]): T[] {
  // Cheap exit for the overwhelmingly common case: no MFT timestomp signal in the case at all.
  const hasSignal = events.some((e) => /T1070\.006/.test((e.mitreTechniques ?? []).join(",")));
  if (!hasSignal) return events as T[];

  const observations: TimeObservation[] = [];
  for (const e of events) {
    const path = e.path ?? "";
    if (!path) continue;
    const src = (e.sources ?? []).join(" ");
    const source: TimeObservation["source"] | null = /ShimCache/i.test(src)
      ? "ShimCache"
      : /UsnJrnl|USN/i.test(src)
        ? "USN"
        : /MFT/i.test(src)
          ? "MFT"
          : null;
    if (!source) continue;
    observations.push({
      source,
      path,
      ...(e.fileModified ? { modified: e.fileModified } : {}),
      ...(e.timestamp ? { created: e.timestamp } : {}),
      // The journal's reasons live in the description; BASIC_INFO_CHANGE is the only one read, and
      // it can never carry a verdict alone, so recognising it from text cannot manufacture one.
      ...(source === "USN" && /BASIC_INFO_CHANGE|BasicInfoChange/i.test(e.description ?? "")
        ? { reasons: ["BASIC_INFO_CHANGE"] }
        : {}),
    });
  }

  return events.map((e) => {
    if (!(e.mitreTechniques ?? []).includes("T1070.006")) return e;
    if ((e.description ?? "").includes(TIMESTOMP_CORROBORATION_MARKER)) return e;
    if (!/MFT/i.test((e.sources ?? []).join(" "))) return e;
    const subject = observations.find((o) => o.source === "MFT" && o.path === e.path);
    if (!subject) return e;

    const verdict = corroborateTimestomp(subject, observations, {
      severity: e.severity ?? "Medium",
      note: "",
    });
    if (!verdict) return e;

    const severity =
      RANK[verdict.severity] > RANK[e.severity ?? "Info"] ? verdict.severity : (e.severity ?? "Info");
    const base = (e.description ?? "").slice(0, 700);
    return {
      ...e,
      severity,
      description: `${base} ${TIMESTOMP_CORROBORATION_MARKER} ${verdict.note.trim()}]`.trim(),
    };
  });
}
