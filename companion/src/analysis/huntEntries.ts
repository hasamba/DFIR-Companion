import { createHash } from "node:crypto";
import type { ForensicEvent, Severity } from "./stateTypes.js";

/**
 * Grouped hunt entries (#2670, decisions D1/D4): ONE forensic-timeline entry per graded program,
 * listing its hosts, instead of one row per event — a routine update across 300 hosts must never
 * flood the timeline. PURE.
 *
 * An entry is a DERIVED SUMMARY, built from the host counts recorded at import (huntInventory.ts):
 *   - its id is deterministic per kind + item, so recalculation updates it rather than duplicating it;
 *   - it is graded above Info, so the forensic gate keeps it;
 *   - it says it is a summary (`provenance`, the "Hunt (…)" head) and never counts itself in the
 *     inventory (it is not a Velociraptor row);
 *   - each kind is capped at HUNT_ENTRY_CAP entries, with ONE visible "N more" entry for the rest. The
 *     cap limits hunt entries only: it never drops or regrades a detection.
 */
export type HuntGradeKind = "policy" | "new" | "rare" | "download";

export interface HuntGrade {
  itemKey: string;
  kind: HuntGradeKind;
  severity: Severity;
  label: string;
  reason: string;
  /** Hostnames, in a stable order. */
  hosts: string[];
  /** "of M answering hosts" when coverage is known; absent otherwise (no percentage claimed). */
  ofHosts?: number;
  firstSeen: string;
}

export const HUNT_ENTRY_PREFIX = "hunt-item:";
export const HUNT_ENTRY_CAP = 50;
export const HUNT_ENTRY_HOSTS = 10;
export const HUNT_ENTRY_PROVENANCE = "hunt summary (derived from host counts recorded at import)";

const KIND_TITLE: Record<HuntGradeKind, string> = {
  policy: "policy violation",
  new: "new since last comparable hunt",
  rare: "rare program",
  download: "flagged download",
};

const RANK: Record<Severity, number> = { Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0 };

export function huntEntryId(kind: HuntGradeKind, itemKey: string): string {
  return `${HUNT_ENTRY_PREFIX}${kind}:${createHash("sha1").update(itemKey).digest("hex").slice(0, 16)}`;
}

export const huntOverflowId = (kind: HuntGradeKind): string => `${HUNT_ENTRY_PREFIX}${kind}:more`;

export function hostList(hosts: readonly string[]): { shown: string[]; more: number } {
  const shown = hosts.slice(0, HUNT_ENTRY_HOSTS);
  return { shown, more: hosts.length - shown.length };
}

function entry(g: HuntGrade): ForensicEvent {
  const { shown, more } = hostList(g.hosts);
  const of = g.ofHosts !== undefined ? ` of ${g.ofHosts} answering` : "";
  const extra = more > 0 ? ` (+${more} more)` : "";
  return {
    id: huntEntryId(g.kind, g.itemKey),
    timestamp: g.firstSeen,
    description: `Hunt (${KIND_TITLE[g.kind]}): ${g.label} — on ${g.hosts.length}${of} host(s): ${shown.join(", ")}${extra}. ${g.reason}`,
    severity: g.severity,
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    sources: ["Hunt grading"],
    artifactName: `Hunt.${g.kind}`,
    provenance: [HUNT_ENTRY_PROVENANCE],
  };
}

function overflow(kind: HuntGradeKind, n: number, at: string): ForensicEvent {
  return {
    id: huntOverflowId(kind),
    timestamp: at,
    description: `Hunt (${KIND_TITLE[kind]}): ${n} more item(s) not listed here (cap ${HUNT_ENTRY_CAP}) — see the Threat Hunt panel.`,
    severity: "Low",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    sources: ["Hunt grading"],
    artifactName: `Hunt.${kind}`,
    provenance: [HUNT_ENTRY_PROVENANCE],
  };
}

/** Worst first, then rarest first, then by name — the order the cap keeps. */
export function rankGrades(grades: readonly HuntGrade[]): HuntGrade[] {
  return [...grades].sort(
    (a, b) =>
      RANK[b.severity] - RANK[a.severity] ||
      a.hosts.length - b.hosts.length ||
      a.label.localeCompare(b.label),
  );
}

/** The capped entries for every kind, plus one "N more" entry per kind that overflowed. */
export function buildHuntEntries(grades: readonly HuntGrade[], at: string): ForensicEvent[] {
  const out: ForensicEvent[] = [];
  for (const kind of ["policy", "new", "rare", "download"] as const) {
    const ranked = rankGrades(grades.filter((g) => g.kind === kind));
    out.push(...ranked.slice(0, HUNT_ENTRY_CAP).map(entry));
    if (ranked.length > HUNT_ENTRY_CAP) out.push(overflow(kind, ranked.length - HUNT_ENTRY_CAP, at));
  }
  return out;
}
