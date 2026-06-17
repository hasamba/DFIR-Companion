// Adversary emulation — offline "likely next techniques" from the matched adversary groups (issue #121).
//
// adversaryHints.ts answers "which known ATT&CK groups favour the same techniques this case used?".
// This module takes the step the analyst actually wants for HUNTING: given those matched groups,
// which techniques are they known to use that the case has NOT yet observed? Those are the
// highest-value places to look next — the lookalike actors' typical tradecraft we haven't caught.
//
// PURE and OFFLINE: input is the case's observed technique ids + the ranked hints + the groups
// dataset, output is the ranked "next technique" suggestions. No AI call, no network, no I/O.
//
// "Not yet observed" is judged at the BASE technique level: if the case already shows T1059.001
// (PowerShell), a group's T1059.003 (cmd) is NOT suggested — the analyst is already on
// command-interpreter ground. A suggestion points at a technique family the case hasn't touched at
// all, so it opens NEW hunting ground rather than a variation of what's already seen.
//
// Each suggestion carries its SUPPORT — how many of the matched groups use it. A technique used by 4
// of 5 lookalike groups is a stronger "watch for this next" than one used by a single group. Ties
// break toward the worst stage (impact/exfil) so the most damaging plausible next move surfaces first.
//
// SAME framing as adversary hints: statistical, predictive hypothesis fuel for hunt prioritization —
// NOT attribution, and NOT a claim the actor WILL do this. Every surface that renders it says so.

import { tacticForTechniques } from "../integrations/iris/mitreTactics.js";
import { attackTechniqueUrl } from "./attack.js";
import {
  baseTechniqueId,
  normalizeTechniqueId,
  type AdversaryGroup,
  type AdversaryHint,
} from "./adversaryHints.js";

// One matched group that supports a given next-technique suggestion.
export interface NextTechniqueGroup {
  id: string; // ATT&CK group id, e.g. "G0016"
  name: string; // e.g. "APT29"
}

// One predicted "next technique" — a technique the matched groups are known to use that the case has
// not observed (at base level), with its support (how many matched groups use it) and its hunt focus.
export interface NextTechnique {
  id: string; // ATT&CK technique id at the granularity the group lists it (T1486, T1021.001)
  url: string | null; // attack.mitre.org technique page (null only for an unparseable id — defensive)
  tactic: string; // ATT&CK tactic name for hunt focus ("Impact"), or "Unspecified"
  groupCount: number; // how many of the matched groups are known to use it (support / confidence)
  groups: NextTechniqueGroup[]; // which matched groups use it (id + name), sorted by id
}

export const DEFAULT_MAX_NEXT_TECHNIQUES = 10;

// The standing disclaimer, shared by every surface that renders next-technique suggestions.
export const ADVERSARY_EMULATION_CAVEAT =
  "Predictive hunt priorities from lookalike groups' tradecraft — hypothesis fuel, not attribution or a forecast.";

// Tie-break order: among equally-supported techniques, surface the worst plausible next stage first
// so the most damaging move the actor might make next is what the analyst sees at the top.
const TACTIC_RANK: Record<string, number> = {
  Impact: 0,
  Exfiltration: 1,
  "Credential Access": 2,
  "Lateral Movement": 3,
  "Privilege Escalation": 4,
  Persistence: 5,
  Collection: 6,
  "Command and Control": 7,
  "Initial Access": 8,
  Discovery: 9,
  "Defense Evasion": 10,
  Execution: 11,
};
const UNSPECIFIED = "Unspecified";

// Given the case's observed techniques and the ranked group hints, suggest the matched groups'
// techniques the case has NOT yet observed (base-level), ranked by support (how many matched groups
// use each), then by worst tactic, then by id for determinism. Pure: the groups dataset supplies each
// hint's FULL technique list (AdversaryHint carries only the overlap, not the group's whole set), so
// the dataset must be passed alongside the hints.
export function suggestNextTechniques(
  caseTechniques: readonly string[],
  hints: readonly AdversaryHint[],
  groups: readonly AdversaryGroup[],
  opts: { maxTechniques?: number } = {},
): NextTechnique[] {
  const max = Math.max(1, Math.floor(opts.maxTechniques ?? DEFAULT_MAX_NEXT_TECHNIQUES));
  if (hints.length === 0) return [];

  // Bases the case has already observed — a suggestion must open NEW ground, not a sub-technique of
  // something already seen.
  const observedBases = new Set<string>();
  for (const t of caseTechniques) {
    const b = baseTechniqueId(t);
    if (b) observedBases.add(b);
  }

  // Look up each matched group's FULL technique list by id (the hints carry only the overlap subset).
  const groupById = new Map<string, AdversaryGroup>();
  for (const g of groups) groupById.set(g.id.trim().toUpperCase(), g);

  // Tally: technique id → the matched groups that use it (deduped per group, so support counts
  // distinct GROUPS, not repeated occurrences within one group's list).
  const support = new Map<string, Map<string, string>>(); // techId → (groupId → groupName)
  for (const h of hints) {
    const g = groupById.get(h.id.trim().toUpperCase());
    if (!g) continue; // a hint with no backing group record (defensive) contributes nothing
    const seenInGroup = new Set<string>();
    for (const raw of g.techniques) {
      const id = normalizeTechniqueId(raw);
      if (!id) continue;
      const b = baseTechniqueId(id);
      if (!b || observedBases.has(b)) continue; // already observed at base → not new hunting ground
      if (seenInGroup.has(id)) continue;
      seenInGroup.add(id);
      let m = support.get(id);
      if (!m) {
        m = new Map();
        support.set(id, m);
      }
      m.set(g.id, g.name);
    }
  }

  const out: NextTechnique[] = [];
  for (const [id, groupMap] of support) {
    const groupList = [...groupMap.entries()]
      .map(([gid, name]) => ({ id: gid, name }))
      .sort((a, b) => a.id.localeCompare(b.id));
    out.push({
      id,
      url: attackTechniqueUrl(id),
      tactic: tacticForTechniques([id]) ?? UNSPECIFIED,
      groupCount: groupMap.size,
      groups: groupList,
    });
  }

  const rank = (t: string): number => (t in TACTIC_RANK ? TACTIC_RANK[t] : 99);
  out.sort(
    (a, b) =>
      b.groupCount - a.groupCount || // most-supported first (confidence)
      rank(a.tactic) - rank(b.tactic) || // then the worst plausible stage
      a.id.localeCompare(b.id), // deterministic
  );
  return out.slice(0, max);
}
