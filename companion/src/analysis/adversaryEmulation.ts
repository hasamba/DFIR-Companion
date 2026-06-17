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
// RANKING IS BY DISTINCTIVENESS, NOT POPULARITY. Ranking by raw support (how many matched groups use
// a technique) floats UBIQUITOUS techniques to the top — every group does recon (T1082) and obtains
// tooling (T1588.002), so "what everyone does" wins the count and the list is useless. Instead we
// score each candidate TF-IDF style:
//   score = support × idf,  idf = ln(N / globalCount)
// where support = how many of the M matched groups use it (consensus) and globalCount = how many of
// the N total groups use it (popularity). A technique many matched groups share but that is globally
// RARE scores high (distinctive to this actor profile); one everybody uses has idf≈0 and sinks. A
// hard prevalence cap (`maxPrevalence`) drops the truly ubiquitous outright so they never appear.
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

// Per-technique metadata from the bundled dataset (id → name + optional "where to look" data sources).
// `dataSources` is populated only when the ATT&CK release still ships the data-component model (the
// legacy fields were reworked into "detection strategies" in ATT&CK v17), so treat it as optional.
export interface TechniqueInfo {
  name?: string; // human-readable technique name, e.g. "Screen Capture"
  dataSources?: string[]; // "Source: Component" hunt hints, e.g. ["Process: Process Creation"]
}
export type TechniqueInfoMap = Record<string, TechniqueInfo>;

// One predicted "next technique" — a technique the matched groups are known to use that the case has
// not observed (at base level), ranked by distinctiveness (consensus among matched groups × global
// rarity), with the support, prevalence and hunt focus needed to present it honestly.
export interface NextTechnique {
  id: string; // ATT&CK technique id at the granularity the group lists it (T1486, T1021.001)
  name?: string; // human-readable name from the dataset ("Screen Capture"), when available
  url: string | null; // attack.mitre.org technique page (null only for an unparseable id — defensive)
  tactic: string; // ATT&CK tactic name for hunt focus ("Impact"), or "Unspecified"
  groupCount: number; // how many of the matched groups are known to use it (support / consensus)
  groups: NextTechniqueGroup[]; // which matched groups use it (id + name), sorted by id
  prevalence: number; // fraction of ALL groups in the dataset that use it (0..1) — lower = rarer/more distinctive
  score: number; // distinctiveness rank key: support × ln(N / globalCount)
  dataSources?: string[]; // "where to look" hunt hints, when the dataset carries them
}

export const DEFAULT_MAX_NEXT_TECHNIQUES = 10;

// Drop a candidate whose global prevalence exceeds this — "everyone does it" is not a hunt priority.
// 0.33 ≈ used by more than a third of all known groups (recon, tooling acquisition, run-keys, …).
export const DEFAULT_MAX_NEXT_PREVALENCE = 0.33;

// The standing disclaimer, shared by every surface that renders next-technique suggestions.
export const ADVERSARY_EMULATION_CAVEAT =
  "Predictive hunt priorities from lookalike groups' tradecraft — hypothesis fuel, not attribution or a forecast.";

// Tie-break order: among equally-scored techniques, surface the worst plausible next stage first so
// the most damaging move the actor might make next is what the analyst sees at the top.
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

// PRE-COMPROMISE technique bases (ATT&CK Reconnaissance TA0043 + Resource Development TA0042). These
// happen on the adversary's own infrastructure (registering domains, harvesting OSINT, acquiring
// tooling), NOT on the victim's endpoints — so they are useless as endpoint HUNT priorities and are
// dropped from the emulation list even when distinctive. (Most are also caught by the prevalence cap;
// this guarantees the rarer ones, e.g. T1585/T1584, never surface as "hunt for this next".)
const NON_HUNTABLE_BASES: ReadonlySet<string> = new Set([
  // Reconnaissance
  "T1595", "T1592", "T1589", "T1590", "T1591", "T1598", "T1597", "T1596", "T1593", "T1594",
  // Resource Development
  "T1583", "T1586", "T1584", "T1587", "T1585", "T1588", "T1608", "T1650",
]);

// How many of the N total groups use each technique id (full granularity, deduped per group). This is
// the "document frequency" for the TF-IDF distinctiveness score — common tradecraft has a high count.
function globalTechniqueCounts(groups: readonly AdversaryGroup[]): Map<string, number> {
  const counts = new Map<string, number>();
  for (const g of groups) {
    const seen = new Set<string>();
    for (const raw of g.techniques) {
      const id = normalizeTechniqueId(raw);
      if (!id || seen.has(id)) continue;
      seen.add(id);
      counts.set(id, (counts.get(id) ?? 0) + 1);
    }
  }
  return counts;
}

// Given the case's observed techniques and the ranked group hints, suggest the matched groups'
// techniques the case has NOT yet observed (base-level), ranked by DISTINCTIVENESS (support × global
// rarity) with the truly ubiquitous dropped. Pure: the groups dataset supplies both each hint's FULL
// technique list (AdversaryHint carries only the overlap) and the global prevalence baseline.
export function suggestNextTechniques(
  caseTechniques: readonly string[],
  hints: readonly AdversaryHint[],
  groups: readonly AdversaryGroup[],
  opts: { maxTechniques?: number; maxPrevalence?: number; info?: TechniqueInfoMap } = {},
): NextTechnique[] {
  const max = Math.max(1, Math.floor(opts.maxTechniques ?? DEFAULT_MAX_NEXT_TECHNIQUES));
  const maxPrevalence = clamp01(opts.maxPrevalence ?? DEFAULT_MAX_NEXT_PREVALENCE);
  if (hints.length === 0) return [];

  const totalGroups = groups.length;
  if (totalGroups === 0) return [];
  const globalCounts = globalTechniqueCounts(groups);

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
      if (NON_HUNTABLE_BASES.has(b)) continue; // pre-compromise (recon / resource dev) → not endpoint-huntable
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
    const globalCount = globalCounts.get(id) ?? groupMap.size; // ≥ support (matched groups ⊆ all groups)
    const prevalence = globalCount / totalGroups;
    if (prevalence > maxPrevalence) continue; // ubiquitous tradecraft is not a hunt priority — drop it
    const supportCount = groupMap.size;
    const idf = Math.log(totalGroups / globalCount); // distinctiveness: rarer globally → larger
    const groupList = [...groupMap.entries()]
      .map(([gid, name]) => ({ id: gid, name }))
      .sort((a, b) => a.id.localeCompare(b.id));
    const info = opts.info?.[id];
    out.push({
      id,
      name: info?.name || undefined, // drop empty-string names so the UI cleanly falls back to the id
      url: attackTechniqueUrl(id),
      tactic: tacticForTechniques([id]) ?? UNSPECIFIED,
      groupCount: supportCount,
      groups: groupList,
      prevalence,
      score: supportCount * idf,
      dataSources: info?.dataSources?.length ? info.dataSources : undefined,
    });
  }

  const rank = (t: string): number => (t in TACTIC_RANK ? TACTIC_RANK[t] : 99);
  out.sort(
    (a, b) =>
      b.score - a.score || // distinctiveness: consensus × global rarity
      b.groupCount - a.groupCount || // then breadth of agreement among matched groups
      a.prevalence - b.prevalence || // then the rarer (more distinctive) technique
      rank(a.tactic) - rank(b.tactic) || // then the worst plausible stage
      a.id.localeCompare(b.id), // deterministic
  );
  return out.slice(0, max);
}

function clamp01(n: number): number {
  if (!Number.isFinite(n)) return DEFAULT_MAX_NEXT_PREVALENCE;
  return Math.min(1, Math.max(0, n));
}
