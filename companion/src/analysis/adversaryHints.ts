// Adversary group hints — offline "who typically uses these techniques?" scoring (issue #46).
//
// Synthesis tells the analyst WHICH ATT&CK techniques a case used, but not WHICH known actor
// groups favour that same combination. The MITRE ATT&CK Groups dataset attributes a technique set
// to each named group; scoring the overlap between the case's techniques and every group surfaces
// hypothesis fuel early — before any threat-intel enrichment has run.
//
// This module is PURE and OFFLINE: input is the case's technique ids (string[]) + the bundled
// groups dataset, output is the ranked group matches. No AI call, no network, no I/O — the dataset
// is loaded separately (adversaryGroupsData.ts) so this logic stays trivially testable.
//
// MATCHING IS HYBRID (sub-technique aware). Both the case and the dataset carry technique ids at
// full granularity (T1059.001), so a match is scored at the finest level both sides share:
//   • EXACT  — same full id (case T1059.001 ∧ group T1059.001): a strong, discriminating signal.
//   • BASE   — only the base technique matches (case T1059.001 vs group T1059.003, or a case tagged
//              at the bare T1059): partial credit, since "both use a command interpreter" is weak.
// This keeps recall (a case tagged coarsely still matches at base) while rewarding precise agreement
// so a focused actor rises above one that merely shares the broad technique.
//
// CRUCIAL FRAMING: this is statistical technique-overlap similarity, NOT attribution. A group that
// uses 150 techniques overlaps with almost any case; the output therefore carries the group's total
// technique count so the analyst can weigh "4 of 12" (focused) against "4 of 150" (diffuse), and
// every surface that renders these hints must show the "not attribution" caveat.

import type { InvestigationState } from "./stateTypes.js";
import { suggestNextTechniques, type NextTechnique } from "./adversaryEmulation.js";

// One adversary group's slimmed record from the bundled dataset. `techniques` carries ATT&CK ids at
// full granularity — sub-technique (T1059.001) where MITRE maps it, base (T1486) otherwise.
export interface AdversaryGroup {
  id: string; // ATT&CK group id, e.g. "G0016"
  name: string; // e.g. "APT29"
  aliases: string[]; // other names, e.g. ["Cozy Bear", "The Dukes"]
  description: string; // short attribution/sector context
  techniques: string[]; // technique ids (sub-technique where mapped), e.g. ["T1059.001", "T1486"]
}

// A ranked match: a group whose technique set overlaps the case's by at least `minOverlap` (counted
// at base-or-better), ordered by a weighted score that rewards exact sub-technique agreement.
export interface AdversaryHint {
  id: string;
  name: string;
  aliases: string[];
  description: string;
  url: string; // attack.mitre.org group page
  overlapCount: number; // distinct case techniques the group shares at base-or-better (breadth)
  exactCount: number; // of those, EXACT (same sub-technique / id) matches — the strong signal
  overlapTechniques: string[]; // all matched case technique ids (full granularity), sorted
  exactTechniques: string[]; // the subset matched exactly (full-id equality), sorted
  groupTechniqueCount: number; // distinct techniques attributed to the group (context for the ratio)
  score: number; // weighted: exactCount + BASE_MATCH_WEIGHT × (overlapCount − exactCount)
}

export interface AdversaryHintOptions {
  minOverlap?: number; // minimum overlapping techniques (base-or-better) to surface a group (default 3)
  topN?: number; // cap on how many ranked groups to return (default 5)
  maxNextTechniques?: number; // cap on emulation "next technique" suggestions (default 10, issue #121)
  maxNextPrevalence?: number; // drop emulation suggestions used by > this fraction of all groups (default 0.33, #121)
}

// The full response a caller (route / report) returns: the ranked hints plus the provenance and
// caveat needed to present them honestly.
export interface AdversaryHintsResult {
  attackVersion: string; // ATT&CK release the dataset came from
  datasetGenerated: string; // when the slim dataset was generated
  groupCount: number; // groups considered (whole dataset)
  caseTechniqueCount: number; // distinct techniques the case contributed (full granularity)
  minOverlap: number; // threshold applied
  caveat: string; // the standing "not attribution" disclaimer
  hints: AdversaryHint[];
  // Adversary emulation (#121): techniques the matched groups are known to use that the case has NOT
  // yet observed — predictive hunt priorities, ranked by how many matched groups use each.
  nextTechniques: NextTechnique[];
}

export const DEFAULT_MIN_OVERLAP = 3;
export const DEFAULT_TOP_N = 5;

// Credit for a match that agrees only at the base technique, not the exact sub-technique. Half of an
// exact match: enough to keep coarse-but-real overlaps ranked, not enough to outweigh precise ones.
export const BASE_MATCH_WEIGHT = 0.5;

// One wording for the disclaimer, shared by every surface that renders hints (issue #46).
export const ADVERSARY_HINTS_CAVEAT =
  "Statistical similarity based on technique overlap — not attribution.";

const TECHNIQUE_RE = /^T(\d{4})(?:\.(\d{3}))?$/; // technique or sub-technique id

// Normalize a technique id to its full, validated form, KEEPING the sub-technique:
// "t1059.001" → "T1059.001", "T1486" → "T1486". Null when it isn't a valid technique id.
export function normalizeTechniqueId(raw: string): string | null {
  const m = TECHNIQUE_RE.exec(raw.trim().toUpperCase());
  if (!m) return null;
  return m[2] ? `T${m[1]}.${m[2]}` : `T${m[1]}`;
}

// The BASE technique of an id ("T1059.001" → "T1059", "T1486" → "T1486"), or null when invalid.
// Used to award partial credit when the case and a group share a technique but differ on the sub.
export function baseTechniqueId(raw: string): string | null {
  const m = TECHNIQUE_RE.exec(raw.trim().toUpperCase());
  return m ? `T${m[1]}` : null;
}

// The ATT&CK group page for a group id (e.g. "G0016" → https://attack.mitre.org/groups/G0016/).
export function adversaryGroupUrl(id: string): string {
  return `https://attack.mitre.org/groups/${id.trim().toUpperCase()}/`;
}

// The distinct set of techniques a case has identified (full granularity), drawn from every place
// techniques live in the state: findings, forensic events, and the synthesized MITRE table. Sorted,
// deduped. Sub-techniques are preserved so the scorer can reward exact agreement.
export function collectCaseTechniques(state: InvestigationState): string[] {
  const set = new Set<string>();
  const add = (raw: string): void => {
    const id = normalizeTechniqueId(raw);
    if (id) set.add(id);
  };
  for (const f of state.findings) for (const t of f.mitreTechniques) add(t);
  for (const e of state.forensicTimeline) for (const t of e.mitreTechniques) add(t);
  for (const t of state.mitreTechniques) add(t.id);
  return [...set].sort();
}

// Score each group's technique overlap with the case (hybrid: exact sub-technique + base credit) and
// return the top matches, ranked. A group must share at least `minOverlap` techniques at base-or-
// better to surface (preserves recall); among those, ranking is by the WEIGHTED score (exact matches
// count full, base-only count half), then by breadth, then by the specificity ratio (a focused group
// outranks a sprawling one), then by id for deterministic output.
export function rankAdversaryGroups(
  caseTechniques: readonly string[],
  groups: readonly AdversaryGroup[],
  opts: AdversaryHintOptions = {},
): AdversaryHint[] {
  const minOverlap = Math.max(1, Math.floor(opts.minOverlap ?? DEFAULT_MIN_OVERLAP));
  const topN = Math.max(1, Math.floor(opts.topN ?? DEFAULT_TOP_N));

  // The case's techniques at full granularity (exact-match candidates).
  const caseFull = new Set<string>();
  for (const t of caseTechniques) {
    const id = normalizeTechniqueId(t);
    if (id) caseFull.add(id);
  }
  if (caseFull.size === 0) return [];

  const hints: AdversaryHint[] = [];
  for (const g of groups) {
    // Index the group at both granularities: full ids for exact matches, bases for partial credit.
    const groupFull = new Set<string>();
    const groupBases = new Set<string>();
    for (const t of g.techniques) {
      const id = normalizeTechniqueId(t);
      if (!id) continue;
      groupFull.add(id);
      const b = baseTechniqueId(id);
      if (b) groupBases.add(b);
    }
    if (groupFull.size === 0) continue;

    const exact: string[] = [];
    const partial: string[] = [];
    for (const c of caseFull) {
      if (groupFull.has(c)) {
        exact.push(c); // same full id — strong, sub-technique-level agreement
      } else {
        const b = baseTechniqueId(c);
        if (b && groupBases.has(b)) partial.push(c); // same base technique, different/unspecified sub
      }
    }
    const overlapCount = exact.length + partial.length;
    if (overlapCount < minOverlap) continue;
    hints.push({
      id: g.id,
      name: g.name,
      aliases: g.aliases,
      description: g.description,
      url: adversaryGroupUrl(g.id),
      overlapCount,
      exactCount: exact.length,
      exactTechniques: [...exact].sort(),
      overlapTechniques: [...exact, ...partial].sort(),
      groupTechniqueCount: groupFull.size,
      score: exact.length + BASE_MATCH_WEIGHT * partial.length,
    });
  }

  // Specificity ratio for tie-breaks (guarded against a hand-edited group with no techniques).
  const ratio = (h: AdversaryHint): number => (h.groupTechniqueCount > 0 ? h.overlapCount / h.groupTechniqueCount : 0);
  hints.sort(
    (a, b) =>
      b.score - a.score || // weighted: exact agreement wins
      b.overlapCount - a.overlapCount || // then breadth
      ratio(b) - ratio(a) || // then focus
      a.id.localeCompare(b.id),
  );
  return hints.slice(0, topN);
}

// The shape of a loaded dataset this builder needs — declared structurally so the pure module
// stays decoupled from the loader (adversaryGroupsData.ts) and the import stays one-directional.
interface DatasetView {
  attackVersion: string;
  generated: string;
  groupCount: number;
  groups: AdversaryGroup[];
}

// End-to-end: collect the case's techniques, rank the dataset's groups, and wrap the result with
// provenance + the caveat. Shared by the /adversary-hints route and the report renderer so both
// present identical numbers and wording. Pure (the dataset + options are passed in).
export function buildAdversaryHintsResult(
  state: InvestigationState,
  dataset: DatasetView,
  opts: AdversaryHintOptions = {},
): AdversaryHintsResult {
  const minOverlap = Math.max(1, Math.floor(opts.minOverlap ?? DEFAULT_MIN_OVERLAP));
  const caseTechniques = collectCaseTechniques(state);
  const hints = rankAdversaryGroups(caseTechniques, dataset.groups, { ...opts, minOverlap });
  // Emulation: from those same matched groups, surface the techniques the case hasn't observed yet —
  // predictive hunt priorities (#121). Empty when no group matched (nothing to emulate).
  const nextTechniques = suggestNextTechniques(caseTechniques, hints, dataset.groups, {
    maxTechniques: opts.maxNextTechniques,
    maxPrevalence: opts.maxNextPrevalence,
  });
  return {
    attackVersion: dataset.attackVersion,
    datasetGenerated: dataset.generated,
    groupCount: dataset.groupCount,
    caseTechniqueCount: caseTechniques.length,
    minOverlap,
    caveat: ADVERSARY_HINTS_CAVEAT,
    hints,
    nextTechniques,
  };
}
