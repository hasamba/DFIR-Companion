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
// CRUCIAL FRAMING: this is statistical technique-overlap similarity, NOT attribution. A group that
// uses 150 techniques overlaps with almost any case; the output therefore carries the group's total
// technique count so the analyst can weigh "4 of 12" (focused) against "4 of 150" (diffuse), and
// every surface that renders these hints must show the "not attribution" caveat.

import type { InvestigationState } from "./stateTypes.js";

// One adversary group's slimmed record (group → base techniques) from the bundled dataset.
export interface AdversaryGroup {
  id: string; // ATT&CK group id, e.g. "G0016"
  name: string; // e.g. "APT29"
  aliases: string[]; // other names, e.g. ["Cozy Bear", "The Dukes"]
  description: string; // short attribution/sector context
  techniques: string[]; // base technique ids attributed to the group, e.g. ["T1059", "T1566"]
}

// A ranked match: a group whose technique set overlaps the case's by at least `minOverlap`.
export interface AdversaryHint {
  id: string;
  name: string;
  aliases: string[];
  description: string;
  url: string; // attack.mitre.org group page
  overlapCount: number; // how many case techniques this group also uses (the headline score)
  overlapTechniques: string[]; // the specific overlapping base technique ids, sorted
  groupTechniqueCount: number; // total techniques attributed to the group (context for the ratio)
  score: number; // = overlapCount; kept as a distinct field for forward-compat weighting
}

export interface AdversaryHintOptions {
  minOverlap?: number; // minimum overlapping techniques to surface a group (default 3)
  topN?: number; // cap on how many ranked groups to return (default 5)
}

// The full response a caller (route / report) returns: the ranked hints plus the provenance and
// caveat needed to present them honestly.
export interface AdversaryHintsResult {
  attackVersion: string; // ATT&CK release the dataset came from
  datasetGenerated: string; // when the slim dataset was generated
  groupCount: number; // groups considered (whole dataset)
  caseTechniqueCount: number; // distinct base techniques the case contributed
  minOverlap: number; // threshold applied
  caveat: string; // the standing "not attribution" disclaimer
  hints: AdversaryHint[];
}

export const DEFAULT_MIN_OVERLAP = 3;
export const DEFAULT_TOP_N = 5;

// One wording for the disclaimer, shared by every surface that renders hints (issue #46).
export const ADVERSARY_HINTS_CAVEAT =
  "Statistical similarity based on technique overlap — not attribution.";

const TECHNIQUE_RE = /^T(\d{4})(?:\.\d{3})?$/; // technique or sub-technique id

// Normalize a technique id to its BASE form ("t1059.001" → "T1059"), or null when it isn't a valid
// technique id. Both sides of the overlap are normalized to base so a case's T1059.001 (PowerShell)
// still matches a group's T1059.003 (cmd) — the right granularity for a hypothesis-level hint.
export function normalizeTechniqueId(raw: string): string | null {
  const m = TECHNIQUE_RE.exec(raw.trim().toUpperCase());
  return m ? `T${m[1]}` : null;
}

// The ATT&CK group page for a group id (e.g. "G0016" → https://attack.mitre.org/groups/G0016/).
export function adversaryGroupUrl(id: string): string {
  return `https://attack.mitre.org/groups/${id.trim().toUpperCase()}/`;
}

// The distinct set of BASE techniques a case has identified, drawn from every place techniques
// live in the state: findings, forensic events, and the synthesized MITRE table. Sorted, deduped.
export function collectCaseTechniques(state: InvestigationState): string[] {
  const set = new Set<string>();
  const add = (raw: string): void => {
    const base = normalizeTechniqueId(raw);
    if (base) set.add(base);
  };
  for (const f of state.findings) for (const t of f.mitreTechniques) add(t);
  for (const e of state.forensicTimeline) for (const t of e.mitreTechniques) add(t);
  for (const t of state.mitreTechniques) add(t.id);
  return [...set].sort();
}

// Score each group's technique overlap with the case and return the top matches, ranked.
// Ranking: most overlapping techniques first; ties broken by the more SPECIFIC match (higher
// overlap ÷ group-size ratio, so a focused group outranks a sprawling one at equal overlap),
// then by group id for deterministic output. Groups below `minOverlap` are dropped entirely.
export function rankAdversaryGroups(
  caseTechniques: readonly string[],
  groups: readonly AdversaryGroup[],
  opts: AdversaryHintOptions = {},
): AdversaryHint[] {
  const minOverlap = Math.max(1, Math.floor(opts.minOverlap ?? DEFAULT_MIN_OVERLAP));
  const topN = Math.max(1, Math.floor(opts.topN ?? DEFAULT_TOP_N));

  const caseSet = new Set<string>();
  for (const t of caseTechniques) {
    const base = normalizeTechniqueId(t);
    if (base) caseSet.add(base);
  }
  if (caseSet.size === 0) return [];

  const hints: AdversaryHint[] = [];
  for (const g of groups) {
    // Dedupe the group's techniques to base while measuring overlap (defensive — the bundled
    // dataset is already base+deduped, but a hand-edited file shouldn't double-count).
    const groupBase = new Set<string>();
    const overlap = new Set<string>();
    for (const t of g.techniques) {
      const base = normalizeTechniqueId(t);
      if (!base) continue;
      groupBase.add(base);
      if (caseSet.has(base)) overlap.add(base);
    }
    if (overlap.size < minOverlap) continue;
    hints.push({
      id: g.id,
      name: g.name,
      aliases: g.aliases,
      description: g.description,
      url: adversaryGroupUrl(g.id),
      overlapCount: overlap.size,
      overlapTechniques: [...overlap].sort(),
      groupTechniqueCount: groupBase.size,
      score: overlap.size,
    });
  }

  // Specificity ratio for tie-breaks. groupTechniqueCount is always ≥ overlapCount ≥ 1 for a
  // pushed hint (overlap ⊆ the group's techniques), so this can't divide by zero — but guard
  // anyway so a hand-edited dataset can never produce a NaN that corrupts the sort order.
  const ratio = (h: AdversaryHint): number => (h.groupTechniqueCount > 0 ? h.overlapCount / h.groupTechniqueCount : 0);
  hints.sort(
    (a, b) => b.overlapCount - a.overlapCount || ratio(b) - ratio(a) || a.id.localeCompare(b.id),
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
  return {
    attackVersion: dataset.attackVersion,
    datasetGenerated: dataset.generated,
    groupCount: dataset.groupCount,
    caseTechniqueCount: caseTechniques.length,
    minOverlap,
    caveat: ADVERSARY_HINTS_CAVEAT,
    hints,
  };
}
