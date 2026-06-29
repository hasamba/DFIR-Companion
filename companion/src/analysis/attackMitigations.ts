// MITRE ATT&CK Mitigations — the CONCRETE, actionable "what to do" layer (issue #178).
//
// D3FEND (d3fendMap.ts) names defensive *techniques/sensors* but reads like a taxonomy, not a
// runbook. ATT&CK Mitigations (the M-code "courses of action") are the recommendations an analyst
// actually implements — and each technique↔mitigation link carries a technique-SPECIFIC detail
// ("On Windows 10 enable ASR rules to secure LSASS…"). Resolving the case's identified techniques
// against the bundled mapping turns the incident into a ranked list of real mitigations, with NO AI
// and NO runtime network (the mapping is a static, committed file from `npm run
// data:update-attack-mitigations`).
//
// This module is PURE and OFFLINE: input is the case's techniques (via the shared
// `collectCaseTechniques`) + the bundled mapping; output is a by-mitigation rollup RANKED BY
// COVERAGE (the highest-leverage actions first — "where to start") plus a per-technique breakdown.
//
// MATCHING is bidirectional + sub-technique-aware, mirroring d3fendMap: a case sub-technique pulls
// its base's mitigations and a base pulls every mapped sub-technique's, so a coarsely-tagged case
// still surfaces the technique family's mitigations.

import type { InvestigationState } from "./stateTypes.js";
import { collectCaseTechniques, normalizeTechniqueId, baseTechniqueId } from "./adversaryHints.js";

// One mitigation's metadata, as stored in the dataset's `mitigations` dict.
export interface AttackMitigation {
  id: string; // "M1043"
  name: string; // "Credential Access Protection"
  description: string; // general mitigation description
  url: string; // attack.mitre.org/mitigations/M1043
}

// A technique→mitigation link with the technique-specific detail (what callers render per technique).
export interface MitigationLink {
  id: string;
  name: string;
  url: string;
  detail: string; // how this mitigation applies to THIS technique
}

// All mitigations recommended for one ATT&CK technique the case identified.
export interface TechniqueMitigations {
  technique: string;
  mitigations: MitigationLink[];
}

// A by-mitigation rollup: one M-code, the case techniques it addresses (the leverage), ranked first.
export interface MitigationRollup {
  id: string;
  name: string;
  url: string;
  description: string;
  techniques: string[]; // case techniques this mitigation covers (sorted)
}

export interface MitigationsResult {
  attackVersion: string;
  datasetGenerated: string;
  source: string;
  note: string;
  mitigationCount: number; // mitigations in the whole dataset
  mappedTechniqueCount: number; // techniques in the whole dataset (coverage context)
  caseTechniqueCount: number; // distinct techniques the case contributed
  coveredTechniqueCount: number; // of those, how many had ≥1 mitigation
  byMitigation: MitigationRollup[]; // PRIMARY: ranked by how many case techniques each addresses
  techniques: TechniqueMitigations[]; // per case-technique that had a match, sorted by id
}

// One stored technique→mitigation link from the dataset map.
export interface MitigationMapLink {
  id: string;
  detail: string;
}

// The dataset shape this builder needs — declared structurally so the pure module stays decoupled
// from the loader (attackMitigationsData.ts).
export interface MitigationsDatasetView {
  attackVersion: string;
  generated: string;
  source: string;
  note: string;
  mitigationCount: number;
  mitigations: Record<string, AttackMitigation>;
  map: Record<string, MitigationMapLink[]>;
}

export const ATTACK_MITIGATIONS_NOTE =
  "Concrete defensive mitigations MITRE ATT&CK recommends for the case's techniques — review for fit before applying.";

// Gather a technique's mitigation links bidirectionally (exact id + base + mapped sub-techniques),
// deduped by M-code (keeping the first/most-specific detail seen).
function lookupTechnique(technique: string, map: Record<string, MitigationMapLink[]>): MitigationMapLink[] {
  const seen = new Set<string>();
  const out: MitigationMapLink[] = [];
  const add = (links: MitigationMapLink[] | undefined): void => {
    if (!links) return;
    for (const l of links) {
      if (!l || typeof l.id !== "string" || seen.has(l.id)) continue;
      seen.add(l.id);
      out.push(l);
    }
  };
  add(map[technique]); // exact id (T1003.001 or T1003)
  const base = baseTechniqueId(technique);
  if (base && base !== technique) {
    add(map[base]); // sub-technique → its base
  } else if (base) {
    const prefix = `${base}.`;
    for (const key of Object.keys(map)) if (key.startsWith(prefix)) add(map[key]); // base → its sub-techniques
  }
  return out;
}

// End-to-end: collect the case's techniques, resolve them against the ATT&CK Mitigations mapping, and
// wrap with provenance + note. Shared by the route and the report so both agree. Pure.
export function buildMitigationsResult(state: InvestigationState, dataset: MitigationsDatasetView): MitigationsResult {
  const map = dataset.map ?? {};
  const dict = dataset.mitigations ?? {};
  const caseTechniques = collectCaseTechniques(state);

  const techniques: TechniqueMitigations[] = [];
  const coverage = new Map<string, Set<string>>(); // M-code → set of case techniques it covers

  for (const raw of caseTechniques) {
    const technique = normalizeTechniqueId(raw);
    if (!technique) continue;
    const links = lookupTechnique(technique, map);
    if (links.length === 0) continue;

    const mitigations: MitigationLink[] = links
      .map((l) => {
        const m = dict[l.id];
        if (!m) return null;
        return { id: m.id, name: m.name, url: m.url, detail: l.detail || m.description };
      })
      .filter((m): m is MitigationLink => m !== null)
      .sort((a, b) => a.id.localeCompare(b.id));
    if (mitigations.length === 0) continue;
    techniques.push({ technique, mitigations });

    for (const m of mitigations) {
      let set = coverage.get(m.id);
      if (!set) {
        set = new Set<string>();
        coverage.set(m.id, set);
      }
      set.add(technique);
    }
  }

  // By-mitigation rollup, ranked by coverage (most case techniques first) — the highest-leverage
  // actions to take, then by id for determinism.
  const byMitigation: MitigationRollup[] = [...coverage.entries()]
    .map(([id, techs]) => {
      const m = dict[id];
      return {
        id,
        name: m?.name ?? id,
        url: m?.url ?? "",
        description: m?.description ?? "",
        techniques: [...techs].sort(),
      };
    })
    .sort((a, b) => b.techniques.length - a.techniques.length || a.id.localeCompare(b.id));

  return {
    attackVersion: dataset.attackVersion || "unknown",
    datasetGenerated: dataset.generated || "",
    source: dataset.source || "",
    note: ATTACK_MITIGATIONS_NOTE,
    mitigationCount: Object.keys(dict).length,
    mappedTechniqueCount: Object.keys(map).length,
    caseTechniqueCount: caseTechniques.length,
    coveredTechniqueCount: techniques.length,
    byMitigation,
    techniques,
  };
}
