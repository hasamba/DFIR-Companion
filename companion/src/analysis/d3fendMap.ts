// MITRE D3FEND defensive-countermeasure mapping — offline "how do I defend against this?" lookup
// (issue #178).
//
// Synthesis tells the analyst WHICH ATT&CK techniques a case used (offensive: "what the attacker
// did"). D3FEND is the defensive counterpart — it maps each ATT&CK technique to the countermeasures
// that harden against / detect / isolate it. Resolving the case's identified techniques against the
// bundled D3FEND mapping turns the incident's technique list into concrete hardening guidance for
// the defensive team, with NO AI call and NO runtime network (the mapping is a static, committed
// file regenerated offline by `npm run data:update-d3fend`).
//
// This module is PURE and OFFLINE: input is the case's techniques (via `collectCaseTechniques`,
// shared with adversary hints so both agree on what counts) + the bundled mapping; output is the
// per-technique countermeasures plus a defensive-tactic rollup. The dataset is loaded separately
// (d3fendData.ts) so this logic stays trivially testable.
//
// MATCHING is sub-technique aware and bidirectional. D3FEND maps most techniques at the sub-technique
// level (T1110.001) and some only at the base (T1059), so the resolver bridges both directions,
// deduped, to maximize recall without inventing mappings:
//   • a case SUB-technique (T1059.001) → its exact id AND its base T1059, and
//   • a case BASE technique (T1110, no sub) → its exact id AND every mapped sub-technique T1110.*
// This mirrors the base-credit idea in adversaryHints.ts: a coarsely-tagged case still surfaces the
// hardening guidance D3FEND lists for the technique family.
//
// CRUCIAL FRAMING: D3FEND's ATT&CK relationships are INFERRED (artifact-based), not an authoritative
// "fix". They are suggested countermeasures to consider — not a guarantee or a complete list — so
// every surface that renders them carries that note.

import type { InvestigationState } from "./stateTypes.js";
import { collectCaseTechniques, normalizeTechniqueId, baseTechniqueId } from "./adversaryHints.js";

// One D3FEND countermeasure as stored in the bundled dataset (no `url` — derived at resolve time to
// keep the file small).
export interface D3fendCountermeasure {
  id: string; // D3FEND technique id (URI fragment), e.g. "TokenBinding"
  name: string; // human label, e.g. "Token Binding"
  tactic: string; // D3FEND defensive tactic: Model | Harden | Detect | Isolate | Deceive | Evict | Restore
  category: string; // top-level D3FEND technique category, e.g. "Credential Hardening"
}

// A countermeasure enriched with its d3fend.mitre.org link + plain-English definition (what callers
// render — the definition powers the dashboard hover tooltip / the report's inline gloss).
export interface D3fendCountermeasureView extends D3fendCountermeasure {
  url: string;
  definition?: string; // plain-English "what this is", from the D3FEND ontology (absent if unmapped)
}

// All countermeasures mapped to one ATT&CK technique the case identified.
export interface D3fendTechniqueMatch {
  technique: string; // the case's ATT&CK technique id (full granularity), e.g. "T1059.001"
  countermeasures: D3fendCountermeasureView[];
}

// A countermeasure in the by-tactic rollup, carrying which of the case's techniques it addresses
// (so the "covers T1003, T1059…" coverage can render without re-deriving it client-side).
export interface D3fendTacticCountermeasure extends D3fendCountermeasureView {
  techniques: string[]; // the case's ATT&CK techniques this countermeasure covers (full matched set, sorted)
}

// A defensive-tactic rollup: every distinct countermeasure for the case, grouped by D3FEND tactic,
// each carrying the techniques it covers. This is the primary, action-first view (the dashboard
// renders it as a "Prevent / Detect / Contain" checklist).
export interface D3fendTacticGroup {
  tactic: string;
  countermeasures: D3fendTacticCountermeasure[];
}

// The full response a caller (route / report) returns.
export interface D3fendResult {
  d3fendVersion: string; // D3FEND ontology release the mapping came from
  datasetGenerated: string; // when the slim mapping was generated
  source: string; // dataset provenance string
  note: string; // the standing "suggested, not guaranteed" disclaimer
  mappedTechniqueCount: number; // techniques in the whole dataset (coverage context)
  countermeasureCount: number; // distinct countermeasures in the whole dataset
  caseTechniqueCount: number; // distinct techniques the case contributed
  coveredTechniqueCount: number; // of those, how many had ≥1 D3FEND countermeasure
  techniques: D3fendTechniqueMatch[]; // per case-technique that had a match, sorted by id
  byTactic: D3fendTacticGroup[]; // distinct countermeasures grouped by D3FEND tactic, lifecycle order
}

// The shape of a loaded dataset this builder needs — declared structurally so the pure module stays
// decoupled from the loader (d3fendData.ts) and the import stays one-directional.
export interface D3fendDatasetView {
  d3fendVersion: string;
  generated: string;
  source: string;
  note: string;
  countermeasureCount: number;
  map: Record<string, D3fendCountermeasure[]>; // ATT&CK technique id → countermeasures
  definitions?: Record<string, string>; // d3fend id → plain-English definition
}

export interface D3fendOptions {
  maxPerTechnique?: number; // cap on countermeasures shown per technique (default 12)
}

export const DEFAULT_MAX_PER_TECHNIQUE = 12;

// D3FEND's defensive lifecycle order — used to order both per-technique countermeasures and the
// tactic rollup so every surface reads Model → Harden → Detect → Isolate → Deceive → Evict → Restore.
export const D3FEND_TACTIC_ORDER = ["Model", "Harden", "Detect", "Isolate", "Deceive", "Evict", "Restore"];

// The standing disclaimer, shared by every surface that renders countermeasures (issue #178).
export const D3FEND_NOTE = "Suggested D3FEND countermeasures inferred from ATT&CK technique — review for fit, not a complete or guaranteed list.";

// Which lifecycle band a D3FEND tactic belongs to, so the UI can separate "the hardening you
// implement now" from "things you do while responding to THIS incident" and "prerequisite context".
//   harden  — proactive hardening to do now (Prevent / Detect / Contain)
//   respond — actions taken during this incident's response (Evict / Restore)
//   context — prerequisite hygiene or advanced/optional (Model / Deceive)
export type D3fendTier = "harden" | "respond" | "context";

// Plain-language action label + meaning + a concrete "what to do" line + lifecycle tier for each
// D3FEND tactic, so the analyst-facing surfaces (dashboard checklist + report) don't lean on raw
// D3FEND jargon and make clear WHERE the actual hardening is. Shared so both agree.
export interface D3fendActionInfo {
  label: string; // imperative action name, e.g. "Prevent"
  blurb: string; // one-line meaning, e.g. "stop it happening again"
  guidance: string; // concrete "what you do" the analyst can act on
  tier: D3fendTier;
}
export const D3FEND_ACTION_INFO: Record<string, D3fendActionInfo> = {
  Harden: {
    label: "Prevent",
    blurb: "stop it happening again",
    guidance: "Apply the config / credential / patch change that removes the weakness the attacker used (e.g. enable MFA, disable the abused feature, restrict permissions).",
    tier: "harden",
  },
  Detect: {
    label: "Detect",
    blurb: "spot it if it recurs",
    guidance: "Make sure logging or an EDR/SIEM rule will catch this behaviour next time, then verify the alert fires.",
    tier: "harden",
  },
  Isolate: {
    label: "Contain",
    blurb: "limit the blast radius",
    guidance: "Segment the network, sandbox the app, or tighten privileges so this technique can't spread.",
    tier: "harden",
  },
  Evict: {
    label: "Evict",
    blurb: "remove the attacker's foothold",
    guidance: "Do this during THIS incident: kill the malicious processes, delete persistence, reset compromised credentials.",
    tier: "respond",
  },
  Restore: {
    label: "Restore",
    blurb: "recover affected systems",
    guidance: "Do this during THIS incident: restore affected data, configs, and accounts from a known-good state.",
    tier: "respond",
  },
  Model: {
    label: "Model",
    blurb: "know your attack surface",
    guidance: "Prerequisite hygiene, not a fix: keep asset/data/account inventories so you can find and scope what's affected.",
    tier: "context",
  },
  Deceive: {
    label: "Deceive",
    blurb: "lure and mislead the attacker",
    guidance: "Optional / advanced: deploy decoys or honeytokens to detect and study intruders — only if your program is mature.",
    tier: "context",
  },
};
// The action label for a D3FEND tactic, falling back to the raw tactic for any future/unknown one.
export function d3fendActionLabel(tactic: string): string {
  return D3FEND_ACTION_INFO[tactic]?.label ?? tactic;
}

const tacticRank = (t: string): number => {
  const i = D3FEND_TACTIC_ORDER.indexOf(t);
  return i === -1 ? D3FEND_TACTIC_ORDER.length : i;
};

// The d3fend.mitre.org page for a countermeasure id (e.g. "TokenBinding" → …/technique/d3f:TokenBinding/).
export function d3fendTechniqueUrl(id: string): string {
  return `https://d3fend.mitre.org/technique/d3f:${id.trim()}/`;
}

// Sort countermeasures by D3FEND lifecycle tactic, then name (stable, deterministic).
function sortCountermeasures<T extends D3fendCountermeasure>(cms: T[]): T[] {
  return [...cms].sort((a, b) => tacticRank(a.tactic) - tacticRank(b.tactic) || a.name.localeCompare(b.name));
}

// Gather the countermeasures mapped to one case technique, deduped by D3FEND id — bidirectionally:
// a sub-technique also pulls in its base's countermeasures, and a base technique also pulls in every
// mapped sub-technique's (D3FEND maps most techniques only at one granularity, so we bridge both).
function lookupTechnique(technique: string, map: Record<string, D3fendCountermeasure[]>): D3fendCountermeasure[] {
  const seen = new Set<string>();
  const out: D3fendCountermeasure[] = [];
  const add = (cms: D3fendCountermeasure[] | undefined): void => {
    if (!cms) return;
    for (const cm of cms) {
      if (!cm || typeof cm.id !== "string" || seen.has(cm.id)) continue;
      seen.add(cm.id);
      out.push(cm);
    }
  };
  add(map[technique]); // exact id (e.g. T1059.001 or T1110)
  const base = baseTechniqueId(technique);
  if (base && base !== technique) {
    add(map[base]); // sub-technique → its base (T1059.001 → T1059)
  } else if (base) {
    // base technique → every mapped sub-technique of it (T1110 → T1110.001, T1110.002, …)
    const prefix = `${base}.`;
    for (const key of Object.keys(map)) if (key.startsWith(prefix)) add(map[key]);
  }
  return out;
}

// End-to-end: collect the case's techniques, resolve each against the D3FEND mapping, and wrap the
// result with provenance + the note. Shared by the /d3fend-countermeasures route and the report
// renderer so both present identical numbers and wording. Pure (the dataset + options are passed in).
export function buildD3fendResult(
  state: InvestigationState,
  dataset: D3fendDatasetView,
  opts: D3fendOptions = {},
): D3fendResult {
  const maxPerTechnique = Math.max(1, Math.floor(opts.maxPerTechnique ?? DEFAULT_MAX_PER_TECHNIQUE));
  const map = dataset.map ?? {};
  const defs = dataset.definitions ?? {};
  const caseTechniques = collectCaseTechniques(state); // full-granularity, deduped, sorted

  // Enrich a raw countermeasure with its d3fend URL + plain-English definition (omitted when absent).
  const viewOf = (cm: D3fendCountermeasure): D3fendCountermeasureView => {
    const def = defs[cm.id];
    return def ? { ...cm, url: d3fendTechniqueUrl(cm.id), definition: def } : { ...cm, url: d3fendTechniqueUrl(cm.id) };
  };

  const techniques: D3fendTechniqueMatch[] = [];
  const tacticBuckets = new Map<string, Map<string, D3fendTacticCountermeasure>>(); // tactic → (id → cm + coverage)

  for (const raw of caseTechniques) {
    const technique = normalizeTechniqueId(raw);
    if (!technique) continue;
    const matched = sortCountermeasures(lookupTechnique(technique, map));
    if (matched.length === 0) continue;

    const views: D3fendCountermeasureView[] = matched.slice(0, maxPerTechnique).map(viewOf);
    techniques.push({ technique, countermeasures: views });

    // Roll the FULL matched set (not just the per-technique cap) into the tactic groups, deduped —
    // the rollup is the case-wide defensive picture, so a countermeasure trimmed off one technique's
    // list still counts if another technique surfaces it. Accumulate the techniques each one covers.
    for (const cm of matched) {
      let bucket = tacticBuckets.get(cm.tactic);
      if (!bucket) {
        bucket = new Map<string, D3fendTacticCountermeasure>();
        tacticBuckets.set(cm.tactic, bucket);
      }
      const entry = bucket.get(cm.id);
      if (entry) entry.techniques.push(technique);
      else bucket.set(cm.id, { ...viewOf(cm), techniques: [technique] });
    }
  }

  // Within a tactic, order by coverage (a countermeasure that defends more of the case's techniques
  // is the higher-leverage action) then name; each one's covered techniques sorted for stable output.
  const byTactic: D3fendTacticGroup[] = [...tacticBuckets.entries()]
    .map(([tactic, byId]) => {
      const countermeasures = [...byId.values()]
        .map((cm) => ({ ...cm, techniques: [...cm.techniques].sort() }))
        .sort((a, b) => b.techniques.length - a.techniques.length || a.name.localeCompare(b.name));
      return { tactic, countermeasures };
    })
    .sort((a, b) => tacticRank(a.tactic) - tacticRank(b.tactic) || a.tactic.localeCompare(b.tactic));

  return {
    d3fendVersion: dataset.d3fendVersion || "unknown",
    datasetGenerated: dataset.generated || "",
    source: dataset.source || "",
    note: D3FEND_NOTE,
    mappedTechniqueCount: Object.keys(map).length,
    countermeasureCount: dataset.countermeasureCount || 0,
    caseTechniqueCount: caseTechniques.length,
    coveredTechniqueCount: techniques.length,
    techniques,
    byTactic,
  };
}
