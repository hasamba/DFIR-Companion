import type { InvestigationState, Severity } from "../analysis/stateTypes.js";

// Build a MITRE ATT&CK Navigator layer (https://mitre-attack.github.io/attack-navigator/) from
// the case state — a deterministic transform, no AI. The layer JSON drops straight into the
// Navigator's "Open Existing Layer → Upload from local" and renders the case's techniques on the
// matrix, colored by severity. This is the artifact analysts paste into every client deck.
//
// Color/score come from the WORST severity any finding or forensic event assigns to a technique;
// the comment lists the supporting finding titles (+ a forensic-event count). Sub-technique
// scores are only visible in the Navigator when their parent is expanded, so we add a neutral
// parent entry with `showSubtechniques: true` for every sub-technique present.

// Navigator layer schema (https://github.com/mitre-attack/attack-navigator/blob/master/layers/LAYERFORMATv4_5.md).
// We emit the subset the Navigator reads; unknown fields are ignored, missing ones default.
export interface NavigatorTechnique {
  techniqueID: string;
  score?: number;
  color?: string;
  comment?: string;
  enabled: boolean;
  showSubtechniques?: boolean;
  metadata?: Array<{ name: string; value: string }>;
}

export interface NavigatorLayer {
  name: string;
  versions: { attack: string; navigator: string; layer: string };
  domain: "enterprise-attack";
  description: string;
  techniques: NavigatorTechnique[];
  gradient: { colors: string[]; minValue: number; maxValue: number };
  legendItems: Array<{ label: string; color: string }>;
  sorting: number;
  hideDisabled: boolean;
  showTacticRowBackground: boolean;
  tacticRowBackground: string;
  selectTechniquesAcrossTactics: boolean;
  selectSubtechniquesWithParent: boolean;
}

// Severity → Navigator cell color (vivid, distinct, legible against the Navigator's white text).
const SEVERITY_COLOR: Record<Severity, string> = {
  Critical: "#b30000",
  High: "#e8590c",
  Medium: "#f1c40f",
  Low: "#2e86de",
  Info: "#7f8c8d",
};

// Heatmap score so the layer is still meaningful if the analyst switches to gradient coloring.
const SEVERITY_SCORE: Record<Severity, number> = {
  Critical: 100, High: 75, Medium: 50, Low: 25, Info: 10,
};

// Worst-wins ordering (higher = worse) when several findings/events touch the same technique.
const SEVERITY_RANK: Record<Severity, number> = {
  Critical: 5, High: 4, Medium: 3, Low: 2, Info: 1,
};

const SEVERITIES: Severity[] = ["Critical", "High", "Medium", "Low", "Info"];

// A technique ("T1059") or sub-technique ("T1059.001") id, anchored so a tactic id (TA0001) or
// free-text technique name never slips into the layer.
const TECHNIQUE_RE = /^T\d{4}(?:\.\d{3})?$/;

function normalizeTechnique(id: string): string | null {
  const t = id.trim().toUpperCase();
  return TECHNIQUE_RE.test(t) ? t : null;
}

function worse(a: Severity, b: Severity): Severity {
  return SEVERITY_RANK[a] >= SEVERITY_RANK[b] ? a : b;
}

// Parent technique id of a sub-technique ("T1059.001" → "T1059"), or null for a base technique.
function parentTechnique(id: string): string | null {
  const dot = id.indexOf(".");
  return dot > 0 ? id.slice(0, dot) : null;
}

interface TechniqueAcc {
  worst: Severity;
  findingTitles: string[];   // de-duped, insertion order preserved for a stable comment
  eventCount: number;
}

function commentFor(acc: TechniqueAcc): string {
  const parts: string[] = [];
  if (acc.findingTitles.length > 0) {
    const shown = acc.findingTitles.slice(0, 3).join("; ");
    parts.push(acc.findingTitles.length > 3 ? `${shown} (+${acc.findingTitles.length - 3} more)` : shown);
  }
  if (acc.eventCount > 0) {
    parts.push(`${acc.eventCount} forensic event${acc.eventCount === 1 ? "" : "s"}`);
  }
  return parts.join(" • ");
}

export interface AttackLayerOptions {
  name?: string;             // layer name shown in the Navigator tab (default derived from the case id)
  attackVersion?: string;    // informational ATT&CK version tag (default "16")
}

/**
 * Build an ATT&CK Navigator layer from the investigation state. Pure — depends only on its
 * arguments. Merges techniques from findings (authoritative for the comment) and forensic events
 * (for coverage of techniques no finding names), coloring each by its worst observed severity.
 */
export function buildAttackLayer(state: InvestigationState, opts: AttackLayerOptions = {}): NavigatorLayer {
  const acc = new Map<string, TechniqueAcc>();

  const bump = (rawId: string, severity: Severity, findingTitle?: string): void => {
    const id = normalizeTechnique(rawId);
    if (!id) return;
    const cur = acc.get(id) ?? { worst: "Info" as Severity, findingTitles: [], eventCount: 0 };
    cur.worst = worse(cur.worst, severity);
    if (findingTitle) {
      const title = findingTitle.trim();
      if (title && !cur.findingTitles.includes(title)) cur.findingTitles.push(title);
    } else {
      cur.eventCount += 1;
    }
    acc.set(id, cur);
  };

  for (const f of state.findings) {
    for (const t of f.mitreTechniques) bump(t, f.severity, f.title || f.id);
  }
  for (const e of state.forensicTimeline) {
    for (const t of e.mitreTechniques) bump(t, e.severity);
  }

  // Parents that need expanding so their sub-technique scores are visible in the Navigator.
  const parentsToExpand = new Set<string>();
  for (const id of acc.keys()) {
    const parent = parentTechnique(id);
    if (parent) parentsToExpand.add(parent);
  }

  const techniques: NavigatorTechnique[] = [];
  // Scored entries first, sorted worst→least-severe then by id, for a stable, readable layer.
  const scored = [...acc.entries()].sort((a, b) => {
    const rank = SEVERITY_RANK[b[1].worst] - SEVERITY_RANK[a[1].worst];
    return rank !== 0 ? rank : a[0].localeCompare(b[0]);
  });
  for (const [id, info] of scored) {
    techniques.push({
      techniqueID: id,
      score: SEVERITY_SCORE[info.worst],
      color: SEVERITY_COLOR[info.worst],
      comment: commentFor(info),
      enabled: true,
      ...(parentsToExpand.has(id) ? { showSubtechniques: true } : {}),
    });
  }
  // Neutral parent entries (no score/color) purely to expand sub-technique rows that would
  // otherwise be hidden. Skip parents that already have their own scored entry above.
  for (const parent of [...parentsToExpand].sort()) {
    if (acc.has(parent)) continue;
    techniques.push({ techniqueID: parent, enabled: true, showSubtechniques: true });
  }

  // Legend covers only the severities actually present, in worst→least order.
  const present = new Set([...acc.values()].map((v) => v.worst));
  const legendItems = SEVERITIES.filter((s) => present.has(s)).map((s) => ({
    label: `${s} severity`,
    color: SEVERITY_COLOR[s],
  }));

  const findingCount = state.findings.length;
  const name = opts.name?.trim() || `DFIR Companion — ${state.caseId}`;
  const description =
    `MITRE ATT&CK technique coverage for case "${state.caseId}", generated by DFIR Companion ` +
    `from ${findingCount} finding${findingCount === 1 ? "" : "s"} and the forensic timeline ` +
    `(state as of ${state.updatedAt}). Cells are colored by worst observed severity.`;

  return {
    name,
    versions: { attack: opts.attackVersion?.trim() || "16", navigator: "5.1.0", layer: "4.5" },
    domain: "enterprise-attack",
    description,
    techniques,
    gradient: { colors: ["#2e86de", "#f1c40f", "#b30000"], minValue: 0, maxValue: 100 },
    legendItems,
    sorting: 0,
    hideDisabled: false,
    showTacticRowBackground: false,
    tacticRowBackground: "#dddddd",
    selectTechniquesAcrossTactics: true,
    selectSubtechniquesWithParent: false,
  };
}
