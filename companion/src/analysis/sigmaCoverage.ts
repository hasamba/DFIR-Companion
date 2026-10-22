// Per-case Sigma coverage (#2217): for every origin the case's super-timeline holds, which Sigma log
// sources grade it at import and how many rules each runs — or that nothing grades it.
//
// Pure and derived on read: the origin counts come from the super-timeline (one GROUP BY), the
// rule counts from the active rule set's inventory. Analyst-only — no AI prompt reads this
// (CLAUDE.md §7: the AI never reads the super-timeline).

import type { SigmaInventoryEntry } from "./sigmaRuleSet.js";
import {
  SIGMA_LOG_SOURCES,
  SIGMA_ORIGIN_ENTRA,
  SIGMA_ORIGIN_WEB,
  type SigmaLogSourceDef,
} from "./sigmaLogSources.js";

export type SigmaCoverageState = "covered" | "no-loaded-rules" | "not-graded" | "sigma-off";

export interface SigmaCoverageSource {
  id: string;
  label: string;
  loaded: number;
  disabled: number;
  refused: number;
  /** Rules held back by the status filter (DFIR_SIGMA_RULE_STATUSES). */
  status: number;
}

export interface SigmaCoverageRow {
  origin: string;
  events: number;
  sigmaSources: SigmaCoverageSource[];
  state: SigmaCoverageState;
  caveat?: string;
}

export interface SigmaCoverage {
  enabled: boolean;
  /** Rows in the "covered" state. */
  graded: number;
  total: number;
  rows: SigmaCoverageRow[];
}

export interface SigmaOriginCount {
  origin: string;
  events: number;
}

// What one origin label cannot say on its own.
const ORIGIN_CAVEATS: Readonly<Record<string, string>> = {
  [SIGMA_ORIGIN_ENTRA]: "service-principal sign-ins carry this origin too, and Sigma does not grade them",
  [SIGMA_ORIGIN_WEB]:
    "graded by the web server OR the web proxy rules, chosen per import from the log's shape",
};

/** Inventory grouped by source id and outcome; rules with no source count under "other". */
export function inventoryCounts(
  inventory: readonly SigmaInventoryEntry[],
): Record<string, Record<string, number>> {
  const out: Record<string, Record<string, number>> = {};
  for (const e of inventory) {
    const src = e.source ?? "other";
    out[src] = { ...(out[src] ?? {}), [e.outcome]: (out[src]?.[e.outcome] ?? 0) + 1 };
  }
  return out;
}

function sourceRow(
  def: SigmaLogSourceDef,
  counts: Record<string, Record<string, number>>,
): SigmaCoverageSource {
  const c = counts[def.id] ?? {};
  return {
    id: def.id,
    label: def.label,
    loaded: c.loaded ?? 0,
    disabled: c.disabled ?? 0,
    refused: c.refused ?? 0,
    status: c.status ?? 0,
  };
}

function stateOf(enabled: boolean, sources: readonly SigmaCoverageSource[]): SigmaCoverageState {
  if (!enabled) return "sigma-off";
  if (!sources.length) return "not-graded";
  return sources.some((s) => s.loaded > 0) ? "covered" : "no-loaded-rules";
}

export function computeSigmaCoverage(
  originCounts: readonly SigmaOriginCount[],
  inventory: readonly SigmaInventoryEntry[],
  enabled: boolean,
  sources: readonly SigmaLogSourceDef[] = SIGMA_LOG_SOURCES,
): SigmaCoverage {
  const counts = inventoryCounts(inventory);
  const rows = [...originCounts]
    .sort((a, b) => b.events - a.events || a.origin.localeCompare(b.origin))
    .map((oc): SigmaCoverageRow => {
      const sigmaSources = sources
        .filter((d) => d.origins.includes(oc.origin))
        .map((d) => sourceRow(d, counts));
      const caveat = ORIGIN_CAVEATS[oc.origin];
      return {
        origin: oc.origin,
        events: oc.events,
        sigmaSources,
        state: stateOf(enabled, sigmaSources),
        ...(caveat ? { caveat } : {}),
      };
    });
  return { enabled, graded: rows.filter((r) => r.state === "covered").length, total: rows.length, rows };
}
