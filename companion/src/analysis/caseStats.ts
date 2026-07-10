// Case-scoped introspection stats (#241): totals, event-by-source breakdown, and daily import
// velocity for the current case's Diagnostics tab. Pure, derived-on-read — no AI, no caching,
// same pattern as hostRanking.ts.

import type { InvestigationState } from "./stateTypes.js";
import { buildAssetGraph } from "./assetGraph.js";
import type { ImportMetadata } from "../types.js";

export interface CaseStatsTotals {
  events: number;
  findings: number;
  iocs: number;
  assets: number;
}

export interface SourceCount {
  source: string;
  count: number;
}

export interface ImportVelocityDay {
  date: string;    // YYYY-MM-DD (UTC)
  imports: number;
  rows: number;
}

export interface CaseStats {
  totals: CaseStatsTotals;
  bySource: SourceCount[];
  importVelocity: ImportVelocityDay[];
}

export function computeCaseStats(state: InvestigationState, importLog: ImportMetadata[]): CaseStats {
  const totals: CaseStatsTotals = {
    events: state.forensicTimeline.length,
    findings: state.findings.length,
    iocs: state.iocs.length,
    assets: buildAssetGraph(state).assets.length,
  };

  const sourceCounts = new Map<string, number>();
  for (const e of state.forensicTimeline) {
    for (const s of e.sources ?? []) sourceCounts.set(s, (sourceCounts.get(s) ?? 0) + 1);
  }
  const bySource = [...sourceCounts.entries()]
    .map(([source, count]) => ({ source, count }))
    .sort((a, b) => b.count - a.count || a.source.localeCompare(b.source));

  const byDay = new Map<string, { imports: number; rows: number }>();
  for (const rec of importLog) {
    const date = (rec.importedAt ?? "").slice(0, 10);
    if (!date) continue;
    const day = byDay.get(date) ?? { imports: 0, rows: 0 };
    day.imports++;
    day.rows += rec.rows ?? 0;
    byDay.set(date, day);
  }
  const importVelocity = [...byDay.entries()]
    .map(([date, v]) => ({ date, imports: v.imports, rows: v.rows }))
    .sort((a, b) => a.date.localeCompare(b.date));

  return { totals, bySource, importVelocity };
}
