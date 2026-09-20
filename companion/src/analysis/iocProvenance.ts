import type { ForensicEvent, IOC } from "./stateTypes.js";
import { SEVERITY_RANK } from "./forensicGate.js";

const TOKEN_RE = /[\w.@:/\\-]{3,}/g;
const LOW_RANK = SEVERITY_RANK.Low;

export type IocProvenance = "detection" | "telemetry";

// For each IOC, the MAX event-severity rank it appears in (SEVERITY_RANK: Info 0 … Critical 4), or
// -1 when no event references it. Boundary-aware exact-token match like iocCorroboration (no false
// substring hits). Pure, derived on read. This is the shared internal-provenance primitive: both the
// detection-vs-telemetry classifier (below) and the composite IOC risk score (iocRiskScore.ts) read it.
//
// Incremental (#1444): the index is keyed by the IOC values up front and remembers ONE number per
// value, so feeding it a 900k-row super-timeline batch by batch costs the IOC count, never the
// case. The whole-array `deriveIocSeverityRank` below is this builder fed once.
export interface IocSeverityRankIndex {
  add(events: readonly ForensicEvent[]): void;
  finish(): Record<string, number>;
  /** How many IOC values have been seen in at least one event — a memory bound, for tests. */
  trackedKeys(): number;
}

export function createIocSeverityRankIndex(iocs: readonly IOC[]): IocSeverityRankIndex {
  const wanted = new Set<string>();
  for (const ioc of iocs) {
    const v = ioc.value.trim().toLowerCase();
    if (v.length >= 3) wanted.add(v);
  }
  const index = new Map<string, number>();
  const add = (raw: string | undefined, rank: number): void => {
    if (!raw) return;
    const key = raw.trim().toLowerCase();
    if (key.length < 3 || !wanted.has(key)) return;
    index.set(key, Math.max(index.get(key) ?? -1, rank));
  };
  return {
    add(events) {
      if (wanted.size === 0) return;
      for (const e of events) {
        const rank = SEVERITY_RANK[e.severity] ?? 0;
        add(e.sha256, rank);
        add(e.md5, rank);
        add(e.srcIp, rank);
        add(e.dstIp, rank);
        add(e.path, rank);
        const tokens = (e.description || "").match(TOKEN_RE);
        if (tokens) for (const t of tokens) add(t, rank);
      }
    },
    finish() {
      const out: Record<string, number> = {};
      for (const ioc of iocs) {
        const v = ioc.value.trim().toLowerCase();
        out[ioc.id] = v.length < 3 ? -1 : (index.get(v) ?? -1);
      }
      return out;
    },
    trackedKeys: () => index.size,
  };
}

export function deriveIocSeverityRank(
  iocs: readonly IOC[],
  events: readonly ForensicEvent[],
): Record<string, number> {
  const index = createIocSeverityRankIndex(iocs);
  index.add(events);
  return index.finish();
}

// For each IOC, the max event severity it appears in (across forensic ∪ super events). Low+ =>
// "detection" (tied to a graded event); Info-only or unmatched => "telemetry". Distinct from the
// threat-intel verdict (external knowledge) — this is internal provenance.
export function deriveIocProvenance(
  iocs: readonly IOC[],
  events: readonly ForensicEvent[],
): Record<string, IocProvenance> {
  return classifyIocProvenance(iocs, deriveIocSeverityRank(iocs, events));
}

/** The classifier over ranks a streamed index produced (#1444) — same rule as deriveIocProvenance. */
export function classifyIocProvenance(
  iocs: readonly IOC[],
  ranks: Record<string, number>,
): Record<string, IocProvenance> {
  const out: Record<string, IocProvenance> = {};
  for (const ioc of iocs) out[ioc.id] = ranks[ioc.id] >= LOW_RANK ? "detection" : "telemetry";
  return out;
}
