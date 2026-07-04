import type { ForensicEvent, IOC } from "./stateTypes.js";
import { SEVERITY_RANK } from "./forensicGate.js";

const TOKEN_RE = /[\w.@:/\\-]{3,}/g;
const LOW_RANK = SEVERITY_RANK.Low;

export type IocProvenance = "detection" | "telemetry";

// For each IOC, the max event severity it appears in (across forensic ∪ super events). Low+ =>
// "detection" (tied to a graded event); Info-only or unmatched => "telemetry". Distinct from the
// threat-intel verdict (external knowledge) — this is internal provenance. Pure, derived on read;
// boundary-aware exact-token match like iocCorroboration (no false substring hits).
export function deriveIocProvenance(iocs: readonly IOC[], events: readonly ForensicEvent[]): Record<string, IocProvenance> {
  const out: Record<string, IocProvenance> = {};
  if (iocs.length === 0) return out;
  const index = new Map<string, number>();
  const add = (raw: string | undefined, rank: number): void => {
    if (!raw) return;
    const key = raw.trim().toLowerCase();
    if (key.length < 3) return;
    index.set(key, Math.max(index.get(key) ?? -1, rank));
  };
  for (const e of events) {
    const rank = SEVERITY_RANK[e.severity] ?? 0;
    add(e.sha256, rank); add(e.md5, rank); add(e.srcIp, rank); add(e.dstIp, rank); add(e.path, rank);
    const tokens = (e.description || "").match(TOKEN_RE);
    if (tokens) for (const t of tokens) add(t, rank);
  }
  for (const ioc of iocs) {
    const v = ioc.value.trim().toLowerCase();
    if (v.length < 3) { out[ioc.id] = "telemetry"; continue; }
    const rank = index.get(v);
    out[ioc.id] = rank !== undefined && rank >= LOW_RANK ? "detection" : "telemetry";
  }
  return out;
}
