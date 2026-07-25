import type { IOC, IocEnrichment, Severity } from "./stateTypes.js";

// IOC verdict evolution tracking (#232). Stale enrichment verdicts are a silent source of
// investigative error: an IOC dismissed as benign on week-old data can be the C2 the case
// hinges on. This pure module builds a timestamped HISTORY per IOC from its enrichment set
// (each provider's `fetchedAt` is a sample of {verdict, score, detections}), and detects
// CHANGES between a previous history and a current one — a benign→suspicious transition, a
// malicious→benign regression, or a score delta beyond a threshold — so the caller can emit an
// activity-log entry + notification ("IOC 5.6.7.8 VT score changed 2→47 (was: benign, now:
// malicious)"). No I/O, no AI calls, no scheduler — the store (verdictEvolutionStore.ts) owns
// persistence and the route owns the recurring schedule + the change-alert dispatch.

export type Verdict = "malicious" | "suspicious" | "harmless" | "unknown";

export interface VerdictSample {
  ts: string;          // ISO timestamp of the lookup (enrichment.fetchedAt)
  provider: string;    // owning provider name (falls back to source)
  verdict: Verdict;
  score?: string;      // human summary, e.g. "47/60"
  detections?: number; // malicious engine count
  total?: number;
}

export interface IocVerdictHistory {
  iocId: string;
  value: string;
  type: IOC["type"];
  samples: VerdictSample[];   // ordered oldest → newest
}

// Per-case config for the scheduled re-enrichment (#232).
export interface VerdictEvolutionConfig {
  enabled: boolean;                // opt-in per case (off by default, like enrichment itself)
  intervalDays: number;            // default 7 for unresolved/low-confidence IOCs
  maliciousIntervalDays: number;   // default 30 for confirmed-malicious IOCs (re-check less often)
  minSeverity: Severity;           // only re-enrich IOCs whose related findings are ≥ this severity
  scoreDeltaThreshold: number;     // emit a change alert when |detections delta| ≥ this (default 5)
  lastRunAt: string;               // ISO, empty when never run
  nextRunAt: string;               // ISO, empty when disabled
}

export const DEFAULT_VERDICT_EVOLUTION_CONFIG: VerdictEvolutionConfig = {
  enabled: false,
  intervalDays: 7,
  maliciousIntervalDays: 30,
  minSeverity: "Low",
  scoreDeltaThreshold: 5,
  lastRunAt: "",
  nextRunAt: "",
};

const VERDICT_RANK: Record<Verdict, number> = { harmless: 0, unknown: 1, suspicious: 2, malicious: 3 };

// Build a per-IOC verdict history from the current IOC list. Each enrichment entry is one
// sample. Samples are ordered oldest → newest per IOC so a sparkline / history table can render
// "VT: 2/60 (Apr 1) → 12/60 (Apr 15) → 47/60 (Apr 22)". Pure — does not mutate the IOCs.
export function computeVerdictHistories(iocs: readonly IOC[]): IocVerdictHistory[] {
  const out: IocVerdictHistory[] = [];
  for (const ioc of iocs) {
    const enrichments = ioc.enrichments ?? [];
    if (enrichments.length === 0) continue;
    const samples: VerdictSample[] = enrichments
      .map((e) => toSample(e))
      .filter((s): s is VerdictSample => s.ts !== "");
    if (samples.length === 0) continue;
    samples.sort((a, b) => a.ts.localeCompare(b.ts));
    out.push({
      iocId: ioc.id,
      value: ioc.value,
      type: ioc.type,
      samples,
    });
  }
  out.sort((a, b) => a.iocId.localeCompare(b.iocId));
  return out;
}

function toSample(e: IocEnrichment): VerdictSample {
  return {
    ts: typeof e.fetchedAt === "string" ? e.fetchedAt : "",
    provider: e.provider ?? e.source,
    verdict: (e.verdict ?? "unknown") as Verdict,
    score: e.score,
    detections: e.detections,
    total: e.total,
  };
}

export type VerdictChangeKind =
  | "escalation"        // verdict moved UP a rank (e.g. harmless → suspicious, suspicious → malicious)
  | "deescalation"      // verdict moved DOWN a rank
  | "score-delta";      // |detections delta| ≥ threshold (verdict may be unchanged)

export interface VerdictChange {
  iocId: string;
  value: string;
  provider: string;
  kind: VerdictChangeKind;
  from: VerdictSample;
  to: VerdictSample;
  message: string;     // pre-formatted one-liner for the activity log / notification
}

// Compare a previous history set against a current one and return the changes worth alerting on.
// A change is detected when, for the same (iocId, provider), the newest sample in `current` is
// newer than the newest sample in `previous` AND either the verdict rank changed OR the
// detections delta ≥ the configured threshold.
//
// Pure and deterministic. `prev` and `current` are the output of computeVerdictHistories() at
// two different points in time (before and after a re-enrichment pass).
export function detectVerdictChanges(
  prev: readonly IocVerdictHistory[],
  current: readonly IocVerdictHistory[],
  opts: { scoreDeltaThreshold?: number } = {},
): VerdictChange[] {
  const threshold = opts.scoreDeltaThreshold ?? DEFAULT_VERDICT_EVOLUTION_CONFIG.scoreDeltaThreshold;
  const prevByIoc = new Map(prev.map((h) => [h.iocId, h]));
  const changes: VerdictChange[] = [];

  for (const cur of current) {
    const prevHistory = prevByIoc.get(cur.iocId);
    if (!prevHistory) continue;
    // Group samples by provider so we compare the same provider's last-before vs last-after.
    const prevByProvider = new Map(prevHistory.samples.map((s) => [s.provider, s]));
    const curByProvider = new Map<string, VerdictSample>();
    for (const s of cur.samples) curByProvider.set(s.provider, s); // last wins → newest (samples are sorted)
    for (const [provider, prevSample] of prevByProvider) {
      const curSample = curByProvider.get(provider);
      if (!curSample) continue;
      // Only a genuinely newer sample counts as a re-check (a re-run that didn't actually query
      // the provider again leaves the same fetchedAt and is not a change).
      if (curSample.ts <= prevSample.ts) continue;
      const rankDelta = VERDICT_RANK[curSample.verdict] - VERDICT_RANK[prevSample.verdict];
      const detDelta = (curSample.detections ?? 0) - (prevSample.detections ?? 0);
      let kind: VerdictChangeKind | null = null;
      if (rankDelta > 0) kind = "escalation";
      else if (rankDelta < 0) kind = "deescalation";
      else if (Math.abs(detDelta) >= threshold) kind = "score-delta";
      if (!kind) continue;
      changes.push({
        iocId: cur.iocId,
        value: cur.value,
        provider,
        kind,
        from: prevSample,
        to: curSample,
        message: formatChangeMessage(cur.value, provider, prevSample, curSample, kind),
      });
    }
  }
  return changes;
}

export function formatChangeMessage(
  value: string,
  provider: string,
  from: VerdictSample,
  to: VerdictSample,
  kind: VerdictChangeKind,
): string {
  const fromScore = from.score ?? (from.detections !== undefined ? `${from.detections}/${from.total ?? "?"}` : "n/a");
  const toScore = to.score ?? (to.detections !== undefined ? `${to.detections}/${to.total ?? "?"}` : "n/a");
  if (kind === "score-delta") {
    return `IOC ${value} ${provider} score changed ${fromScore}→${toScore} (verdict: ${to.verdict}).`;
  }
  return `IOC ${value} ${provider} verdict changed ${from.verdict}→${to.verdict} (${fromScore}→${toScore}).`;
}

// Compute the next run timestamp for a config, given the current time. Returns "" when disabled.
// Pure — injectable `now` for tests.
export function nextRunAtFor(cfg: VerdictEvolutionConfig, now: Date = new Date()): string {
  if (!cfg.enabled) return "";
  // Use the shorter interval (the unresolved/low-confidence IOC cadence) as the schedule tick;
  // the per-IOC malicious-interval is applied at run time to skip recently-confirmed-malicious
  // IOCs. This keeps the scheduler simple: one tick, run-time filtering.
  const days = Math.max(1, Math.floor(cfg.intervalDays));
  const next = new Date(now.getTime() + days * 24 * 60 * 60 * 1000);
  return next.toISOString();
}

// Decide which IOCs are due for a re-enrichment at this run, given the config + the current
// histories + the case's findings (for severity filtering). An IOC is due when:
//   - it has at least one enrichment sample (we only re-check IOCs that have been enriched
//     before — the first enrichment is the existing one-shot bulk-enrich, not this feature), AND
//   - its most-recent sample is older than the applicable interval (intervalDays for
//     unresolved/low-confidence, maliciousIntervalDays for confirmed-malicious), AND
//   - it is related to a finding at or above the configured minSeverity (so we don't burn API
//     quota re-checking Info-severity noise).
//
// Pure. `findings` is the case's findings list (used for severity filtering via relatedIocs).
export function selectIocsDueForRecheck(
  iocs: readonly IOC[],
  histories: readonly IocVerdictHistory[],
  findings: { id: string; severity: Severity; relatedIocs: string[]; status: string }[],
  cfg: VerdictEvolutionConfig,
  now: Date = new Date(),
): IOC[] {
  const historyByIoc = new Map(histories.map((h) => [h.iocId, h]));
  // Build the set of IOC ids that appear on a finding at/above minSeverity.
  const minRank = severityRank(cfg.minSeverity);
  const iocsOnRelevantFindings = new Set<string>();
  for (const f of findings) {
    if (severityRank(f.severity) < minRank) continue;
    for (const iocId of f.relatedIocs) iocsOnRelevantFindings.add(iocId);
  }
  const out: IOC[] = [];
  for (const ioc of iocs) {
    if (!iocsOnRelevantFindings.has(ioc.id)) continue;
    const h = historyByIoc.get(ioc.id);
    if (!h || h.samples.length === 0) continue;
    const newest = h.samples[h.samples.length - 1];
    const lastTs = Date.parse(newest.ts);
    if (Number.isNaN(lastTs)) continue;
    const isMalicious = newest.verdict === "malicious";
    const intervalDays = isMalicious ? Math.max(1, Math.floor(cfg.maliciousIntervalDays)) : Math.max(1, Math.floor(cfg.intervalDays));
    const dueMs = lastTs + intervalDays * 24 * 60 * 60 * 1000;
    if (now.getTime() >= dueMs) out.push(ioc);
  }
  return out;
}

function severityRank(s: Severity): number {
  return { Critical: 5, High: 4, Medium: 3, Low: 2, Info: 1 }[s] ?? 0;
}