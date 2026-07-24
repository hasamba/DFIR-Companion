import type { ForensicEvent } from "./stateTypes.js";

// Clock-skew detection & cross-host timeline alignment (#228).
//
// Hosts in a fleet rarely share a perfectly synchronised clock: NTP drift, a misconfigured
// timezone, or a tampered log source can place an event seconds or minutes off its true time.
// When two tools observe the SAME real-world artifact (the same sha256 / same description) on
// different hosts, the difference between their recorded timestamps is a sample of the clock
// offset between those hosts. We collect those samples, take the MEDIAN per host (robust to a
// stray outlier), and report it so the analyst can either mentally account for it or have
// `alignTimestamps` virtually shift that host's events back onto a common axis.
//
// Pure, deterministic, NO AI call — an anchor-matching + median algorithm.

export const DEFAULT_SKEW_THRESHOLD_MS = 60_000;

export interface ClockSkewOptions {
  thresholdMs?: number;
}

export interface ClockSkewResult {
  host: string;
  offsetMs: number;
  anchorCount: number;
  confidence: number;
}

function anchorKey(e: ForensicEvent): string | undefined {
  if (e.sha256 && e.sha256.length > 0) return `sha256:${e.sha256}`;
  if (e.description && e.description.length > 0) return `desc:${e.description}`;
  return undefined;
}

function median(values: number[]): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0
    ? Math.round((sorted[mid - 1] + sorted[mid]) / 2)
    : sorted[mid];
}

export function detectClockSkew(
  events: ForensicEvent[],
  opts: ClockSkewOptions = {},
): ClockSkewResult[] {
  const thresholdMs = opts.thresholdMs ?? DEFAULT_SKEW_THRESHOLD_MS;

  const buckets = new Map<string, Map<string, number[]>>();
  for (const e of events) {
    if (!e.asset) continue;
    const ts = Date.parse(e.timestamp);
    if (Number.isNaN(ts)) continue;
    const key = anchorKey(e);
    if (!key) continue;
    let byHost = buckets.get(key);
    if (!byHost) { byHost = new Map(); buckets.set(key, byHost); }
    const arr = byHost.get(e.asset);
    if (arr) arr.push(ts); else byHost.set(e.asset, [ts]);
  }

  const samplesByHost = new Map<string, number[]>();
  for (const byHost of buckets.values()) {
    if (byHost.size < 2) continue;
    const allTimes: number[] = [];
    for (const times of byHost.values()) allTimes.push(...times);
    const reference = median(allTimes);
    const maxTime = Math.max(...allTimes);
    const minTime = Math.min(...allTimes);
    if (maxTime - minTime > thresholdMs) continue;
    for (const [host, times] of byHost) {
      for (const t of times) {
        let arr = samplesByHost.get(host);
        if (!arr) { arr = []; samplesByHost.set(host, arr); }
        arr.push(t - reference);
      }
    }
  }

  const results: ClockSkewResult[] = [];
  for (const [host, samples] of samplesByHost) {
    results.push({
      host,
      offsetMs: median(samples),
      anchorCount: samples.length,
      confidence: samples.length,
    });
  }
  results.sort((a, b) => a.host.localeCompare(b.host));
  return results;
}

export function alignTimestamps(
  events: ForensicEvent[],
  skewResults: ClockSkewResult[],
): ForensicEvent[] {
  const offsetByHost = new Map<string, number>();
  for (const r of skewResults) offsetByHost.set(r.host, r.offsetMs);

  const shifted: ForensicEvent[] = [];
  for (const e of events) {
    const offset = e.asset ? offsetByHost.get(e.asset) : undefined;
    if (!offset) { shifted.push(e); continue; }
    const ts = Date.parse(e.timestamp);
    if (Number.isNaN(ts)) { shifted.push(e); continue; }
    const adjustedTs = new Date(ts - offset).toISOString();
    let adjustedEnd: string | undefined;
    if (e.endTimestamp) {
      const endMs = Date.parse(e.endTimestamp);
      if (!Number.isNaN(endMs)) adjustedEnd = new Date(endMs - offset).toISOString();
    }
    shifted.push({ ...e, timestamp: adjustedTs, endTimestamp: adjustedEnd ?? e.endTimestamp });
  }
  return shifted;
}
