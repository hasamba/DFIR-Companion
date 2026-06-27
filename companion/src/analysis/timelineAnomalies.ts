import type { ForensicEvent, Severity } from "./stateTypes.js";
import { byEventTime } from "./forensicSort.js";

// Timeline anomaly detection: flags per-asset event-rate spikes relative to other assets in the
// same time bucket. A large intrusion timeline hides the "host that went crazy" signal behind
// thousands of routine rows from other machines; this surfaces the outlier without an AI call.
//
// Algorithm:
//   1. Bucket dated events by (asset, bucket-start) — default 1-hour buckets.
//   2. For each bucket-start, collect every asset's count → compute the MEDIAN count across assets.
//   3. An anomaly is an (asset, bucket) pair whose count exceeds spikeFactor × median.
//   4. Events without an `asset` field are grouped under the synthetic "(unknown)" asset.
//
// Pure, deterministic, NO AI call. Same "derived on read" shape as burstDetect / gapDetect.

export interface TimelineAnomaly {
  id: string;           // stable: `${asset}:${bucketStart}`
  asset: string;        // affected host or account
  bucketStart: string;  // ISO timestamp of the bucket's start
  bucketEnd: string;    // ISO timestamp of the bucket's end
  eventCount: number;   // events in this bucket for this asset
  medianCount: number;  // median count across all assets in this bucket
  ratio: number;        // eventCount / medianCount (rounded to 1 decimal)
  severity: Severity;   // Critical ≥ 10×, High ≥ 7×, else Medium
  eventIds: string[];   // ids of the underlying events, chronological
}

export interface TimelineAnomalyResult {
  anomalies: TimelineAnomaly[];
  bucketMinutes: number;
  spikeFactor: number;
  assetCount: number;
}

export interface AnomalyOptions {
  bucketMinutes?: number;  // bucket width in minutes; default 60
  spikeFactor?: number;    // ratio threshold to flag; default 5
  minEvents?: number;      // minimum events in the spike bucket to flag; default 3
}

export const DEFAULT_BUCKET_MINUTES = 60;
export const DEFAULT_SPIKE_FACTOR = 5;
export const DEFAULT_MIN_EVENTS = 3;

function bucketFloorMs(tsMs: number, bucketMs: number): number {
  return Math.floor(tsMs / bucketMs) * bucketMs;
}

function msToIso(ms: number): string {
  return new Date(ms).toISOString();
}

function median(values: number[]): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 1
    ? sorted[mid]
    : (sorted[mid - 1] + sorted[mid]) / 2;
}

function deriveAnomSeverity(ratio: number): Severity {
  if (ratio >= 10) return "Critical";
  if (ratio >= 7) return "High";
  return "Medium";
}

export function detectTimelineAnomalies(
  events: readonly ForensicEvent[],
  opts: AnomalyOptions = {},
): TimelineAnomalyResult {
  const bucketMinutes = Math.max(1, opts.bucketMinutes ?? DEFAULT_BUCKET_MINUTES);
  const spikeFactor = Math.max(1, opts.spikeFactor ?? DEFAULT_SPIKE_FACTOR);
  const minEvents = Math.max(1, opts.minEvents ?? DEFAULT_MIN_EVENTS);
  const bucketMs = bucketMinutes * 60 * 1000;

  const dated = events.filter((e) => !Number.isNaN(Date.parse(e.timestamp))).sort(byEventTime);
  if (dated.length === 0) {
    return { anomalies: [], bucketMinutes, spikeFactor, assetCount: 0 };
  }

  // Build bucket map: bucketStart (ms) → asset → event[]
  const buckets = new Map<number, Map<string, ForensicEvent[]>>();
  for (const e of dated) {
    const floorMs = bucketFloorMs(Date.parse(e.timestamp), bucketMs);
    const asset = (e.asset ?? "").trim() || "(unknown)";
    let assetMap = buckets.get(floorMs);
    if (!assetMap) { assetMap = new Map(); buckets.set(floorMs, assetMap); }
    let evs = assetMap.get(asset);
    if (!evs) { evs = []; assetMap.set(asset, evs); }
    evs.push(e);
  }

  const allAssets = new Set<string>(dated.map((e) => (e.asset ?? "").trim() || "(unknown)"));

  const anomalies: TimelineAnomaly[] = [];
  for (const [floorMs, assetMap] of buckets) {
    if (assetMap.size < 2) continue; // need at least 2 assets for a meaningful baseline

    const counts = [...assetMap.values()].map((evs) => evs.length);
    const med = median(counts);
    if (med <= 0) continue;

    const bucketStart = msToIso(floorMs);
    const bucketEnd = msToIso(floorMs + bucketMs);

    for (const [asset, evs] of assetMap) {
      const count = evs.length;
      if (count < minEvents) continue;
      const ratio = count / med;
      if (ratio < spikeFactor) continue;
      anomalies.push({
        id: `${asset}:${bucketStart}`,
        asset,
        bucketStart,
        bucketEnd,
        eventCount: count,
        medianCount: Math.round(med * 10) / 10,
        ratio: Math.round(ratio * 10) / 10,
        severity: deriveAnomSeverity(ratio),
        eventIds: evs.map((e) => e.id),
      });
    }
  }

  // Sort by severity then ratio descending
  const SEV_RANK: Record<Severity, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
  anomalies.sort((a, b) => {
    const sev = SEV_RANK[a.severity] - SEV_RANK[b.severity];
    return sev !== 0 ? sev : b.ratio - a.ratio;
  });

  return { anomalies, bucketMinutes, spikeFactor, assetCount: allAssets.size };
}

export function anomalyEnvOptions(): AnomalyOptions {
  return {
    bucketMinutes: process.env.DFIR_ANOMALY_BUCKET_MINUTES
      ? Number(process.env.DFIR_ANOMALY_BUCKET_MINUTES) : undefined,
    spikeFactor: process.env.DFIR_ANOMALY_SPIKE_FACTOR
      ? Number(process.env.DFIR_ANOMALY_SPIKE_FACTOR) : undefined,
    minEvents: process.env.DFIR_ANOMALY_MIN_EVENTS
      ? Number(process.env.DFIR_ANOMALY_MIN_EVENTS) : undefined,
  };
}
