import type { ForensicEvent, Severity } from "./stateTypes.js";
import { byEventTime } from "./forensicSort.js";

// Timeline anomaly detection: flags per-asset event-rate spikes in a time bucket. A large
// intrusion timeline hides the "host that went crazy" signal behind thousands of routine rows;
// this surfaces the outlier without an AI call, via TWO complementary baselines:
//
//   • PEER baseline ("peer"): an asset whose count in a bucket exceeds spikeFactor × the MEDIAN
//     count across all OTHER assets in that same bucket. Catches "one host far busier than its
//     peers right now". RELATIVE — can be masked when broad, low-rate telemetry lifts every
//     asset's count in the bucket (the median rises, so a marginal outlier stops being one).
//   • SELF baseline ("self"): an asset whose count in a bucket exceeds selfFactor × the MEDIAN of
//     THAT asset's own per-bucket counts across the whole timeline. Catches "a host that is
//     normally quiet, then bursts" independent of its peers — so importing unrelated telemetry
//     can't hide it. Needs a few active buckets to have a stable baseline (selfMinBuckets).
//
// An (asset, bucket) flagged by both is reported ONCE, carrying both methods; the shown
// ratio/baseline/severity come from the stronger (higher-ratio) method.
//
// Algorithm:
//   1. Bucket dated events by (asset, bucket-start) — default 15-minute buckets.
//   2. Peer pass: per bucket, median across assets → flag count ≥ spikeFactor × median.
//   3. Self pass: per asset, median across its active buckets → flag count ≥ selfFactor × median.
//   4. Merge by (asset, bucket); events without an `asset` group under "(unknown)".
//
// Pure, deterministic, NO AI call. Same "derived on read" shape as burstDetect / gapDetect.

export type AnomalyKind = "peer" | "self";

export interface TimelineAnomaly {
  id: string;             // stable: `${asset}:${bucketStart}`
  asset: string;          // affected host or account
  bucketStart: string;    // ISO timestamp of the bucket's start
  bucketEnd: string;      // ISO timestamp of the bucket's end
  eventCount: number;     // events in this bucket for this asset
  medianCount: number;    // baseline the shown ratio is measured against (peer or self median)
  ratio: number;          // eventCount / baseline (rounded to 1 decimal) — the stronger method's
  severity: Severity;     // Critical ≥ 10×, High ≥ 7×, else Medium
  kind: AnomalyKind;      // the method that produced the shown (stronger) ratio
  methods: AnomalyKind[]; // every method that flagged this (asset, bucket) — "peer" and/or "self"
  eventIds: string[];     // ids of the underlying events, chronological
}

export interface TimelineAnomalyResult {
  anomalies: TimelineAnomaly[];
  bucketMinutes: number;
  spikeFactor: number;
  selfFactor: number;
  assetCount: number;
}

export interface AnomalyOptions {
  bucketMinutes?: number;   // bucket width in minutes; default 15
  spikeFactor?: number;     // peer-median ratio threshold to flag; default 5
  minEvents?: number;       // minimum events in the spike bucket to flag; default 3
  selfFactor?: number;      // self-median ratio threshold; default = spikeFactor
  selfMinBuckets?: number;  // min active buckets for an asset's self-baseline; default 3
}

export const DEFAULT_BUCKET_MINUTES = 15;
export const DEFAULT_SPIKE_FACTOR = 5;
export const DEFAULT_MIN_EVENTS = 3;
export const DEFAULT_SELF_MIN_BUCKETS = 3;

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
  const selfFactor = Math.max(1, opts.selfFactor ?? spikeFactor);
  const selfMinBuckets = Math.max(2, opts.selfMinBuckets ?? DEFAULT_SELF_MIN_BUCKETS);
  const bucketMs = bucketMinutes * 60 * 1000;

  const dated = events.filter((e) => !Number.isNaN(Date.parse(e.timestamp))).sort(byEventTime);
  if (dated.length === 0) {
    return { anomalies: [], bucketMinutes, spikeFactor, selfFactor, assetCount: 0 };
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

  // Merge sink, keyed by `${asset}:${bucketStartIso}`. The first method to flag an (asset,bucket)
  // creates the entry; a second method appends to `methods` and, when stronger, takes over the
  // shown ratio/baseline/severity/kind.
  const flagged = new Map<string, TimelineAnomaly>();
  const flag = (asset: string, floorMs: number, evs: ForensicEvent[], baseline: number, rawRatio: number, kind: AnomalyKind): void => {
    const bucketStart = msToIso(floorMs);
    const id = `${asset}:${bucketStart}`;
    const ratio = Math.round(rawRatio * 10) / 10;
    const existing = flagged.get(id);
    if (existing) {
      if (!existing.methods.includes(kind)) existing.methods.push(kind);
      if (rawRatio > existing.eventCount / existing.medianCount) {
        existing.medianCount = Math.round(baseline * 10) / 10;
        existing.ratio = ratio;
        existing.severity = deriveAnomSeverity(rawRatio);
        existing.kind = kind;
      }
      return;
    }
    flagged.set(id, {
      id, asset, bucketStart, bucketEnd: msToIso(floorMs + bucketMs),
      eventCount: evs.length,
      medianCount: Math.round(baseline * 10) / 10,
      ratio,
      severity: deriveAnomSeverity(rawRatio),
      kind, methods: [kind],
      eventIds: evs.map((e) => e.id),
    });
  };

  // ── Peer pass: each asset vs the median across assets in the same bucket. ──
  for (const [floorMs, assetMap] of buckets) {
    if (assetMap.size < 2) continue; // need ≥ 2 assets for a meaningful peer baseline
    const med = median([...assetMap.values()].map((evs) => evs.length));
    if (med <= 0) continue;
    for (const [asset, evs] of assetMap) {
      if (evs.length < minEvents) continue;
      const ratio = evs.length / med;
      if (ratio >= spikeFactor) flag(asset, floorMs, evs, med, ratio, "peer");
    }
  }

  // ── Self pass: each asset vs the median of its OWN per-bucket counts across the timeline. ──
  const perAsset = new Map<string, Map<number, ForensicEvent[]>>();
  for (const [floorMs, assetMap] of buckets) {
    for (const [asset, evs] of assetMap) {
      let bm = perAsset.get(asset);
      if (!bm) { bm = new Map(); perAsset.set(asset, bm); }
      bm.set(floorMs, evs);
    }
  }
  for (const [asset, bm] of perAsset) {
    if (bm.size < selfMinBuckets) continue; // too few active buckets for a stable self-baseline
    const med = median([...bm.values()].map((evs) => evs.length));
    if (med <= 0) continue;
    for (const [floorMs, evs] of bm) {
      if (evs.length < minEvents) continue;
      const ratio = evs.length / med;
      if (ratio >= selfFactor) flag(asset, floorMs, evs, med, ratio, "self");
    }
  }

  // Stable display order: "peer" before "self" when both fired.
  const anomalies = [...flagged.values()];
  for (const a of anomalies) a.methods.sort((x, y) => (x === "peer" ? -1 : 1) - (y === "peer" ? -1 : 1));

  // Sort by severity then ratio descending.
  const SEV_RANK: Record<Severity, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
  anomalies.sort((a, b) => {
    const sev = SEV_RANK[a.severity] - SEV_RANK[b.severity];
    return sev !== 0 ? sev : b.ratio - a.ratio;
  });

  return { anomalies, bucketMinutes, spikeFactor, selfFactor, assetCount: allAssets.size };
}

export function anomalyEnvOptions(): AnomalyOptions {
  return {
    bucketMinutes: process.env.DFIR_ANOMALY_BUCKET_MINUTES
      ? Number(process.env.DFIR_ANOMALY_BUCKET_MINUTES) : undefined,
    spikeFactor: process.env.DFIR_ANOMALY_SPIKE_FACTOR
      ? Number(process.env.DFIR_ANOMALY_SPIKE_FACTOR) : undefined,
    minEvents: process.env.DFIR_ANOMALY_MIN_EVENTS
      ? Number(process.env.DFIR_ANOMALY_MIN_EVENTS) : undefined,
    selfFactor: process.env.DFIR_ANOMALY_SELF_FACTOR
      ? Number(process.env.DFIR_ANOMALY_SELF_FACTOR) : undefined,
  };
}
