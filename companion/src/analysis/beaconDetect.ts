import type { ForensicEvent, Severity } from "./stateTypes.js";
import { isInternalIp } from "./anonymize.js";

// Beacon / C2 pattern detection (issue #82).
//
// A compromised host calling home to its C2 does so PERIODICALLY — a callback every N seconds
// (± a little jitter). The raw forensic timeline shows each connection as its own row, so the
// regularity that screams "beacon" is invisible to the eye when hundreds of network events are
// interleaved. This groups outbound connection events by (source host, destination IP, destination
// port) and flags any tuple whose inter-arrival intervals are TOO REGULAR to be human traffic.
//
// Pure, deterministic, NO AI call and NO network — a statistics pass over events the network
// importers (Suricata/Zeek `networkImport`, SIEM/Velociraptor netstat) already produced with
// `srcIp`/`dstIp`/`port`/`asset`. Like attack phases and adversary hints, this is DERIVED ON READ:
// never persisted to state, re-computed from the timeline each time it's requested.
//
// CRUCIAL FRAMING: low jitter is a *candidate*, not a verdict. Legitimate software also polls on a
// timer (NTP, software-update checks, telemetry, monitoring agents). The output is a hunting lead —
// the analyst confirms against the destination's reputation and the process that owns the socket.

export interface BeaconCandidate {
  id: string; // stable per-timeline id: "beacon-1", "beacon-2", …
  source: string; // the calling host (event.asset, falling back to srcIp), or "(unknown)"
  destIp: string; // the destination IP being contacted
  destPort?: number; // the destination port, when the events carried one
  eventCount: number; // number of connection events in the tuple (occurrences)
  intervalSeconds: number; // MEDIAN inter-arrival interval (seconds), rounded — the beacon period
  jitterSeconds: number; // median absolute deviation of the intervals (seconds), rounded
  jitterPct: number; // MAD / median × 100, rounded — the regularity score (lower = more beacon-like)
  firstSeen: string; // earliest event timestamp in the tuple
  lastSeen: string; // latest event timestamp in the tuple
  severity: Severity; // High when the destination is a public IP (likely external C2), else Medium
  external: boolean; // destination is a public (non-RFC1918/loopback/CGNAT) IP
  eventIds: string[]; // backing forensic-event ids, chronological — for linking from the panel/report
}

export interface BeaconOptions {
  // Minimum number of connection events to a tuple before it's eligible. Default 5 (≥4 intervals).
  minCount?: number;
  // Maximum interval jitter (stddev as a % of the mean) for a tuple to count as a beacon. Default 20%.
  maxJitterPct?: number;
}

export const DEFAULT_BEACON_MIN_COUNT = 5;
export const DEFAULT_BEACON_MAX_JITTER_PCT = 20;

// The shared "this is a lead, not a verdict" disclaimer — rendered on every surface (panel + report).
export const BEACON_CAVEAT =
  "Periodic traffic is a hunting lead, not a verdict — legitimate software also polls on a timer (updates, NTP, telemetry). Confirm the destination reputation and the owning process.";

// One outbound connection event reduced to what beacon grouping needs.
interface Conn {
  source: string;
  destIp: string;
  destPort?: number;
  ms: number; // event time in epoch ms
  ts: string; // original timestamp string
  id: string;
}

// An event participates in beacon detection only if it names a destination IP and is dated. The
// destination is what a host beacons TO; without it there's no tuple. `action` is not required —
// netstat-style imports record a connection without tagging send/receive — but a receive-only row
// (inbound) is excluded so we measure the host's OUTBOUND callback cadence.
function toConn(e: ForensicEvent): Conn | null {
  const destIp = (e.dstIp ?? "").trim();
  if (!destIp) return null;
  if (e.action === "network_receive") return null; // inbound — not a callback
  const ms = Date.parse(e.timestamp);
  if (Number.isNaN(ms)) return null;
  const source = (e.asset ?? e.srcIp ?? "").trim() || "(unknown)";
  return {
    source,
    destIp,
    destPort: typeof e.port === "number" && Number.isFinite(e.port) ? e.port : undefined,
    ms,
    ts: e.timestamp,
    id: e.id,
  };
}

// The grouping key: one beacon is one (source host → destination IP : port) channel. Port is part of
// the key when known, so two services on the same host↔dest pair don't blur together; events without
// a port group under the host↔dest pair alone.
function tupleKey(c: Conn): string {
  return `${c.source}\u0000${c.destIp}\u0000${c.destPort ?? ""}`;
}

// Median of a non-empty list (copies + sorts; even length averages the two middle values).
function median(values: number[]): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = sorted.length >> 1;
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

// Median absolute deviation — a ROBUST spread measure. Unlike stddev, a few off-cadence intervals
// (a missed beacon, an operator-interaction burst, a long idle gap) can't inflate it, so a real
// beacon with occasional irregular check-ins is still recognised as periodic.
function medianAbsoluteDeviation(values: number[], med: number): number {
  if (values.length === 0) return 0;
  return median(values.map((v) => Math.abs(v - med)));
}

// Detect periodic beaconing in a forensic timeline. Returns candidates worst-first (external before
// internal, then most regular, then most frequent), each with the backing event ids. An empty or
// non-network timeline yields no candidates.
export function detectBeacons(events: readonly ForensicEvent[], opts: BeaconOptions = {}): BeaconCandidate[] {
  const minCount = Math.max(3, Math.floor(opts.minCount ?? DEFAULT_BEACON_MIN_COUNT)); // ≥3 ⇒ ≥2 intervals
  const maxJitterPct = Math.max(0, opts.maxJitterPct ?? DEFAULT_BEACON_MAX_JITTER_PCT);

  // Bucket connection events by tuple.
  const groups = new Map<string, Conn[]>();
  for (const e of events) {
    const c = toConn(e);
    if (!c) continue;
    const key = tupleKey(c);
    const bucket = groups.get(key);
    if (bucket) bucket.push(c);
    else groups.set(key, [c]);
  }

  const candidates: BeaconCandidate[] = [];
  for (const conns of groups.values()) {
    if (conns.length < minCount) continue;
    conns.sort((a, b) => a.ms - b.ms || a.id.localeCompare(b.id));

    // Inter-arrival intervals (seconds) between consecutive connections.
    const intervals: number[] = [];
    for (let i = 1; i < conns.length; i++) intervals.push((conns[i].ms - conns[i - 1].ms) / 1000);
    if (intervals.length < 2) continue;

    // Robust period estimate: the MEDIAN interval and its median absolute deviation. Using median
    // over mean means a handful of irregular check-ins (a missed beacon, an operator burst, an idle
    // overnight gap) don't hide an otherwise-periodic channel — the common real-world case.
    const med = median(intervals);
    if (med <= 0) continue; // half the gaps are zero-length — a same-instant burst, not periodic
    const mad = medianAbsoluteDeviation(intervals, med);
    const jitterPct = (mad / med) * 100;
    if (jitterPct > maxJitterPct) continue; // too irregular — human traffic, not a beacon

    const first = conns[0];
    const external = !isInternalIp(first.destIp);
    candidates.push({
      id: "", // assigned after sort, so ids are stable worst-first
      source: first.source,
      destIp: first.destIp,
      destPort: first.destPort,
      eventCount: conns.length,
      intervalSeconds: Math.round(med),
      jitterSeconds: Math.round(mad),
      jitterPct: Math.round(jitterPct),
      firstSeen: conns[0].ts,
      lastSeen: conns[conns.length - 1].ts,
      severity: external ? "High" : "Medium",
      external,
      eventIds: conns.map((c) => c.id),
    });
  }

  // Worst-first: external (likely C2) above internal, then the most regular (lowest jitter), then the
  // most frequent (highest count), then by destination for a deterministic order.
  candidates.sort(
    (a, b) =>
      Number(b.external) - Number(a.external) ||
      a.jitterPct - b.jitterPct ||
      b.eventCount - a.eventCount ||
      a.destIp.localeCompare(b.destIp),
  );
  candidates.forEach((c, i) => {
    c.id = `beacon-${i + 1}`;
  });
  return candidates;
}

// Thresholds resolved from the environment so the route and the report agree:
//   DFIR_BEACON_MIN_COUNT     (default 5)  — minimum connection events to a tuple to consider it
//   DFIR_BEACON_MAX_JITTER_PCT (default 20) — max interval jitter (% of mean) to call it a beacon
export function beaconEnvOptions(): Required<BeaconOptions> {
  return {
    minCount: Number(process.env.DFIR_BEACON_MIN_COUNT) || DEFAULT_BEACON_MIN_COUNT,
    maxJitterPct: Number(process.env.DFIR_BEACON_MAX_JITTER_PCT) || DEFAULT_BEACON_MAX_JITTER_PCT,
  };
}
