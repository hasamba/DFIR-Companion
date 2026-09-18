// nfdump's (NetFlow/IPFIX collector) `-o ndjson` flow-record output (#932 item 10, "933.3"): one
// exporter-reported flow per line. Interim active-timeout re-exports of the same ongoing
// connection are merged by temporal adjacency BEFORE anything reaches periodicity analysis; a
// same-tuple record from a different exporter is disclosed as a possible duplicate, never merged
// away. Normalized flows feed `beaconDetect.ts` — the EXISTING, unmodified periodicity detector —
// in-memory, at import time; any candidate it finds becomes ONE bounded Low-severity lead, which
// is what survives the forensic-gate demote floor and reaches AI synthesis. The bulk per-flow
// telemetry itself stays Info, exactly like every other bulk network importer in this codebase
// (mirrors Zeek `conn` rows in networkImport.ts) — never sent to AI in bulk.
//
// Schema verified live against nfdump's own src/output/output_json.c — not invented. See
// RECOMMENDATION-10.md for the full research trail, including why v1's design was rejected.

import { createHash } from "node:crypto";
import { boundedAggKey } from "./aggKey.js";
import { createCanonicalEvent } from "./canonicalEvent.js";
import {
  EXPORTER_FLOW_BASIS,
  EXPORTER_FLOW_BEACON_LEAD_BASIS,
  MAX_FIELD_LEN,
} from "./canonicalExporterFlow.js";
import { detectBeacons, BEACON_CAVEAT, type BeaconCandidate } from "./beaconDetect.js";
import { isInternalIp } from "./anonymize.js";
import {
  addIoc,
  isObject,
  mergeRowIocs,
  type MappedEvent,
  type SiemEvent,
  type SiemIoc,
} from "./siemImport.js";
import { aggregateEvents } from "./eventAggregate.js";
import type { ForensicEvent } from "./stateTypes.js";

export const MAX_RECORDS_SCANNED = 20_000; // report-wide
export const MAX_DUPLICATE_CHECK_BUCKET = 500; // pairwise-comparison bound per same-tuple bucket
export const MERGE_GAP_SECONDS = 5;

const TCP = 6;

interface RawRecord {
  firstMs: number;
  lastMs: number;
  proto: number;
  srcAddr: string;
  dstAddr: string;
  srcPort?: number;
  dstPort?: number;
  inBytes: number;
  inPackets: number;
  tcpFlags?: string;
  exporterSysId: number;
  observationPointId?: number;
  sampled: boolean;
}

interface MergedFlow extends RawRecord {
  mergedRecordCount: number;
  possibleDuplicateExporterCount: number;
}

export interface ExporterFlowOptions {
  aggregate?: boolean;
  maxEvents?: number;
}

export interface ExporterFlowResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  total: number;
  kept: number;
  dropped: number;
  groups: number;
  format: string;
  malformedRecords: number;
  recordsTruncated: boolean;
  flowCount: number;
  beaconLeadCount: number;
}

function str(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}

function num(v: unknown): number | undefined {
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
}

function clip(text: string, max: number): string {
  return text.length <= max ? text : text.slice(0, max);
}

// nfdump's own `first`/`last` strings carry no timezone offset (its C code formats local time,
// then appends milliseconds) — Date.parse's interpretation of an offset-less ISO-shaped string is
// runtime-dependent. Known, disclosed limitation (not resolved here): absolute cross-upload/
// cross-timezone time comparison isn't guaranteed, but every comparison THIS importer itself makes
// (interim-merge adjacency, beacon interval/jitter) is relative, within one parse of one upload, so
// it stays internally consistent regardless of which absolute epoch a given runtime assigns.
function parseMs(v: unknown): number | undefined {
  const s = str(v);
  if (!s) return undefined;
  const ms = Date.parse(s);
  return Number.isNaN(ms) ? undefined : ms;
}

/** Two anchors: the fixed timestamp triple `first`/`last`/`received` (nfdump's own code keeps
 * these structurally distinct) plus `export_sysid` — no other tool in this codebase's vocabulary
 * emits that exact combination. */
export function isNfdumpFlowRecord(root: unknown): boolean {
  if (!isObject(root)) return false;
  return (
    typeof root.first === "string" &&
    typeof root.last === "string" &&
    typeof root.received === "string" &&
    typeof root.export_sysid === "number"
  );
}

function parseRecord(raw: unknown): RawRecord | null {
  if (!isObject(raw)) return null;
  const firstMs = parseMs(raw.first);
  const lastMs = parseMs(raw.last);
  const proto = num(raw.proto);
  const srcAddr = str(raw.src4_addr);
  const dstAddr = str(raw.dst4_addr);
  const inBytes = num(raw.in_bytes);
  const inPackets = num(raw.in_packets);
  const exporterSysId = num(raw.export_sysid);
  if (
    firstMs === undefined ||
    lastMs === undefined ||
    proto === undefined ||
    !srcAddr ||
    !dstAddr ||
    inBytes === undefined ||
    inPackets === undefined ||
    exporterSysId === undefined
  ) {
    return null;
  }
  // nfdump's own JSON emits a numeric 0/1, never a JSON boolean literal (Codex code review
  // finding on the design doc) — coerced explicitly here, before the canonical schema (which
  // stays a real boolean) ever sees it.
  const sampledRaw = raw.sampled;
  const sampled = typeof sampledRaw === "number" ? sampledRaw !== 0 : sampledRaw === true;
  return {
    firstMs,
    lastMs,
    proto,
    srcAddr,
    dstAddr,
    srcPort: num(raw.src_port),
    dstPort: num(raw.dst_port),
    inBytes,
    inPackets,
    tcpFlags: str(raw.tcp_flags),
    exporterSysId,
    observationPointId: num(raw.observationPointID),
    sampled,
  };
}

function tupleKey(r: RawRecord, includeExporter: boolean): string {
  const base = [r.proto, r.srcAddr, r.dstAddr, r.srcPort ?? "", r.dstPort ?? ""].join("|");
  return includeExporter ? `${r.exporterSysId}|${r.observationPointId ?? ""}|${base}` : base;
}

/** Positional union of two nfdump FlagsString values (fixed-width, one character per flag —
 * e.g. ".AP.SF") — Codex code review finding: a merge previously kept only the FIRST record's own
 * flags, so a later interim record's own flags (e.g. a final FIN/RST) were silently lost. Any
 * non-"." character at a position wins. */
function mergeTcpFlags(a: string | undefined, b: string | undefined): string | undefined {
  if (!a) return b;
  if (!b || a.length !== b.length) return a;
  let out = "";
  for (let i = 0; i < a.length; i++) out += a[i] !== "." ? a[i] : b[i];
  return out;
}

/** Merge interim active-timeout re-exports of the SAME ongoing connection by temporal adjacency —
 * a heuristic, never a certainty (see RECOMMENDATION-10.md's own disclosed limitations). */
function mergeGroup(records: RawRecord[]): MergedFlow[] {
  const sorted = [...records].sort((a, b) => a.firstMs - b.firstMs);
  const merged: MergedFlow[] = [];
  for (const r of sorted) {
    const prev = merged[merged.length - 1];
    if (prev && r.firstMs <= prev.lastMs + MERGE_GAP_SECONDS * 1000) {
      prev.lastMs = Math.max(prev.lastMs, r.lastMs);
      prev.inBytes += r.inBytes;
      prev.inPackets += r.inPackets;
      prev.sampled = prev.sampled || r.sampled;
      prev.tcpFlags = mergeTcpFlags(prev.tcpFlags, r.tcpFlags);
      prev.mergedRecordCount += 1;
      continue;
    }
    merged.push({ ...r, mergedRecordCount: 1, possibleDuplicateExporterCount: 0 });
  }
  return merged;
}

// A completed TCP handshake typically leaves BOTH directions' own aggregate (OR-of-the-whole-flow)
// tcp_flags carrying SYN — the initiator's flow from its own opening SYN packet, and the
// responder's flow from its own SYN-ACK reply — so "contains S" alone cannot reliably tell
// initiator from responder (Codex code review finding: a SYN-ACK reply flow was being
// misclassified as outbound/initiating). The only UNAMBIGUOUS signal available from an aggregate
// flag set is a bare SYN with no ACK ever recorded alongside it — the very first packet of a
// handshake that received no reply captured in this flow. Everything else (SYN+ACK together,
// ACK-only, no flags at all) is honestly "unknown", never guessed as "reply" — a claim this
// importer can no longer make reliably. UDP/ICMP carry no flag signal at all — always "unknown".
function initiatingDirectionOf(flow: MergedFlow): "outbound" | "unknown" {
  if (flow.proto !== TCP || !flow.tcpFlags) return "unknown";
  return flow.tcpFlags.includes("S") && !flow.tcpFlags.includes("A") ? "outbound" : "unknown";
}

function flowAggKey(reportFingerprint: string, flow: MergedFlow): string {
  const findingId = createHash("sha256")
    .update(
      JSON.stringify([
        reportFingerprint,
        flow.exporterSysId,
        flow.observationPointId ?? null,
        flow.proto,
        flow.srcAddr,
        flow.dstAddr,
        flow.srcPort ?? null,
        flow.dstPort ?? null,
        flow.firstMs,
        flow.lastMs,
        flow.mergedRecordCount,
      ]),
    )
    .digest("hex");
  return boundedAggKey(`exporter-flow|${reportFingerprint}|flow|${findingId}`);
}

function mapFlow(flow: MergedFlow, reportFingerprint: string, sink: Map<string, SiemIoc>): MappedEvent {
  const aggKey = flowAggKey(reportFingerprint, flow);
  if (!isInternalIp(flow.dstAddr)) {
    const rowSink = new Map<string, SiemIoc>();
    addIoc(rowSink, "ip", flow.dstAddr);
    mergeRowIocs(sink, rowSink, aggKey);
  }

  const reportTag = `; report ${reportFingerprint.slice(0, 16)}`;
  const portPart = flow.dstPort !== undefined ? `:${flow.dstPort}` : "";
  const dupPart = flow.possibleDuplicateExporterCount
    ? `; ${flow.possibleDuplicateExporterCount} possible duplicate exporter observation(s)`
    : "";
  const body = clip(
    `nfdump exporter flow: ${flow.srcAddr} -> ${flow.dstAddr}${portPart} (proto ${flow.proto}) — ` +
      `${flow.inBytes} byte(s)/${flow.inPackets} packet(s)${flow.sampled ? " (sampled, an estimate)" : ""}, ` +
      `${flow.mergedRecordCount} record(s) merged${dupPart}; a structural fact, never a current-state verdict`,
    600 - reportTag.length,
  );
  const description = `${body}${reportTag}`;

  return {
    timestamp: new Date(flow.firstMs).toISOString(),
    description,
    severity: "Info",
    mitre: [],
    aggKey,
    sources: ["nfdump"],
    srcIp: flow.srcAddr,
    dstIp: flow.dstAddr,
    ...(flow.dstPort !== undefined ? { port: flow.dstPort } : {}),
    canonical: createCanonicalEvent({
      event: { category: "network", type: "exporter-flow", action: "found" },
      time: {
        observed: new Date(flow.firstMs).toISOString(),
        normalized: new Date(flow.firstMs).toISOString(),
      },
      evidence: { rawRecords: [{ source: "exporter-flow", locator: `flow:${aggKey.slice(0, 24)}` }] },
      network: {
        source: {
          address: flow.srcAddr,
          provenance: "edge-observed",
          ...(flow.srcPort !== undefined ? { port: flow.srcPort } : {}),
        },
        destination: { address: flow.dstAddr, ...(flow.dstPort !== undefined ? { port: flow.dstPort } : {}) },
      },
      producer: { importer: "exporter-flow", parserVersion: "1", mappingVersion: "exporter-flow-v1" },
      exporterFlow: {
        tool: "nfdump",
        initiatingDirection: initiatingDirectionOf(flow),
        exporterSysId: flow.exporterSysId,
        ...(flow.observationPointId !== undefined ? { observationPointId: flow.observationPointId } : {}),
        proto: flow.proto,
        srcAddr: flow.srcAddr,
        dstAddr: flow.dstAddr,
        ...(flow.srcPort !== undefined ? { srcPort: flow.srcPort } : {}),
        ...(flow.dstPort !== undefined ? { dstPort: flow.dstPort } : {}),
        inBytes: flow.inBytes,
        inPackets: flow.inPackets,
        sampled: flow.sampled,
        mergedRecordCount: flow.mergedRecordCount,
        possibleDuplicateExporterCount: flow.possibleDuplicateExporterCount,
        reportFingerprint,
        mappingVersion: "exporter-flow-v1",
        basis: EXPORTER_FLOW_BASIS,
      },
    }),
  };
}

function mapBeaconLead(candidate: BeaconCandidate, reportFingerprint: string): MappedEvent {
  const findingId = createHash("sha256")
    .update(
      JSON.stringify([
        reportFingerprint,
        "beacon-lead",
        candidate.source,
        candidate.destIp,
        candidate.destPort ?? null,
        candidate.firstSeen,
        candidate.lastSeen,
      ]),
    )
    .digest("hex");
  const aggKey = boundedAggKey(`exporter-flow|${reportFingerprint}|lead|beacon|${findingId}`);
  const reportTag = `; report ${reportFingerprint.slice(0, 16)}`;
  const portPart = candidate.destPort !== undefined ? `:${candidate.destPort}` : "";
  const body = clip(
    `nfdump exporter-flow periodicity lead: ${candidate.source} -> ${candidate.destIp}${portPart} — ` +
      `${candidate.eventCount} normalized flow(s), ~${candidate.intervalSeconds}s interval, ` +
      `${candidate.jitterPct}% jitter. ${BEACON_CAVEAT}`,
    600 - reportTag.length,
  );
  const description = `${body}${reportTag}`;

  return {
    timestamp: candidate.firstSeen,
    description,
    severity: "Low",
    mitre: [],
    aggKey,
    sources: ["nfdump"],
    dstIp: candidate.destIp,
    ...(candidate.destPort !== undefined ? { port: candidate.destPort } : {}),
    canonical: createCanonicalEvent({
      event: { category: "network", type: "exporter-flow-beacon-lead", action: "flagged" },
      time: { observed: candidate.firstSeen, normalized: candidate.firstSeen },
      evidence: { rawRecords: [{ source: "exporter-flow", locator: `beacon:${findingId.slice(0, 24)}` }] },
      producer: { importer: "exporter-flow", parserVersion: "1", mappingVersion: "exporter-flow-v1" },
      exporterFlowBeaconLead: {
        tool: "nfdump",
        source: clip(candidate.source, MAX_FIELD_LEN),
        destAddr: clip(candidate.destIp, MAX_FIELD_LEN),
        ...(candidate.destPort !== undefined ? { destPort: candidate.destPort } : {}),
        eventCount: candidate.eventCount,
        intervalSeconds: candidate.intervalSeconds,
        jitterPct: candidate.jitterPct,
        reportFingerprint,
        mappingVersion: "exporter-flow-v1",
        basis: EXPORTER_FLOW_BEACON_LEAD_BASIS,
      },
    }),
  };
}

export function parseExporterFlowNdjson(
  text: string,
  opts: ExporterFlowOptions = {},
): ExporterFlowResult | null {
  const lines = text.split(/\r?\n/).filter((l) => l.trim().length > 0);
  if (lines.length === 0) return null;

  let firstValid = false;
  let total = 0;
  let malformedRecords = 0;
  let recordsTruncated = false;
  const parsed: RawRecord[] = [];

  for (const line of lines) {
    if (parsed.length + malformedRecords >= MAX_RECORDS_SCANNED) {
      recordsTruncated = true;
      break;
    }
    let root: unknown;
    try {
      root = JSON.parse(line);
    } catch {
      malformedRecords += 1;
      continue;
    }
    if (!isNfdumpFlowRecord(root)) {
      malformedRecords += 1;
      continue;
    }
    firstValid = true;
    total += 1;
    const rec = parseRecord(root);
    if (!rec) {
      malformedRecords += 1;
      continue;
    }
    parsed.push(rec);
  }

  if (!firstValid) return null;

  // Group by exporter+observation-point+5-tuple, then merge interim re-exports within each group.
  const byExporterTuple = new Map<string, RawRecord[]>();
  for (const r of parsed) {
    const key = tupleKey(r, true);
    const bucket = byExporterTuple.get(key);
    if (bucket) bucket.push(r);
    else byExporterTuple.set(key, [r]);
  }

  const flows: MergedFlow[] = [];
  for (const records of byExporterTuple.values()) flows.push(...mergeGroup(records));

  // Disclosure-only duplicate-exporter detection: same 5-tuple (ignoring exporter), overlapping
  // time window, reported by more than one exporter — never merged away (Codex design review
  // finding: v1's "lower sysid wins" merge was unsound, since this may be the legitimate other
  // direction of a bidirectional conversation instead of a true duplicate).
  const byTupleOnly = new Map<string, MergedFlow[]>();
  for (const f of flows) {
    const key = tupleKey(f, false);
    const bucket = byTupleOnly.get(key);
    if (bucket) bucket.push(f);
    else byTupleOnly.set(key, [f]);
  }
  for (const bucket of byTupleOnly.values()) {
    if (bucket.length < 2) continue;
    // A pairwise check is O(n^2) in the bucket size — safe for the realistic case (a handful of
    // exporters ever see the same conversation), but a crafted upload naming the same tuple under
    // thousands of distinct exporter ids would otherwise defeat MAX_RECORDS_SCANNED as a CPU bound
    // (Codex code review finding). Bounded: skip the disclosure for a pathologically large bucket
    // rather than compute it — every record is still imported and counted, only this one
    // cross-check is foregone, and this is an extreme edge case no real nfdump capture produces.
    if (bucket.length > MAX_DUPLICATE_CHECK_BUCKET) continue;
    for (const f of bucket) {
      const others = bucket.filter(
        (o) =>
          o !== f && o.exporterSysId !== f.exporterSysId && o.firstMs <= f.lastMs && o.lastMs >= f.firstMs,
      );
      // Distinct EXPORTERS, not overlapping-flow count (Codex code review finding: several
      // non-adjacent overlapping windows from the SAME other exporter must count once).
      f.possibleDuplicateExporterCount = new Set(others.map((o) => o.exporterSysId)).size;
    }
  }

  const sink = new Map<string, SiemIoc>();
  const reportFingerprint = createHash("sha256").update(text).digest("hex");
  const mapped: MappedEvent[] = flows.map((f) => mapFlow(f, reportFingerprint, sink));

  // In-memory, at import time, over THIS upload's own normalized flows only — the existing,
  // unmodified detectBeacons() function, never re-implemented (Codex design review's own
  // architecture fix: raw Info-severity flow events alone never reach the default forensic
  // timeline, so any periodicity signal must be lifted into its own bounded, visible lead here).
  // No direction-based exclusion here (Codex code review finding: a SYN+ACK reply flow cannot be
  // reliably told apart from an initiating one via aggregate tcp_flags alone — see
  // initiatingDirectionOf's own comment) — every normalized flow participates in the sweep,
  // matching this importer's own established default-outbound-when-ambiguous convention.
  const syntheticEvents: ForensicEvent[] = flows.map((f, i) => ({
    id: `exporter-flow-synthetic-${i}`,
    timestamp: new Date(f.firstMs).toISOString(),
    description: "",
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    srcIp: f.srcAddr,
    dstIp: f.dstAddr,
    ...(f.dstPort !== undefined ? { port: f.dstPort } : {}),
  }));
  const beaconCandidates = detectBeacons(syntheticEvents);
  const beaconLeads = beaconCandidates.map((c) => mapBeaconLead(c, reportFingerprint));

  const { events, groups } = aggregateEvents([...mapped, ...beaconLeads], {
    aggregate: opts.aggregate,
    minSeverity: "Info",
    maxEvents: opts.maxEvents ?? MAX_RECORDS_SCANNED,
  });

  return {
    events,
    iocs: [...sink.values()],
    total,
    kept: events.length,
    dropped: malformedRecords,
    groups,
    format: "NfdumpFlowNdjson",
    malformedRecords,
    recordsTruncated,
    flowCount: flows.length,
    beaconLeadCount: beaconLeads.length,
  };
}
