// The envelope blocks one nfdump (NetFlow/IPFIX collector) flow record, or a bounded periodicity
// lead built from a set of them, carries (#932 item 10, "933.3"): the exporter's own observed
// start/end for one flow, normalized across interim active-timeout re-exports of the same ongoing
// connection — never asserted as the underlying transport connection's true start, never a
// current-state verdict, and never a substitute for `beaconDetect.ts`'s own periodicity math
// (reused unmodified, never duplicated). Kept beside canonicalEvent.ts so the envelope schema
// stays within its size bound (mirrors canonicalSqliteRowState.ts's own sibling-file pattern,
// #932 item 8).

import { z } from "zod";

export const exporterFlowTools = ["nfdump"] as const;
export type ExporterFlowTool = (typeof exporterFlowTools)[number];

export const MAX_FIELD_LEN = 300;

export const EXPORTER_FLOW_BASIS =
  "the exporter's own observed start/end for this flow record — never asserted as the underlying " +
  "transport connection's true start when an active-timeout split is possible; the export/" +
  "collection time is read but never substituted for it; byte/packet counts are the exporter's " +
  "own report and, when sampled, an estimate scaled by an unknown or approximate rate, never an " +
  "exact count; interim-record merging is a temporal-adjacency heuristic, not a certainty; a " +
  "same-tuple record from a different exporter is disclosed as a possible duplicate, never merged " +
  "away, since it may be the conversation's legitimate other direction instead";

/** Derived from TCP SYN-flag presence (never nfdump's own `direction`, which is ingress/egress at
 * the observation point, not an initiator flag) — "unknown" for UDP/ICMP, which carry no such
 * signal at all. Disclosure only: `ForensicEvent.action` cannot round-trip through this
 * importer's own aggregation path today, so this field is the one place the derived direction
 * actually survives persistence. */
export const exporterFlowDirections = ["outbound", "reply", "unknown"] as const;
export type ExporterFlowDirection = (typeof exporterFlowDirections)[number];

export const exporterFlowBlockSchema = z.object({
  tool: z.enum(exporterFlowTools),
  initiatingDirection: z.enum(exporterFlowDirections),
  exporterSysId: z.number().int().nonnegative(),
  observationPointId: z.number().int().nonnegative().optional(),
  proto: z.number().int().nonnegative(),
  srcAddr: z.string().min(1).max(MAX_FIELD_LEN),
  dstAddr: z.string().min(1).max(MAX_FIELD_LEN),
  srcPort: z.number().int().nonnegative().optional(),
  dstPort: z.number().int().nonnegative().optional(),
  inBytes: z.number().int().nonnegative(),
  inPackets: z.number().int().nonnegative(),
  sampled: z.boolean(),
  mergedRecordCount: z.number().int().positive(),
  possibleDuplicateExporterCount: z.number().int().nonnegative(),
  reportFingerprint: z.string().length(64),
  mappingVersion: z.literal("exporter-flow-v1"),
  basis: z.literal(EXPORTER_FLOW_BASIS),
});
export type ExporterFlowBlock = z.infer<typeof exporterFlowBlockSchema>;

export const EXPORTER_FLOW_BEACON_LEAD_BASIS =
  "a hunting lead from normalized exporter flow data, not a verdict — legitimate software also " +
  "polls on a timer (updates, NTP, telemetry); confirm the destination reputation and the owning " +
  "process; the underlying flow records may themselves carry a normalization heuristic's residual " +
  "uncertainty (interim-record merging, TCP-SYN-based direction inference)";

export const exporterFlowBeaconLeadBlockSchema = z.object({
  tool: z.enum(exporterFlowTools),
  source: z.string().min(1).max(MAX_FIELD_LEN),
  destAddr: z.string().min(1).max(MAX_FIELD_LEN),
  destPort: z.number().int().nonnegative().optional(),
  eventCount: z.number().int().positive(),
  intervalSeconds: z.number().nonnegative(),
  jitterPct: z.number().nonnegative(),
  reportFingerprint: z.string().length(64),
  mappingVersion: z.literal("exporter-flow-v1"),
  basis: z.literal(EXPORTER_FLOW_BEACON_LEAD_BASIS),
});
export type ExporterFlowBeaconLeadBlock = z.infer<typeof exporterFlowBeaconLeadBlockSchema>;
