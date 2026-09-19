// Deterministic importer for Google Cloud VPC Flow Logs (#931 item 13 second half, #1294), read
// from a Cloud Logging export (Logs Explorer download or a sink): one `LogEntry` per record, the
// record itself under `jsonPayload`. Sibling of awsFlowLogImport.ts / azureFlowLogImport.ts.
//
// Schema (fetched live from docs.cloud.google.com/vpc/docs/about-flow-logs-records and
// access-flow-logs, 2026-09-18 — not recalled). `logName` ends in `vpc_flows` under either
// `compute.googleapis.com` (resource.type gce_subnetwork) or `networkmanagement.googleapis.com`
// (resource.type vpc_flow_logs_config). `jsonPayload.connection` is the 5-tuple (`protocol` is the
// IANA number; ports exist for TCP/UDP only). `reporter` is SRC|DEST|SRC_GATEWAY|DEST_GATEWAY.
// `start_time`/`end_time` are RFC 3339 (first/last observed packet). `bytes_sent`/`packets_sent`
// are int64 — Cloud Logging exports int64 as JSON STRINGS, so both shapes are accepted.
// `disposition: "DROPPED"` marks a drop record, which carries `drop_reason` and
// `bytes_dropped`/`packets_dropped` and NOT `bytes_sent` — a dropped row prints the dropped
// counters and never fabricates a zero for a field the platform did not populate.
//
// WHAT AN INSTANCE NAME IN A ROW IS. `src_instance`/`dest_instance`/`src_vpc`/`dest_vpc`/
// `*_gke_details` are Google's OWN metadata annotations, written at log time and present only
// when annotations are enabled. This importer prints them as "(Google's annotation)" and never
// joins anything itself; a side with no annotation says "no instance annotation" so absence is
// never read as "not a VM". `cloud.accountId` is the EMITTING project (resource.labels.project_id,
// else the logName's project token) — never an annotation, so identity does not depend on
// whether annotations were on. `cloud.region`/`resource` are the reporter side's annotated
// region/vm_name when present.
//
// NEVER CLAIMED. A byte total comparable to Azure/AWS: `bytes_sent` is user PAYLOAD (no headers)
// and the row says "payload byte(s)". Absence of a flow: VPC Flow Logs are SAMPLED at a
// configurable rate, so a flow that does not appear is never evidence of no traffic (the import
// note says so). A non-dropped record carries no allow/deny verdict, so `event.action` is
// `observed` (or `dropped`) — a per-provider vocabulary nothing gates on. Reporter, disposition,
// counters and start/end are description-only in this slice. A routable IPv6 endpoint makes a
// row, never an IOC. Round-trip time, load-balancer, PSC, gateway and serverless metadata are
// not read. Not fed to beaconDetect.ts (interval rows read as low-jitter beacons).
//
// AGGREGATION. Every entry carries a measurement, so the key includes `start_time` — only an
// exact re-export of the same interval merges. The VPC names, disposition and drop reason are in
// the key as recorded (empty when absent), so identical private 5-tuples in two VPCs of one
// project, or two drop reasons, stay apart whenever the export can tell them apart.
//
// BOUNDS. Detection is by the `vpc_flows` logName wrapper ONLY — `resource.type` is not used,
// because `gce_subnetwork` is shared with firewall-rules logging, whose entries also carry a
// `connection` block. Ports must be <= 65535 (the canonical schema throws on more, and one bad
// entry must never abort the upload, so each row's mapping is also guarded and counted
// `malformed`). `start_time` must lie in [2001, 2242]; an `end_time` before `start_time` is
// dropped from the row rather than printed as an interval. Counters above 2^53 are `malformed`,
// never rounded. Free text (drop reason, instance/project/zone/VPC/pod names) is bounded AND
// stripped of brackets before the row is composed, so the counters, times and both per-side
// annotation brackets always fit and no logged string can print as a "[<name>: …]" derived note
// (#1388). `project_id` must match GCP's own project-id grammar (6–30 chars, `[a-z][a-z0-9-]*`,
// no trailing hyphen) or it is not the account — the row keeps, like an Azure record whose
// subscription is not a GUID. `insertId` is an evidence pointer: over the text bound it is
// `malformed`, never clipped into a pointer that no longer names the record (#1371).
//
// Pure, deterministic, NO AI call.

import type { Severity } from "./stateTypes.js";
import { createCanonicalEvent } from "./canonicalEvent.js";
import { boundedAggKey, boundedTextTo, stripNoteBrackets } from "./aggKey.js";
import { isInternalIpv4 } from "./internalIp.js";
import {
  addIoc,
  cleanIp,
  extractRecords,
  getCI,
  isObject,
  str,
  type SiemEvent,
  type SiemIoc,
  type MappedEvent,
  aggregateEvents,
  maxEventsDefault,
} from "./siemImport.js";

type Row = Record<string, unknown>;

export interface GcpFlowLogImportOptions {
  aggregate?: boolean;
  minSeverity?: Severity;
  maxEvents?: number;
  maxIocs?: number;
}

export interface GcpFlowLogParseResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  total: number;
  kept: number;
  dropped: number;
  groups: number;
  format: string;
  malformed: number;
  /** LogEntry objects in the same export that are not vpc_flows records — skipped, never malformed. */
  nonFlow: number;
  droppedRecords: number;
  noReporterInstance: number;
}

const REPORTERS = new Set(["SRC", "DEST", "SRC_GATEWAY", "DEST_GATEWAY"]);
const PROTOCOL_NAMES: Record<string, string> = {
  "1": "icmp",
  "6": "tcp",
  "17": "udp",
  "47": "gre",
  "50": "esp",
  "58": "icmpv6",
};
const MIN_MILLIS = 1_000_000_000_000;
const MAX_MILLIS = 8_640_000_000_000;
const MAX_PORT = 65535;
const DESCRIPTION_MAX = 600;
const TEXT_MAX = 64;
const LOGNAME_PROJECT_RE = /^projects\/([^/]+)\/logs\//i;
// GCP project ids: 6–30 lowercase letters, digits and hyphens, starting with a letter, not ending
// in a hyphen (cloud.google.com/resource-manager/docs/creating-managing-projects). An AWS account
// number or an arbitrary label never matches, so it never becomes cloud.accountId.
const PROJECT_ID_RE = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/;

interface Instance {
  project: string;
  region: string;
  zone: string;
  vm: string;
}

interface Flow {
  src: string;
  dst: string;
  srcPort: number;
  dstPort: number;
  protocol: string;
  reporter: string;
  startMs: number;
  endIso: string;
  dropped: boolean;
  dropReason: string;
  insertId: string;
  packets: number | null;
  bytes: number | null;
  srcInstance: Instance | null;
  dstInstance: Instance | null;
  srcVpc: string;
  dstVpc: string;
  srcGke: string;
  dstGke: string;
}

/** A non-negative integer from a JSON number or a digit string (int64 export shape); null when absent; NaN when malformed. */
function int(v: unknown): number | null {
  if (v === undefined || v === null || v === "") return null;
  if (typeof v === "number") return Number.isSafeInteger(v) && v >= 0 ? v : NaN;
  if (typeof v === "string" && /^\d+$/.test(v.trim())) {
    const n = Number(v.trim());
    return Number.isSafeInteger(n) ? n : NaN;
  }
  return NaN;
}

/** Free text bound for the description: brackets stripped first, then the length bound. */
const text = (v: unknown) => boundedTextTo(stripNoteBrackets(str(v).trim()), TEXT_MAX);

/** The value when it is a GCP project id by grammar, else "" — never a bounded or clipped one. */
const projectId = (v: unknown) => {
  const id = str(v).trim();
  return PROJECT_ID_RE.test(id) ? id : "";
};

function instance(v: unknown): Instance | null {
  if (!isObject(v)) return null;
  const vm = text(getCI(v, "vm_name"));
  if (!vm) return null;
  return {
    project: text(getCI(v, "project_id")),
    region: text(getCI(v, "region")),
    zone: text(getCI(v, "zone")),
    vm,
  };
}

function gke(v: unknown): string {
  if (!isObject(v)) return "";
  const pod = getCI(v, "pod");
  const cluster = getCI(v, "cluster");
  const podName = isObject(pod) ? text(getCI(pod, "pod_name")) : "";
  const ns = isObject(pod) ? text(getCI(pod, "pod_namespace")) : "";
  const clusterName = isObject(cluster) ? text(getCI(cluster, "cluster_name")) : "";
  if (!podName) return "";
  return `${ns ? `${ns}/` : ""}${podName}${clusterName ? ` (cluster ${clusterName})` : ""}`;
}

function decodedLogName(entry: Row): string {
  return str(getCI(entry, "logName")).replace(/%2F/gi, "/").trim();
}

/**
 * True when a LogEntry is a vpc_flows record by its own wrapper — the `vpc_flows` logName plus a
 * `jsonPayload` object. Never by `resource.type` (gce_subnetwork is shared with firewall-rules
 * logging, whose entries also carry a `connection`), never by payload shape alone. A claimed entry
 * whose payload then fails validation is `malformed`, not `nonFlow`.
 */
export function isGcpFlowLogEntry(entry: Row): boolean {
  return isObject(getCI(entry, "jsonPayload")) && /\/vpc_flows$/i.test(decodedLogName(entry));
}

/** Reads one entry's flow, or null (malformed). */
function parseEntry(entry: Row): Flow | null {
  const p = getCI(entry, "jsonPayload") as Row;
  const connRaw = getCI(p, "connection");
  if (!isObject(connRaw)) return null;
  const conn = connRaw;
  const src = cleanIp(str(getCI(conn, "src_ip")));
  const dst = cleanIp(str(getCI(conn, "dest_ip")));
  const srcPort = int(getCI(conn, "src_port"));
  const dstPort = int(getCI(conn, "dest_port"));
  const protocol = int(getCI(conn, "protocol"));
  if (
    !src ||
    !dst ||
    Number.isNaN(srcPort) ||
    Number.isNaN(dstPort) ||
    protocol === null ||
    Number.isNaN(protocol)
  )
    return null;
  if ((srcPort ?? 0) > MAX_PORT || (dstPort ?? 0) > MAX_PORT) return null;
  const reporter = str(getCI(p, "reporter")).trim().toUpperCase();
  if (!REPORTERS.has(reporter)) return null;
  const startMs = Date.parse(str(getCI(p, "start_time")));
  if (!Number.isFinite(startMs) || startMs < MIN_MILLIS || startMs > MAX_MILLIS) return null;
  const endMs = Date.parse(str(getCI(p, "end_time")));
  const dropped = str(getCI(p, "disposition")).trim().toUpperCase() === "DROPPED";
  const packets = int(getCI(p, dropped ? "packets_dropped" : "packets_sent"));
  const bytes = int(getCI(p, dropped ? "bytes_dropped" : "bytes_sent"));
  if (Number.isNaN(packets) || Number.isNaN(bytes)) return null;
  const insertId = str(getCI(entry, "insertId")).trim();
  if (insertId.length > TEXT_MAX) return null;
  const vpc = (v: unknown) => (isObject(v) ? text(getCI(v, "vpc_name")) : "");
  return {
    src,
    dst,
    srcPort: srcPort ?? 0,
    dstPort: dstPort ?? 0,
    protocol: String(protocol),
    reporter,
    startMs,
    endIso:
      Number.isFinite(endMs) && endMs >= startMs && endMs <= MAX_MILLIS ? new Date(endMs).toISOString() : "",
    dropped,
    dropReason: text(getCI(p, "drop_reason")),
    insertId,
    packets,
    bytes,
    srcInstance: instance(getCI(p, "src_instance")),
    dstInstance: instance(getCI(p, "dest_instance")),
    srcVpc: vpc(getCI(p, "src_vpc")),
    dstVpc: vpc(getCI(p, "dest_vpc")),
    srcGke: gke(getCI(p, "src_gke_details")),
    dstGke: gke(getCI(p, "dest_gke_details")),
  };
}

function endpoint(ip: string, port: number): string {
  return port > 0 ? `${ip}:${port}` : ip;
}

/** Public unicast IPv4 only: not internal, not multicast/reserved/broadcast (224.0.0.0/3) — a v6 peer is never an IOC. */
function isIocCandidate(ip: string): boolean {
  const m = /^(\d+)\.\d+\.\d+\.\d+$/.exec(ip);
  return !!m && Number(m[1]) < 224 && !isInternalIpv4(ip);
}

function emittingProject(entry: Row): string {
  const resource = getCI(entry, "resource");
  const labels = isObject(resource) ? getCI(resource, "labels") : undefined;
  const fromLabels = isObject(labels) ? projectId(getCI(labels, "project_id")) : "";
  return fromLabels || projectId(LOGNAME_PROJECT_RE.exec(decodedLogName(entry))?.[1]);
}

/** Probative fields first; annotation brackets appended whole only while the bound holds. */
function describe(f: Flow): string {
  const protoName = PROTOCOL_NAMES[f.protocol] ?? f.protocol;
  const verdict = f.dropped ? `dropped${f.dropReason ? `: ${f.dropReason}` : ""}` : "observed";
  const tail = f.dropped ? " dropped" : "";
  const counters = [
    f.packets === null ? "" : `${f.packets} packet(s)${tail}`,
    f.bytes === null ? "" : `${f.bytes} payload byte(s)${tail}`,
  ]
    .filter(Boolean)
    .join(", ");
  const times = `${new Date(f.startMs).toISOString()}${f.endIso ? `–${f.endIso}` : ""}`;
  let out = `GCP VPC flow (reported by ${f.reporter}): ${endpoint(f.src, f.srcPort)} -> ${endpoint(f.dst, f.dstPort)} (${protoName}) ${verdict} [${[counters, times].filter(Boolean).join(", ")}]`;
  const inst = (side: string, i: Instance | null) =>
    i
      ? `[${side} instance ${i.vm} (${[i.project, i.zone].filter(Boolean).join("/")}, Google's annotation)]`
      : `[${side}: no instance annotation]`;
  const brackets = [
    inst("src", f.srcInstance),
    inst("dest", f.dstInstance),
    f.srcVpc ? `[src vpc ${f.srcVpc}]` : "",
    f.dstVpc ? `[dest vpc ${f.dstVpc}]` : "",
    f.srcGke ? `[src gke pod ${f.srcGke}]` : "",
    f.dstGke ? `[dest gke pod ${f.dstGke}]` : "",
  ].filter(Boolean);
  for (const b of brackets) {
    if (out.length + 1 + b.length > DESCRIPTION_MAX) break;
    out += ` ${b}`;
  }
  return boundedTextTo(out, DESCRIPTION_MAX);
}

function mapFlow(f: Flow, entry: Row, index: number, sink: Map<string, SiemIoc>): MappedEvent {
  const protoName = PROTOCOL_NAMES[f.protocol] ?? f.protocol;
  const observed = new Date(f.startMs).toISOString();
  for (const ip of [f.src, f.dst]) if (isIocCandidate(ip)) addIoc(sink, "ip", ip);
  const reporterSide = f.reporter.startsWith("SRC") ? f.srcInstance : f.dstInstance;
  const project = emittingProject(entry);
  const srcPortField = f.srcPort > 0 ? f.srcPort : undefined;
  const dstPortField = f.dstPort > 0 ? f.dstPort : undefined;

  return {
    timestamp: observed,
    description: describe(f),
    severity: "Low",
    mitre: [],
    aggKey: boundedAggKey(
      `gcp-flow|${project}|${f.reporter}|${f.srcVpc}|${f.dstVpc}|${f.src}|${f.dst}|${f.srcPort}|${f.dstPort}|${f.protocol}|${f.dropped ? `dropped:${f.dropReason}` : "observed"}|${f.startMs}`.toLowerCase(),
    ),
    sources: ["GCP VPC Flow Logs"],
    srcIp: f.src,
    dstIp: f.dst,
    ...(dstPortField ? { port: dstPortField } : {}),
    canonical: createCanonicalEvent({
      event: { category: "network", type: "flow", action: f.dropped ? "dropped" : "observed" },
      network: {
        source: {
          address: f.src,
          provenance: "edge-observed",
          ...(srcPortField ? { port: srcPortField } : {}),
        },
        destination: { address: f.dst, ...(dstPortField ? { port: dstPortField } : {}) },
        protocol: protoName,
      },
      cloud: {
        provider: "gcp",
        ...(project ? { accountId: project } : {}),
        ...(reporterSide?.region ? { region: reporterSide.region } : {}),
        ...(reporterSide ? { resource: reporterSide.vm } : {}),
      },
      time: { observed, normalized: observed },
      evidence: {
        rawRecords: [
          {
            source: "gcp-vpc-flow-log",
            locator: `entry:${index}${f.insertId ? `/insertId:${f.insertId}` : ""}`,
          },
        ],
      },
      producer: {
        importer: "gcp-vpc-flow-log",
        parserVersion: "1",
        mappingVersion: "gcp-vpc-flow-log-v1",
        ruleVersions: ["gcp-vpc-flow-log-v1"],
      },
    }),
  };
}

export function parseGcpFlowLog(text: string, opts: GcpFlowLogImportOptions = {}): GcpFlowLogParseResult {
  const { records } = extractRecords(text);
  const sink = new Map<string, SiemIoc>();
  const mapped: MappedEvent[] = [];
  let malformed = 0;
  let nonFlow = 0;
  let droppedRecords = 0;
  let noReporterInstance = 0;

  records.forEach((entry, index) => {
    if (!isGcpFlowLogEntry(entry)) {
      nonFlow++;
      return;
    }
    const f = parseEntry(entry);
    if (!f) {
      malformed++;
      return;
    }
    // One entry's mapping must never abort the upload: anything the validators missed that the
    // canonical schema rejects is counted here, not thrown out of the whole parse.
    let row: MappedEvent;
    try {
      row = mapFlow(f, entry, index, sink);
    } catch {
      malformed++;
      return;
    }
    if (f.dropped) droppedRecords++;
    if (!(f.reporter.startsWith("SRC") ? f.srcInstance : f.dstInstance)) noReporterInstance++;
    mapped.push(row);
  });

  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? maxEventsDefault(),
  });
  const represented = events.reduce((n, e) => n + (e.count ?? 1), 0);

  return {
    events,
    iocs: [...sink.values()].slice(0, opts.maxIocs ?? 5000),
    total: records.length,
    kept: events.length,
    dropped: Math.max(0, mapped.length - represented),
    groups,
    format: "gcp-vpc-flow-log",
    malformed,
    nonFlow,
    droppedRecords,
    noReporterInstance,
  };
}
