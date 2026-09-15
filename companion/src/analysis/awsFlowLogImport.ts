// Deterministic importer for AWS VPC Flow Logs, default (version 2) format (#931 item 13) —
// the data-plane half of the cloud flow-log-to-resource-lifetime correlation. Existing importers
// already grade the control-plane signal (DeleteFlowLogs, High/T1562.008, in awsImport.ts);
// nothing imported the actual traffic records VPC Flow Logs itself writes.
//
// Schema (fetched live from docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html —
// not recalled), exactly 14 space-separated fields in this order:
//
//   version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes
//   start end action log-status
//
// `protocol` is the IANA protocol number, never a name. `action` is ACCEPT|REJECT — REJECT
// includes packets arriving after a connection closed and is never auto-suspicious on its own.
// `log-status` is OK|NODATA|SKIPDATA, and these are NOT equivalent: NODATA is scoped NEGATIVE
// evidence (nothing crossed this interface in this interval); SKIPDATA is a COLLECTION GAP (AWS
// dropped records — a coverage problem, never read as "no traffic"). Both produce zero events
// and are counted separately from each other and from malformed lines.
//
// `start`/`end` are Unix seconds bounding an aggregation interval (up to 10 minutes, 1 minute on
// Nitro instances) with AWS-documented timing slop up to 60s either side — never a single
// packet's exact time.
//
// Every real (OK, well-formed) record is graded Low, uniformly — ACCEPT/REJECT and internal/
// external alike. Deliberate departure from ecarImport.ts's own `external ? Low : Info` split:
// this row must survive the default per-import demote step for awsFlowResourceAttribution.ts's
// cross-import correlator to have anything to attribute, which ecarImport's endpoint netflow
// never needed.
//
// Not fed into beaconDetect.ts: verified that detector assumes one row per connection occurrence
// and reads the row's own timestamp as that occurrence's time. A flow-log row aggregates a whole
// interval — AWS's own fixed-interval cadence would read as a textbook low-jitter beacon to that
// detector. A VPC-flow-aware periodicity detector is a real, separate feature, not this one.
//
// Pure, deterministic, NO AI call.

import type { Severity } from "./stateTypes.js";
import { createCanonicalEvent } from "./canonicalEvent.js";
import { boundedAggKey, boundedTextTo } from "./aggKey.js";
import { isInternalIpv4 } from "./internalIp.js";
import {
  addIoc,
  cleanIp,
  type SiemEvent,
  type SiemIoc,
  type MappedEvent,
  aggregateEvents,
  maxEventsDefault,
} from "./siemImport.js";

export interface AwsFlowLogImportOptions {
  aggregate?: boolean;
  minSeverity?: Severity;
  maxEvents?: number;
  maxIocs?: number;
}

// No `hostname` — matches AzureStorageLogParseResult's own precedent (a cloud source, not an
// endpoint import). `nodata`/`skipdata`/`malformed` are tracked separately (Codex review, #931
// item 13): lumping them into one `dropped` count would conflate "no traffic occurred" with
// "AWS lost records" with "the line didn't parse" — three different facts an analyst needs told
// apart.
export interface AwsFlowLogParseResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  total: number;
  kept: number;
  dropped: number;
  groups: number;
  format: string;
  nodata: number;
  skipdata: number;
  malformed: number;
}

const ACTIONS = new Set(["ACCEPT", "REJECT"]);
const LOG_STATUSES = new Set(["OK", "NODATA", "SKIPDATA"]);
const PROTOCOL_NAMES: Record<string, string> = { "1": "icmp", "6": "tcp", "17": "udp" };

interface FlowRecord {
  accountId: string;
  interfaceId: string;
  srcaddr: string;
  dstaddr: string;
  srcport: number;
  dstport: number;
  protocol: string;
  packets: number;
  bytes: number;
  startSec: number;
  endSec: number;
  action: string;
  logStatus: string;
}

/** Parses and validates one default-format (v2) VPC Flow Log line, or null if malformed/skippable. */
function parseLine(line: string): { record: FlowRecord | null; logStatus: string | null } {
  const fields = line.trim().split(/\s+/);
  if (fields.length !== 14) return { record: null, logStatus: null };
  const [
    version,
    accountId,
    interfaceId,
    srcaddr,
    dstaddr,
    srcport,
    dstport,
    protocol,
    packets,
    bytes,
    start,
    end,
    action,
    logStatus,
  ] = fields;
  if (version !== "2") return { record: null, logStatus: null };
  if (!LOG_STATUSES.has(logStatus)) return { record: null, logStatus: null };
  if (logStatus !== "OK") return { record: null, logStatus };

  if (!ACTIONS.has(action)) return { record: null, logStatus: null };
  const numFields = [srcport, dstport, protocol, packets, bytes, start, end];
  if (numFields.some((f) => f === "-" || !/^\d+$/.test(f))) return { record: null, logStatus: null };
  const startSec = Number(start);
  const endSec = Number(end);
  if (endSec < startSec) return { record: null, logStatus: null };
  const src = cleanIp(srcaddr === "-" ? "" : srcaddr);
  const dst = cleanIp(dstaddr === "-" ? "" : dstaddr);
  if (!src || !dst) return { record: null, logStatus: null };

  return {
    record: {
      accountId: accountId === "-" ? "" : accountId,
      interfaceId: interfaceId === "-" ? "" : interfaceId,
      srcaddr: src,
      dstaddr: dst,
      srcport: Number(srcport),
      dstport: Number(dstport),
      protocol,
      packets: Number(packets),
      bytes: Number(bytes),
      startSec,
      endSec,
      action,
      logStatus,
    },
    logStatus,
  };
}

function mapFlowRecord(r: FlowRecord, sink: Map<string, SiemIoc>, recordIndex: number): MappedEvent {
  const protoName = PROTOCOL_NAMES[r.protocol] ?? r.protocol;
  const observed = new Date(r.startSec * 1000).toISOString();
  const endObserved = new Date(r.endSec * 1000).toISOString();
  if (!isInternalIpv4(r.dstaddr)) addIoc(sink, "ip", r.dstaddr);
  if (!isInternalIpv4(r.srcaddr)) addIoc(sink, "ip", r.srcaddr);

  const description = boundedTextTo(
    `AWS VPC flow: ${r.srcaddr}:${r.srcport} -> ${r.dstaddr}:${r.dstport} (${protoName}) ${r.action}` +
      ` [${r.packets} packet(s), ${r.bytes} byte(s), interval ${observed}–${endObserved}]`,
    600,
  );

  return {
    timestamp: observed,
    description,
    severity: "Low",
    mitre: [],
    // Deliberately excludes time — repeated identical 5-tuple flows collapse into one counted
    // row via the shared aggregator's `count`, same shape as ecarImport.ts's own FLOW/CONNECT.
    aggKey: boundedAggKey(
      `aws-flow|${r.accountId}|${r.srcaddr}|${r.dstaddr}|${r.srcport}|${r.dstport}|${r.protocol}|${r.action}`.toLowerCase(),
    ),
    sources: ["AWS VPC Flow Logs"],
    srcIp: r.srcaddr,
    dstIp: r.dstaddr,
    port: r.dstport,
    canonical: createCanonicalEvent({
      event: { category: "network", type: "flow", action: r.action.toLowerCase() },
      network: {
        source: { address: r.srcaddr, port: r.srcport },
        destination: { address: r.dstaddr, port: r.dstport },
        protocol: protoName,
      },
      cloud: { provider: "aws", ...(r.accountId ? { accountId: r.accountId } : {}) },
      time: { observed, normalized: observed },
      evidence: { rawRecords: [{ source: "aws-vpc-flow-log", locator: `record:${recordIndex}` }] },
      producer: {
        importer: "aws-vpc-flow-log",
        parserVersion: "1",
        mappingVersion: "aws-vpc-flow-log-v1",
        ruleVersions: ["aws-vpc-flow-log-v1"],
      },
    }),
  };
}

export function parseAwsFlowLog(text: string, opts: AwsFlowLogImportOptions = {}): AwsFlowLogParseResult {
  const lines = text.split(/\r?\n/).filter((l) => l.trim().length > 0);
  const sink = new Map<string, SiemIoc>();
  const mapped: MappedEvent[] = [];
  let nodata = 0;
  let skipdata = 0;
  let malformed = 0;

  lines.forEach((line, index) => {
    const { record, logStatus } = parseLine(line);
    if (record) {
      mapped.push(mapFlowRecord(record, sink, index));
    } else if (logStatus === "NODATA") {
      nodata++;
    } else if (logStatus === "SKIPDATA") {
      skipdata++;
    } else {
      malformed++;
    }
  });

  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? maxEventsDefault(),
  });

  const represented = events.reduce((n, e) => n + (e.count ?? 1), 0);
  const maxIocs = opts.maxIocs ?? 5000;

  return {
    events,
    iocs: [...sink.values()].slice(0, maxIocs),
    total: lines.length,
    kept: events.length,
    dropped: Math.max(0, mapped.length - represented),
    groups,
    format: "aws-vpc-flow-log",
    nodata,
    skipdata,
    malformed,
  };
}

/** True for a plain-text default-format VPC Flow Log line — used by importDetect.ts. */
export function isAwsFlowLogLine(sample: string): boolean {
  const fields = sample.trim().split(/\s+/);
  return fields.length === 14 && fields[0] === "2" && LOG_STATUSES.has(fields[13]);
}
