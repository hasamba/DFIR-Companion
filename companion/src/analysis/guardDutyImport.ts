// Deterministic importer for Amazon GuardDuty findings (#2361) — a hand-dropped export or the pages
// the live AWS collector saved. No AI call. Each finding becomes ONE row graded by GuardDuty's own
// severity (guardDutyRecord.ts bands); an archived finding stays Info, so it lands in the
// super-timeline only, with "archived" in its description. MITRE comes from the finding type where
// the type establishes a technique. The remote address of the finding's action becomes an IP IOC
// and a DNS request's domain a domain IOC.
//
// Every string here (title, description, resource names, domains) is the finding's — adversary
// reachable — so each goes through oneLine and a bound before it reaches a row. No Sigma rule reads
// GuardDuty findings, and no Cloud Coverage draft is made for them.

import type { Severity } from "./stateTypes.js";
import { boundedAggKey, boundedTextTo } from "./aggKey.js";
import {
  addIoc,
  aggregateEvents,
  cleanIp,
  getCI,
  getPath,
  isObject,
  maxEventsDefault,
  normalizeTime,
  oneLine,
  str,
  type MappedEvent,
  type SiemEvent,
  type SiemIoc,
} from "./siemImport.js";
import type { ImportDebugRecorder } from "./importDebug.js";
import { gateRows, isDuplicateRecord, type CloudRecordParseOptions } from "./cloudRecordGate.js";
import type { CloudCoverageDraft } from "./cloudCoverage.js";
import type { JsonRepairs } from "./tolerantJson.js";
import {
  guardDutyMitre,
  guardDutyScore,
  guardDutySeverity,
  guardDutyVersion,
  isArchived,
  isGuardDutyFinding,
  readGuardDutyRecords,
} from "./guardDutyRecord.js";

type Row = Record<string, unknown>;

import { GUARDDUTY_SOURCE } from "./vendorGrade.js";
export { GUARDDUTY_SOURCE };
const TITLE_MAX = 200;
const RESOURCE_MAX = 160;
const MESSAGE_MAX = 4000;

export interface GuardDutyImportOptions extends CloudRecordParseOptions {
  aggregate?: boolean;
  minSeverity?: Severity;
  maxEvents?: number;
  maxIocs?: number;
  debug?: ImportDebugRecorder;
}

export interface GuardDutyParseResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  total: number;
  kept: number;
  dropped: number;
  groups: number;
  format: string; // "guardduty" | "empty"
  coverage: CloudCoverageDraft[]; // always empty: the Cloud Coverage panel does not read findings
  repairs?: JsonRepairs;
  /** Findings that carried no usable numeric severity (graded Low), disclosed in the note. */
  missingSeverity: number;
  /** Records that were not GuardDuty findings, never mapped. */
  unrecognized: number;
  mapped?: MappedEvent[];
  rowRecords?: number[];
}

const clean = (v: unknown, max: number): string => boundedTextTo(oneLine(str(v)), max);
const at = (rec: Row, path: string): string => str(getPath(rec, path)).trim();

/** The affected resource in a few words: its type and the identifier an analyst looks for. */
export function guardDutyResource(rec: Row): string {
  const type = at(rec, "Resource.ResourceType");
  const bucket = getPath(rec, "Resource.S3BucketDetails");
  const id =
    at(rec, "Resource.InstanceDetails.InstanceId") ||
    at(rec, "Resource.AccessKeyDetails.UserName") ||
    at(rec, "Resource.AccessKeyDetails.PrincipalId") ||
    (Array.isArray(bucket) && isObject(bucket[0]) ? str(getCI(bucket[0], "Name")) : "") ||
    at(rec, "Resource.EksClusterDetails.Name") ||
    at(rec, "Resource.KubernetesDetails.KubernetesWorkloadDetails.Name") ||
    at(rec, "Resource.EcsClusterDetails.Name") ||
    at(rec, "Resource.LambdaDetails.FunctionName") ||
    at(rec, "Resource.RdsDbInstanceDetails.DbInstanceIdentifier") ||
    at(rec, "Resource.ContainerDetails.Name");
  return clean([type, id].filter(Boolean).join(" "), RESOURCE_MAX);
}

const ACTIONS = [
  "NetworkConnectionAction",
  "AwsApiCallAction",
  "KubernetesApiCallAction",
  "RdsLoginAttemptAction",
] as const;

/** The remote IPv4 address of the finding's action, when it names one. */
export function guardDutyRemoteIp(rec: Row): string {
  for (const a of ACTIONS) {
    const ip = cleanIp(at(rec, `Service.Action.${a}.RemoteIpDetails.IpAddressV4`));
    if (ip) return ip;
  }
  const probes = getPath(rec, "Service.Action.PortProbeAction.PortProbeDetails");
  if (Array.isArray(probes))
    for (const p of probes)
      if (isObject(p)) {
        const ip = cleanIp(str(getPath(p, "RemoteIpDetails.IpAddressV4")).trim());
        if (ip) return ip;
      }
  return "";
}

function describe(rec: Row, type: string, score: number | null, archived: boolean): string {
  const title = clean(getCI(rec, "Title"), TITLE_MAX);
  const resource = guardDutyResource(rec);
  const where = [at(rec, "AccountId") && `account ${at(rec, "AccountId")}`, at(rec, "Region")]
    .filter(Boolean)
    .join(", ");
  const sev = score === null ? "severity not given" : `severity ${score}`;
  return clean(
    `GuardDuty finding ${type}${title ? `: ${title}` : ""}${resource ? ` — ${resource}` : ""} (${[where, sev]
      .filter(Boolean)
      .join(", ")})${archived ? ", archived" : ""}`,
    600,
  );
}

function detail(rec: Row): string {
  const parts = [
    clean(getCI(rec, "Description"), 1500),
    `Finding ${at(rec, "Id")}`,
    at(rec, "Arn") && `ARN ${at(rec, "Arn")}`,
    at(rec, "Service.Count") && `seen ${at(rec, "Service.Count")} time(s)`,
    at(rec, "Service.EventFirstSeen") && `first seen ${at(rec, "Service.EventFirstSeen")}`,
    at(rec, "Service.EventLastSeen") && `last seen ${at(rec, "Service.EventLastSeen")}`,
    at(rec, "CreatedAt") && `created ${at(rec, "CreatedAt")}`,
    at(rec, "UpdatedAt") && `updated ${at(rec, "UpdatedAt")}`,
  ];
  return clean(parts.filter(Boolean).join("; "), MESSAGE_MAX);
}

/** One finding → one row, or null when it has no type (counted by the caller). */
export function mapGuardDutyFinding(rec: Row, sink: Map<string, SiemIoc>): MappedEvent | null {
  const type = clean(getCI(rec, "Type"), 200);
  if (!type) return null;
  const score = guardDutyScore(rec);
  const archived = isArchived(rec);
  const ip = guardDutyRemoteIp(rec);
  const domain = clean(getPath(rec, "Service.Action.DnsRequestAction.Domain"), 253);
  if (ip) addIoc(sink, "ip", ip);
  if (domain) addIoc(sink, "domain", domain);
  const time = normalizeTime(at(rec, "Service.EventFirstSeen") || at(rec, "CreatedAt"));
  const key = ["guardduty", at(rec, "AccountId"), at(rec, "Region"), at(rec, "Id"), guardDutyVersion(rec)];
  const resource = guardDutyResource(rec);
  return {
    timestamp: time,
    description: describe(rec, type, score, archived),
    severity: guardDutySeverity(score, archived),
    mitre: guardDutyMitre(type),
    aggKey: boundedAggKey(key.join("|")),
    sourceRecordId: boundedAggKey(key.join(":")),
    message: detail(rec),
    sources: [GUARDDUTY_SOURCE],
    ...(ip ? { srcIp: ip } : {}),
    ...(resource ? { asset: resource } : {}),
  };
}

/** Parse a GuardDuty findings export (or the records the ingest layer pre-read). */
export function parseGuardDuty(text: string, opts: GuardDutyImportOptions = {}): GuardDutyParseResult {
  const { records, repairs } = opts.records
    ? { records: opts.records, repairs: opts.repairs }
    : readGuardDutyRecords(text);
  const total = records.length;
  const gate = opts.recordGate;
  const sink = new Map<string, SiemIoc>();
  const mapped: MappedEvent[] = [];
  const rowRecords: number[] = [];
  let missingSeverity = 0;
  let unrecognized = 0;
  records.forEach((rec, i) => {
    if (isDuplicateRecord(gate, i)) return;
    if (!isGuardDutyFinding(rec)) {
      unrecognized++;
      opts.debug?.skipped("unrecognized_record");
      return;
    }
    const row = mapGuardDutyFinding(rec, sink);
    if (!row) return;
    if (guardDutyScore(rec) === null) {
      missingSeverity++;
      opts.debug?.observed("missing_severity");
    }
    for (const r of gateRows(gate, i, [row])) {
      mapped.push(r);
      rowRecords.push(i);
    }
  });
  const iocs = [...sink.values()].slice(0, opts.maxIocs ?? 5000);
  const base = { iocs, total, coverage: [], repairs, missingSeverity, unrecognized };
  const format = mapped.length ? "guardduty" : "empty";
  if (opts.rowsOnly)
    return { ...base, events: [], kept: 0, dropped: 0, groups: 0, format, mapped, rowRecords };
  if (!mapped.length) return { ...base, events: [], kept: 0, dropped: total, groups: 0, format };
  const aggregated = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? maxEventsDefault(),
    provenance: opts.provenance,
  });
  const represented = aggregated.events.reduce((n, e) => n + (e.count ?? 1), 0);
  return {
    ...base,
    events: aggregated.events,
    kept: aggregated.events.length,
    dropped: Math.max(0, total - represented),
    groups: aggregated.groups,
    format,
  };
}

/** The import note's extra clauses: unrecognised records and findings without a severity. */
export function guardDutyNoteDetail(
  r: Pick<GuardDutyParseResult, "missingSeverity" | "unrecognized">,
): string {
  return [
    r.missingSeverity ? `${r.missingSeverity} finding(s) with no numeric severity, graded Low` : "",
    r.unrecognized ? `${r.unrecognized} record(s) that are not GuardDuty findings, not read` : "",
  ]
    .filter(Boolean)
    .join(", ");
}
