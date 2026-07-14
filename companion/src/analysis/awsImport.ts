// Deterministic importer for AWS CloudTrail logs — cloud IR. The ninth deterministic ingest
// path; no AI call.
//
// CloudTrail delivers JSON: the native `{ "Records": [ … ] }` envelope, NDJSON (CloudTrail
// Lake / Athena), or a plain array. Each record is an API call with no maliciousness score,
// so — like the SIEM/M365 importers — severity is DERIVED from the action: a curated table of
// high-risk `eventName`s (IAM persistence/priv-esc, CloudTrail/GuardDuty/flow-log tampering,
// S3 exposure, secrets access, AMI/snapshot sharing) maps to High/Medium + MITRE. On top of
// that, a present `errorCode` (AccessDenied / UnauthorizedOperation = a probe/attempt) bumps
// severity, `userIdentity.type == Root` is treated as notable, and a failed ConsoleLogin is a
// brute-force signal. The caller `sourceIPAddress` becomes an IOC; the principal is surfaced
// in the description. NOT a detection engine — the same deterministic mapping pattern.

import type { Severity } from "./stateTypes.js";
import {
  extractRecords,
  aggregateEvents,
  cleanIp,
  addIoc,
  worst,
  str,
  isObject,
  getCI,
  getPath,
  oneLine,
  normalizeTime,
  type MappedEvent,
  type SiemEvent,
  type SiemIoc,
  maxEventsDefault,
} from "./siemImport.js";

type Row = Record<string, unknown>;

export interface AwsImportOptions {
  aggregate?: boolean;
  minSeverity?: Severity;
  maxEvents?: number;
  maxIocs?: number;
}

export interface AwsParseResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  total: number;
  kept: number;
  dropped: number;
  groups: number;
  format: string; // "cloudtrail" | "empty"
}

interface ActionDef { severity: Severity; mitre?: string[]; }

// Curated high-risk CloudTrail actions → derived severity + MITRE (keys = lowercased eventName).
const AWS_ACTIONS: Record<string, ActionDef> = {
  consolelogin: { severity: "Info", mitre: ["T1078.004"] },
  // IAM persistence / privilege escalation
  createuser: { severity: "Medium", mitre: ["T1136.003"] },
  createaccesskey: { severity: "High", mitre: ["T1098.001"] },
  createloginprofile: { severity: "High", mitre: ["T1098"] },
  updateloginprofile: { severity: "High", mitre: ["T1098"] },
  attachuserpolicy: { severity: "High", mitre: ["T1098.003"] },
  attachrolepolicy: { severity: "High", mitre: ["T1098.003"] },
  attachgrouppolicy: { severity: "High", mitre: ["T1098.003"] },
  putuserpolicy: { severity: "High", mitre: ["T1098.003"] },
  putrolepolicy: { severity: "High", mitre: ["T1098.003"] },
  putgrouppolicy: { severity: "High", mitre: ["T1098.003"] },
  addusertogroup: { severity: "Medium", mitre: ["T1098"] },
  createrole: { severity: "Medium" },
  updateassumerolepolicy: { severity: "High", mitre: ["T1098"] },
  createpolicyversion: { severity: "High", mitre: ["T1098.003"] },
  setdefaultpolicyversion: { severity: "High", mitre: ["T1098.003"] },
  // iam:PassRole priv-esc primitive + Lambda-based execution/persistence — from the IAM-priv-esc
  // skill (Anthropic-Cybersecurity-Skills `detecting-aws-iam-privilege-escalation`, Apache-2.0).
  passrole: { severity: "Medium", mitre: ["T1098"] },
  createfunction: { severity: "Medium", mitre: ["T1648"] },
  deactivatemfadevice: { severity: "High", mitre: ["T1556"] },
  deletevirtualmfadevice: { severity: "High", mitre: ["T1556"] },
  // Defense evasion — disabling logging / detection
  deletetrail: { severity: "High", mitre: ["T1562.008"] },
  stoplogging: { severity: "High", mitre: ["T1562.008"] },
  updatetrail: { severity: "High", mitre: ["T1562.008"] },
  puteventselectors: { severity: "High", mitre: ["T1562.008"] },
  deleteflowlogs: { severity: "High", mitre: ["T1562.008"] },
  deletedetector: { severity: "High", mitre: ["T1562.001"] },
  updatedetector: { severity: "High", mitre: ["T1562.001"] },
  // Exfil / exposure
  putbucketpolicy: { severity: "High", mitre: ["T1530"] },
  putbucketacl: { severity: "High", mitre: ["T1530"] },
  putobjectacl: { severity: "Medium", mitre: ["T1530"] },
  putbucketpublicaccessblock: { severity: "Medium", mitre: ["T1530"] },
  modifysnapshotattribute: { severity: "High", mitre: ["T1537"] },
  modifyimageattribute: { severity: "High", mitre: ["T1537"] },
  sharesnapshot: { severity: "High", mitre: ["T1537"] },
  // Credential access / recon / compute
  getsecretvalue: { severity: "Medium", mitre: ["T1552.001"] },
  batchgetsecretvalue: { severity: "High", mitre: ["T1552.001"] },
  getcalleridentity: { severity: "Info", mitre: ["T1087"] },
  assumerole: { severity: "Info", mitre: ["T1078.004"] },
  getfederationtoken: { severity: "Low", mitre: ["T1078.004"] },
  getsessiontoken: { severity: "Low", mitre: ["T1078.004"] }, // STS token minting (cryptomining/priv-esc skills)
  // NOTE: S3 object-level ops (GetObject/CopyObject/DeleteObject) are deliberately NOT graded here —
  // they are extremely high-volume in normal operation, so grading each would flood the timeline
  // (same signal-to-noise discipline as logAggregate). Bucket-policy/ACL exposure above is the signal.
  authorizesecuritygroupingress: { severity: "Medium", mitre: ["T1562.007"] },
  runinstances: { severity: "Low", mitre: ["T1578.002"] },
  importkeypair: { severity: "Medium", mitre: ["T1098.004"] },
};

function truthy(v: unknown): boolean { return v === true || /^(true|1|yes)$/i.test(str(v).trim()); }

// The acting principal: IAM user name, the assumed-role's issuer, the ARN, or the type.
function principal(ui: unknown): { name: string; isRoot: boolean } {
  if (!isObject(ui)) return { name: str(ui), isRoot: false };
  const name = str(getCI(ui, "userName"))
    || str(getPath(ui, "sessionContext.sessionIssuer.userName"))
    || str(getCI(ui, "arn"))
    || str(getCI(ui, "invokedBy"))
    || str(getCI(ui, "type"));
  return { name, isRoot: /^root$/i.test(str(getCI(ui, "type"))) };
}

function shortSource(eventSource: string): string {
  return eventSource.replace(/\.amazonaws\.com$/i, "");
}

function mapRecord(rec: Row, sink: Map<string, SiemIoc>): MappedEvent | null {
  const name = str(getCI(rec, "eventName"));
  const source = str(getCI(rec, "eventSource"));
  if (!name || !source) return null;

  const readOnly = truthy(getCI(rec, "readOnly"));
  const def = AWS_ACTIONS[name.toLowerCase()];
  let severity: Severity = def?.severity ?? (readOnly ? "Info" : "Low");
  const mitre = [...(def?.mitre ?? [])];

  const { name: who, isRoot } = principal(getCI(rec, "userIdentity"));
  const region = str(getCI(rec, "awsRegion"));
  const errorCode = str(getCI(rec, "errorCode"));
  const rawIp = str(getCI(rec, "sourceIPAddress"));
  const ip = cleanIp(rawIp); // AWS-service callers ("ec2.amazonaws.com") yield no IP

  // Console-login failure → brute-force signal; root console login is notable.
  let failed = !!errorCode;
  if (/^consolelogin$/i.test(name)) {
    const res = str(getPath(rec, "responseElements.ConsoleLogin"));
    if (/fail/i.test(res) || /failed authentication/i.test(str(getCI(rec, "errorMessage")))) {
      severity = worst(severity, "Medium"); if (!mitre.includes("T1110")) mitre.push("T1110"); failed = true;
    }
    if (isRoot) severity = worst(severity, "High");
  }
  // A denied/failed mutating call is a probe / privilege test.
  if (errorCode) severity = worst(severity, "Medium");
  // Root doing anything mutating is worth a look.
  if (isRoot && !readOnly) severity = worst(severity, "Medium");

  if (ip) addIoc(sink, "ip", ip);

  let description = `AWS ${name} (${shortSource(source)})`;
  if (who) description += ` by ${oneLine(who).slice(0, 120)}`;
  if (ip) description += ` from ${ip}`;
  else if (rawIp && rawIp !== "AWS Internal") description += ` from ${rawIp}`;
  if (region) description += ` in ${region}`;
  if (isRoot) description += " [root]";
  if (errorCode) description += ` [${errorCode}]`;
  description = description.slice(0, 600);

  return {
    timestamp: normalizeTime(str(getCI(rec, "eventTime"))),
    description, severity, mitre,
    aggKey: `aws|${name}|${who}|${ip || rawIp}|${errorCode}`.toLowerCase().slice(0, 400),
    sources: ["AWS CloudTrail"],
  };
}

export function parseCloudTrail(text: string, opts: AwsImportOptions = {}): AwsParseResult {
  const maxIocs = opts.maxIocs ?? 5000;
  const { records } = extractRecords(text);
  const total = records.length;
  if (total === 0) {
    return { events: [], iocs: [], total: 0, kept: 0, dropped: 0, groups: 0, format: "empty" };
  }

  const iocSink = new Map<string, SiemIoc>();
  const mapped: MappedEvent[] = [];
  for (const rec of records) {
    const m = mapRecord(rec, iocSink);
    if (m) mapped.push(m);
  }
  if (mapped.length === 0) {
    return { events: [], iocs: [], total, kept: 0, dropped: total, groups: 0, format: "empty" };
  }

  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? maxEventsDefault(),
  });

  const represented = events.reduce((n, e) => n + (e.count ?? 1), 0);
  return {
    events,
    iocs: [...iocSink.values()].slice(0, maxIocs),
    total,
    kept: events.length,
    dropped: Math.max(0, total - represented),
    groups,
    format: "cloudtrail",
  };
}
