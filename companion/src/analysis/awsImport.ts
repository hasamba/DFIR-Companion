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
import { createCanonicalEvent, stampSourceArtifactHash } from "./canonicalEvent.js";
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
  firstStr,
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

interface ActionDef {
  severity: Severity;
  mitre?: string[];
}

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
  // Lambda-based execution/persistence — from the IAM-priv-esc skill
  // (Anthropic-Cybersecurity-Skills `detecting-aws-iam-privilege-escalation`, Apache-2.0).
  //
  // NO `passrole` ENTRY. `iam:PassRole` is a PERMISSION evaluated during another call, not an API
  // that CloudTrail records under its own `eventName` — so a `passrole` key here could never match
  // a real record. It sat in this table (and in a test that fabricated the impossible record) until
  // the #931 review. Detecting role-passing means reading the assigned role out of the request
  // parameters of the call that passes it (RunInstances, CreateFunction, ...), which #931 item 6
  // proposes and this table cannot express.
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

function truthy(v: unknown): boolean {
  return v === true || /^(true|1|yes)$/i.test(str(v).trim());
}

// The acting principal: IAM user name, the assumed-role's issuer, the ARN, or the type.
function principal(ui: unknown): {
  name: string;
  isRoot: boolean;
  id?: string;
  type?: string;
  arn?: string;
  accountId?: string;
} {
  if (!isObject(ui)) return { name: str(ui), isRoot: false };
  const type = str(getCI(ui, "type"));
  const arn = str(getCI(ui, "arn"));
  const id = str(getCI(ui, "principalId")) || str(getCI(ui, "userId"));
  const accountId = str(getCI(ui, "accountId"));
  const name =
    str(getCI(ui, "userName")) ||
    str(getPath(ui, "sessionContext.sessionIssuer.userName")) ||
    arn ||
    str(getCI(ui, "invokedBy")) ||
    type;
  return {
    name,
    isRoot: /^root$/i.test(type),
    ...(id ? { id } : {}),
    ...(type ? { type } : {}),
    ...(arn ? { arn } : {}),
    ...(accountId ? { accountId } : {}),
  };
}

function shortSource(eventSource: string): string {
  return eventSource.replace(/\.amazonaws\.com$/i, "");
}

function mapRecord(rec: Row, sink: Map<string, SiemIoc>, recordIndex = 0): MappedEvent | null {
  const name = str(getCI(rec, "eventName"));
  const source = str(getCI(rec, "eventSource"));
  if (!name || !source) return null;

  const readOnly = truthy(getCI(rec, "readOnly"));
  const def = AWS_ACTIONS[name.toLowerCase()];
  let severity: Severity = def?.severity ?? (readOnly ? "Info" : "Low");
  const mitre = [...(def?.mitre ?? [])];

  const identity = principal(getCI(rec, "userIdentity"));
  const { name: who, isRoot } = identity;
  const region = str(getCI(rec, "awsRegion"));
  const errorCode = str(getCI(rec, "errorCode"));
  const rawIp = str(getCI(rec, "sourceIPAddress"));
  const ip = cleanIp(rawIp); // AWS-service callers ("ec2.amazonaws.com") yield no IP

  // Console-login failure → brute-force signal; root console login is notable.
  let failed = !!errorCode;
  if (/^consolelogin$/i.test(name)) {
    const res = str(getPath(rec, "responseElements.ConsoleLogin"));
    if (/fail/i.test(res) || /failed authentication/i.test(str(getCI(rec, "errorMessage")))) {
      severity = worst(severity, "Medium");
      if (!mitre.includes("T1110")) mitre.push("T1110");
      failed = true;
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
  // The CLIENT, in a marker the bulk-read pass reads back. The issue names the user agent as one of
  // the five dimensions to aggregate on, and CloudTrail records it on every call — but nothing kept
  // it, so two different clients under one identity merged into a single group and a fifty-object
  // threshold could be reached by two twenty-five-object sessions that had nothing to do with each
  // other. Trimmed hard: a full user agent is long and this is a marker, not the raw field.
  const client = str(getCI(rec, "userAgent")).trim();
  if (client) description += ` [ua: ${oneLine(client).slice(0, 80)}]`;
  if (isRoot) description += " [root]";
  if (errorCode) description += ` [${errorCode}]`;
  description = description.slice(0, 600);
  const observedTimestamp = str(getCI(rec, "eventTime"));
  const normalizedTimestamp = normalizeTime(observedTimestamp);
  const request = getCI(rec, "requestParameters");
  // An object read names BOTH a bucket and a key, and firstStr returns whichever it meets first —
  // so `cloud.resource` was the bucket alone and the object was thrown away. That is not a cosmetic
  // loss: bulk-read correlation (#908 item 8) counts DISTINCT OBJECTS, so with the key gone every
  // group had an object count of zero and the pass could never fire on real CloudTrail. Both are
  // kept, joined the way the rest of the codebase writes an object path.
  const bucket = isObject(request) ? firstStr(request, ["bucketName"]) : "";
  const objectKey = isObject(request) ? firstStr(request, ["key"]) : "";
  const resource =
    bucket && objectKey
      ? `${bucket}/${objectKey}`
      : isObject(request)
        ? firstStr(request, [
            "resource",
            "resourceName",
            "userName",
            "roleName",
            // roleArn is how AssumeRole names the role it issued. Without it the role-assumption
            // correlation in cloudBulkRead had nothing to match a bulk reader's session against.
            "roleArn",
            "bucketName",
            "key",
          ])
        : "";
  const canonical = createCanonicalEvent({
    event: {
      category: "cloud",
      type: "api",
      action: name,
      outcome: failed ? "failed" : "success",
    },
    ...(who
      ? {
          actor: {
            kind: "cloud_principal",
            name: who,
            ...(identity.id ? { id: identity.id } : {}),
          },
        }
      : {}),
    ...(resource ? { target: { kind: "other", name: resource } } : {}),
    ...(ip ? { network: { source: { address: ip } } } : {}),
    cloud: {
      provider: "aws",
      ...(identity.id ? { principalId: identity.id } : {}),
      ...(identity.type ? { principalType: identity.type } : {}),
      ...(identity.accountId ? { accountId: identity.accountId } : {}),
      ...(region ? { region } : {}),
      ...(resource ? { resource } : {}),
    },
    time: { observed: observedTimestamp, normalized: normalizedTimestamp },
    evidence: {
      rawRecords: [
        {
          source: "aws-cloudtrail",
          locator: `record:${recordIndex}`,
          ...(str(getCI(rec, "eventID")).trim() ? { recordId: str(getCI(rec, "eventID")).trim() } : {}),
        },
      ],
    },
    producer: {
      importer: "aws-cloudtrail",
      parserVersion: "1",
      mappingVersion: "cloudtrail-v1",
      ruleVersions: ["cloudtrail-action-severity-v1"],
    },
    rawFieldMap: {
      "event.action": ["eventName"],
      "event.outcome": ["errorCode", "responseElements.ConsoleLogin"],
      "time.observed": ["eventTime"],
      ...(who ? { "actor.name": ["userIdentity.userName", "userIdentity.arn", "userIdentity.type"] } : {}),
      ...(identity.id ? { "actor.id": ["userIdentity.principalId", "userIdentity.userId"] } : {}),
      ...(ip ? { "network.source.address": ["sourceIPAddress"] } : {}),
      "cloud.provider": ["eventSource"],
      ...(region ? { "cloud.region": ["awsRegion"] } : {}),
      ...(resource ? { "cloud.resource": ["requestParameters"] } : {}),
    },
  });

  return {
    timestamp: normalizedTimestamp,
    description,
    severity,
    mitre,
    canonical,
    // The OBJECT is part of the key for a data-plane read. Without it, three hundred GetObject
    // calls on three hundred different files collapsed into ONE aggregated event with a count of
    // 300, and every downstream question about WHICH objects were read — bulk-read correlation
    // (#908 item 8) above all — had nothing left to read. Management-plane calls keep the old key:
    // a hundred DescribeInstances by one principal genuinely are one thing.
    aggKey: `aws|${name}|${who}|${ip || rawIp}|${errorCode}|${client}${objectKey ? `|${resource}` : ""}`
      .toLowerCase()
      .slice(0, 400),
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
  for (const [recordIndex, rec] of records.entries()) {
    const m = mapRecord(rec, iocSink, recordIndex);
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
  const finalEvents = stampSourceArtifactHash(events, text);

  const represented = finalEvents.reduce((n, e) => n + (e.count ?? 1), 0);
  return {
    events: finalEvents,
    iocs: [...iocSink.values()].slice(0, maxIocs),
    total,
    kept: finalEvents.length,
    dropped: Math.max(0, total - represented),
    groups,
    format: "cloudtrail",
  };
}
