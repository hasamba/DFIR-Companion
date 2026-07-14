// Deterministic importer for GCP Cloud Audit Logs + Azure Activity Log — the other two major
// clouds (AWS has its own CloudTrail path). The tenth deterministic ingest path; no AI call.
//
// Both deliver JSON (an array from `gcloud logging read` / `az monitor activity-log list`,
// NDJSON from a log sink, or an Elastic/Log-Analytics wrapper). Records are routed per-record:
//   • GCP  — a Cloud Logging LogEntry with a `protoPayload` AuditLog (or a `cloudaudit` logName).
//   • Azure — an Activity Log entry with `operationName` (+ `caller`/`resourceId`), in either the
//             native REST/az camelCase form or the flat Log-Analytics PascalCase form.
//
// Like AWS/M365 these are API calls with no maliciousness score, so severity is DERIVED from
// the action (IAM/role grants, service-account & access keys, logging-sink/diagnostic deletion,
// firewall opens, secret/storage-key access, snapshot/image sharing) — the same deterministic
// mapping pattern, NOT a detection engine. A non-OK status (denied probe) bumps severity. The
// caller IP becomes an IOC; the principal email is surfaced for the asset↔IoC graph.

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

export interface CloudActivityImportOptions {
  aggregate?: boolean;
  minSeverity?: Severity;
  maxEvents?: number;
  maxIocs?: number;
}

export interface CloudActivityParseResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  total: number;
  kept: number;
  dropped: number;
  groups: number;
  format: string; // "gcp" | "azure" | "mixed" | "empty"
}

type Rule = [RegExp, Severity, string[]];

// GCP audit methodName patterns (prefixes vary — v1./beta./google.iam.admin.v1. — so match
// on the distinctive verb/resource fragment).
const GCP_RULES: Rule[] = [
  [/createserviceaccountkey/, "High", ["T1098.001"]],
  [/createserviceaccount\b/, "Medium", ["T1136"]],
  [/(create|update).*\brole\b/, "Medium", ["T1098.003"]],
  [/firewalls?\.(insert|patch|update)/, "Medium", ["T1562.007"]],
  [/sinks?\.(delete|update)|logentries.*delete/, "High", ["T1562.008"]],
  [/accesssecretversion/, "Medium", ["T1552.001"]],
  [/(snapshots|images|disks)\.(insert|setiampolicy)/, "High", ["T1537"]],
  [/instances\.insert/, "Low", ["T1578.002"]],
  [/storage\.objects\.(get|list)/, "Info", []],
  [/\.delete$/, "Medium", []],
];

// Azure operationName patterns ("Microsoft.X/resource/action").
const AZURE_RULES: Rule[] = [
  [/authorization\/roleassignments\/write/, "High", ["T1098.003"]],
  [/authorization\/roledefinitions\/write/, "High", ["T1098.003"]],
  [/runcommand\/action/, "High", ["T1059"]],
  [/(networksecuritygroups|securityrules).*\/write/, "Medium", ["T1562.007"]],
  [/keyvault.*\/(accesspolicies\/write|write|action)/, "High", ["T1552"]],
  [/storageaccounts\/listkeys\/action/, "High", ["T1552.001"]],
  [/diagnosticsettings\/(delete|write)/, "High", ["T1562.008"]],
  [/virtualmachines\/write/, "Medium", []],
  [/storageaccounts\/write/, "Medium", []],
  [/\/delete$/, "Medium", []],
];

function matchRule(rules: Rule[], key: string): { severity: Severity; mitre: string[] } | null {
  const k = key.toLowerCase();
  for (const [re, severity, mitre] of rules) if (re.test(k)) return { severity, mitre };
  return null;
}

function pickStr(row: Row, keys: string[]): string {
  for (const k of keys) {
    const v = k.includes(".") ? getPath(row, k) : getCI(row, k);
    const s = str(v).trim();
    if (s) return s;
  }
  return "";
}

// ───────────────────────────── GCP ─────────────────────────────

function mapGcp(rec: Row, sink: Map<string, SiemIoc>): MappedEvent | null {
  const pp = isObject(getCI(rec, "protoPayload")) ? (getCI(rec, "protoPayload") as Row)
    : isObject(getCI(rec, "jsonPayload")) ? (getCI(rec, "jsonPayload") as Row) : null;
  const method = pp ? str(getCI(pp, "methodName")) : "";
  const service = pp ? str(getCI(pp, "serviceName")) : "";
  if (!method) return null;

  const principal = pp ? str(getPath(pp, "authenticationInfo.principalEmail")) : "";
  const ip = cleanIp(pp ? str(getPath(pp, "requestMetadata.callerIp")) : "");
  const resource = pp ? str(getCI(pp, "resourceName")) : "";
  const statusCode = Number(pp ? getPath(pp, "status.code") : 0) || 0;
  const statusMsg = pp ? str(getPath(pp, "status.message")) : "";

  // setIamPolicy/setIamPermissions: priv-esc generally, but data exposure on storage.
  let def = matchRule(GCP_RULES, method);
  if (!def && /setiam(policy|permissions)/i.test(method)) {
    def = /storage/i.test(service)
      ? { severity: "High", mitre: ["T1530"] }
      : { severity: "High", mitre: ["T1098.003"] };
  }
  let severity: Severity = def?.severity ?? "Low";
  const mitre = [...(def?.mitre ?? [])];
  if (statusCode !== 0) severity = worst(severity, "Medium");
  if (ip) addIoc(sink, "ip", ip);

  const shortSvc = service.replace(/\.googleapis\.com$/i, "");
  const shortRes = resource.split("/").slice(-2).join("/");
  let description = `GCP ${method}${shortSvc ? ` (${shortSvc})` : ""}`;
  if (principal) description += ` by ${principal}`;
  if (ip) description += ` from ${ip}`;
  if (shortRes) description += ` on ${shortRes}`;
  if (statusCode !== 0) description += ` [DENIED${statusMsg ? `: ${oneLine(statusMsg).slice(0, 60)}` : ""}]`;
  description = description.slice(0, 600);

  return {
    timestamp: normalizeTime(str(getCI(rec, "timestamp")) || str(getCI(rec, "receiveTimestamp"))),
    description, severity, mitre,
    aggKey: `gcp|${method}|${principal}|${ip}|${statusCode}`.toLowerCase().slice(0, 400),
    sources: ["GCP Audit"],
  };
}

// ───────────────────────────── Azure ─────────────────────────────

function mapAzure(rec: Row, sink: Map<string, SiemIoc>): MappedEvent | null {
  const op = pickStr(rec, ["operationName.value", "operationName", "OperationNameValue", "OperationName"]);
  if (!op) return null;

  const caller = pickStr(rec, ["caller", "Caller", "identity.claims.name"]);
  const ip = cleanIp(pickStr(rec, ["httpRequest.clientIpAddress", "claims.ipaddr", "CallerIpAddress", "callerIpAddress"]));
  const status = pickStr(rec, ["status.value", "status", "ActivityStatusValue", "resultType", "ResultType"]);
  const resource = pickStr(rec, ["resourceId", "ResourceId", "resourceGroupName", "ResourceGroup"]);
  const failed = /fail/i.test(status);

  const def = matchRule(AZURE_RULES, op);
  let severity: Severity = def?.severity ?? "Low";
  const mitre = [...(def?.mitre ?? [])];
  if (failed) severity = worst(severity, "Medium");
  if (ip) addIoc(sink, "ip", ip);

  const shortRes = resource.split("/").slice(-2).join("/");
  let description = `Azure ${op}`;
  if (caller) description += ` by ${caller}`;
  if (ip) description += ` from ${ip}`;
  if (shortRes) description += ` on ${shortRes}`;
  if (failed) description += ` [${status}]`;
  description = description.slice(0, 600);

  return {
    timestamp: normalizeTime(pickStr(rec, ["eventTimestamp", "time", "TimeGenerated", "timeStamp"])),
    description, severity, mitre,
    aggKey: `azure|${op}|${caller}|${ip}|${status}`.toLowerCase().slice(0, 400),
    sources: ["Azure Activity"],
  };
}

// ───────────────────────────── classification ─────────────────────────────

function isGcp(rec: Row): boolean {
  return !!getCI(rec, "protoPayload") || /cloudaudit/i.test(str(getCI(rec, "logName")));
}
function isAzure(rec: Row): boolean {
  const hasOp = !!(getCI(rec, "operationName") || getCI(rec, "OperationNameValue") || getCI(rec, "OperationName"));
  return hasOp && !!(getCI(rec, "caller") || getCI(rec, "Caller") || getCI(rec, "resourceId") ||
    getCI(rec, "ResourceId") || getCI(rec, "correlationId") || /azureactivity/i.test(str(getCI(rec, "Type"))));
}

// ───────────────────────────── top-level parse ─────────────────────────────

export function parseCloudActivity(text: string, opts: CloudActivityImportOptions = {}): CloudActivityParseResult {
  const maxIocs = opts.maxIocs ?? 5000;
  const { records } = extractRecords(text);
  const total = records.length;
  if (total === 0) {
    return { events: [], iocs: [], total: 0, kept: 0, dropped: 0, groups: 0, format: "empty" };
  }

  const iocSink = new Map<string, SiemIoc>();
  const mapped: MappedEvent[] = [];
  let sawGcp = false, sawAzure = false;

  for (const rec of records) {
    let m: MappedEvent | null = null;
    if (isGcp(rec)) { m = mapGcp(rec, iocSink); if (m) sawGcp = true; }
    else if (isAzure(rec)) { m = mapAzure(rec, iocSink); if (m) sawAzure = true; }
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
  const format = sawGcp && sawAzure ? "mixed" : sawGcp ? "gcp" : sawAzure ? "azure" : "empty";

  return {
    events,
    iocs: [...iocSink.values()].slice(0, maxIocs),
    total,
    kept: events.length,
    dropped: Math.max(0, total - represented),
    groups,
    format,
  };
}
