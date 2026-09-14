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
import { boundedAggKey, boundedTextTo } from "./aggKey.js";
import { gcpRows } from "./gcpRow.js";
import { show as neutral } from "./gcpIdentity.js";
import { matchGcpRule } from "./gcpSeverityRules.js";
import { gcpServiceAccountJoins, GCP_SA_JOIN_MAX } from "./gcpServiceAccountJoin.js";
import { decodeAzureLogging } from "./loggingChangeCloud.js";
import { renderLoggingDescription } from "./loggingChange.js";
import { createCanonicalEvent, sourceArtifactHash } from "./canonicalEvent.js";
import { gcpCoverage, azureCoverage } from "./cloudCoverageBuilders.js";
import type { CloudCoverageDraft } from "./cloudCoverage.js";
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
  /** Per-upload coverage drafts (#1063) for whichever of GCP/Azure this upload carried. */
  coverage: CloudCoverageDraft[];
}

type Rule = [RegExp, Severity, string[]];

// Azure operationName patterns ("Microsoft.X/resource/action").
const AZURE_RULES: Rule[] = [
  [/authorization\/roleassignments\/write/, "High", ["T1098.003"]],
  [/authorization\/roledefinitions\/write/, "High", ["T1098.003"]],
  // Remote execution as a FAMILY (#931 item 7): the action form and the managed form
  // (`runCommands/write`, inline or URI-hosted scripts), on a VM or a scale-set instance. T1651 is
  // the precise technique (Cloud Administration Command); T1059 stays for existing expectations.
  [/virtualmachines(?:\/[^/]+)?\/runcommands?\/(?:action|write)/, "High", ["T1651", "T1059"]],
  [/(networksecuritygroups|securityrules).*\/write/, "Medium", ["T1562.007"]],
  [/keyvault.*\/(accesspolicies\/write|write|action)/, "High", ["T1552"]],
  [/storageaccounts\/listkeys\/action/, "High", ["T1552.001"]],
  [/diagnosticsettings\/(delete|write)/, "High", ["T1562.008"]],
  [/virtualmachines\/write/, "Medium", []],
  [/storageaccounts\/write/, "Medium", []],
  [/\/delete$/, "Medium", []],
];

/**
 * Does this operation READ an object's content, as opposed to managing infrastructure?
 *
 * Used only to decide whether the resource belongs in the aggregation key. Kept deliberately narrow:
 * widening it would stop this importer aggregating the management noise it exists to collapse.
 */
function isObjectRead(action: string): boolean {
  return /^(?:storage\.objects\.(?:get|list)|get blob|list blobs|blob\.(?:read|download))$/i.test(
    (action ?? "").trim(),
  );
}

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

function mapGcp(rec: Row, sink: Map<string, SiemIoc>, locator: string): MappedEvent[] {
  const pp = isObject(getCI(rec, "protoPayload"))
    ? (getCI(rec, "protoPayload") as Row)
    : isObject(getCI(rec, "jsonPayload"))
      ? (getCI(rec, "jsonPayload") as Row)
      : null;
  const method = pp ? str(getCI(pp, "methodName")) : "";
  const service = pp ? str(getCI(pp, "serviceName")) : "";
  if (!method || !pp) return [];

  const principal = str(getPath(pp, "authenticationInfo.principalEmail"));
  const ip = cleanIp(str(getPath(pp, "requestMetadata.callerIp")));
  const resource = str(getCI(pp, "resourceName"));
  const statusCode = Number(getPath(pp, "status.code")) || 0;
  const statusMsg = str(getPath(pp, "status.message"));

  // setIamPolicy/setIamPermissions: priv-esc generally, but data exposure on storage.
  let def = matchGcpRule(method);
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
  // Every imported string in the head is neutralised (brackets, controls, bidi) and bounded.
  let head = `GCP ${neutral(method, 120)}${shortSvc ? ` (${neutral(shortSvc, 40)})` : ""}`;
  if (principal) head += ` by ${neutral(principal, 80)}`;
  if (ip) head += ` from ${ip}`;
  // The object name is kept whole here: the row's digest-preserving clip (#940) is what bounds it.
  if (shortRes) head += ` on ${neutral(shortRes, 800)}`;
  if (statusCode !== 0) head += ` [DENIED${statusMsg ? `: ${neutral(oneLine(statusMsg), 60)}` : ""}]`;
  // The identity facts, the binding delta, the credential fact and the key step are read by
  // gcpRow.ts (#931 item 12); one record with N binding deltas is N rows. The RESOURCE is part of
  // the key for an object read only — a hundred management calls by one principal are one thing.
  return gcpRows({
    rec,
    pp,
    method,
    service,
    principal,
    ip,
    resource,
    statusCode,
    head: boundedTextTo(head, 300),
    severity,
    mitre,
    baseKey: `gcp|${method}|${principal}|${ip}|${statusCode}${isObjectRead(method) && shortRes ? `|${shortRes}` : ""}`,
    locator,
  });
}

// ───────────────────────────── Azure ─────────────────────────────

function mapAzure(rec: Row, sink: Map<string, SiemIoc>, recordIndex: number): MappedEvent | null {
  const op = pickStr(rec, ["operationName.value", "operationName", "OperationNameValue", "OperationName"]);
  if (!op) return null;

  const caller = pickStr(rec, ["caller", "Caller", "identity.claims.name"]);
  const ip = cleanIp(
    pickStr(rec, ["httpRequest.clientIpAddress", "claims.ipaddr", "CallerIpAddress", "callerIpAddress"]),
  );
  const status = pickStr(rec, ["status.value", "status", "ActivityStatusValue", "resultType", "ResultType"]);
  const resource = pickStr(rec, ["resourceId", "ResourceId", "resourceGroupName", "ResourceGroup"]);
  const failed = /fail/i.test(status);

  const def = matchRule(AZURE_RULES, op);
  let severity: Severity = def?.severity ?? "Low";
  const mitre = [...(def?.mitre ?? [])];
  if (failed) severity = worst(severity, "Medium");
  if (ip) addIoc(sink, "ip", ip);

  const shortRes = resource.split("/").slice(-2).join("/");
  // Remote execution names its TARGET machine, not the last two path segments (which, for the
  // managed form, are `runCommands/<command-name>` — a child, not the VM). The parent VM or the
  // scale-set instance (`<set>/<instanceId>` — an instance number alone is not an identity) is the
  // target, and its normalised resource id joins the key so commands against two machines by one
  // caller are two rows. The script body is not in the Activity Log, and the note says so.
  const exec = azureRemoteExecutionTarget(
    op,
    resource,
    pickStr(rec, [
      "eventDataId",
      "EventDataId",
      "correlationId",
      "CorrelationId",
      "operationId",
      "OperationId",
    ]),
  );
  // A diagnostic-setting or log-profile operation is read for the state its request body
  // establishes (#931 item 14); the reading's grade replaces the table's blanket High.
  const logging = decodeAzureLogging(
    op,
    resource,
    getPath(rec, "properties.requestbody") ??
      getPath(rec, "properties.requestBody") ??
      getPath(rec, "Properties.requestbody") ??
      getPath(rec, "Properties.requestBody") ??
      getPath(rec, "properties"),
    failed,
  );
  if (logging) {
    severity = logging.severity;
    mitre.length = 0;
    mitre.push(...logging.mitre);
  }
  let description = `Azure ${op}`;
  if (caller) description += ` by ${caller}`;
  if (ip) description += ` from ${ip}`;
  if (exec) description += ` → ${exec.display} — the script body is not in the Activity Log`;
  else if (shortRes && !logging) description += ` on ${shortRes}`;
  if (failed) description += ` [${status}]`;
  // A logging row goes through the logging renderer: every slot neutralised, the qualifiers reserved.
  description = logging
    ? renderLoggingDescription(description, "", logging)
    : boundedTextTo(description, 600); // an identity downstream — see mapGcp
  const observed = pickStr(rec, ["eventTimestamp", "time", "TimeGenerated", "timeStamp"]);

  return {
    timestamp: normalizeTime(observed),
    description,
    severity,
    mitre,
    // The RESOURCE is part of the key for an object read. Without it, aggregation folded every
    // read by one principal into a single counted event before any correlation could see it — so
    // bulk-read detection (#908 item 8) was structurally blind to this provider. Only data-plane
    // reads carry it: a hundred management calls by one principal genuinely are one thing, and
    // adding the resource everywhere would undo the aggregation this importer exists to do.
    aggKey: boundedAggKey(
      `azure|${op}|${caller}|${ip}|${status}${exec ? `|${exec.id}` : isObjectRead(op) && shortRes ? `|${shortRes}` : ""}${logging?.keySegment ?? ""}`.toLowerCase(),
    ),
    sources: ["Azure Activity"],
    ...(logging
      ? {
          canonical: createCanonicalEvent({
            event: {
              category: "cloud",
              type: "logging-change",
              action: op,
              outcome: failed ? "failure" : "success",
            },
            ...(caller ? { actor: { kind: "account", name: caller } } : {}),
            ...(ip ? { network: { source: { address: ip } } } : {}),
            cloud: { provider: "azure", ...(resource ? { resource } : {}) },
            time: { observed, normalized: normalizeTime(observed) },
            evidence: { rawRecords: [{ source: "azure-activity", locator: `record:${recordIndex}` }] },
            producer: {
              importer: "azure-activity",
              parserVersion: "1",
              mappingVersion: "azure-logging-v1",
              ruleVersions: ["azure-logging-v1"],
            },
            rawFieldMap: {
              "event.action": ["operationName.value", "operationName", "OperationNameValue", "OperationName"],
              "event.outcome": ["status.value", "status", "ActivityStatusValue", "resultType", "ResultType"],
              "time.observed": ["eventTimestamp", "time", "TimeGenerated", "timeStamp"],
              ...(caller ? { "actor.name": ["caller", "Caller", "identity.claims.name"] } : {}),
              ...(ip
                ? {
                    "network.source.address": [
                      "httpRequest.clientIpAddress",
                      "claims.ipaddr",
                      "CallerIpAddress",
                      "callerIpAddress",
                    ],
                  }
                : {}),
              "cloud.provider": ["operationName.value"],
              ...(resource
                ? { "cloud.resource": ["resourceId", "ResourceId", "resourceGroupName", "ResourceGroup"] }
                : {}),
            },
            loggingChange: logging.block,
          }),
        }
      : {}),
  };
}

// The machine a Run Command targets, from the operation and the resource id. Null for every other
// operation. `id` is the normalised parent resource id (lowercased) — the identity the key carries;
// `display` is the VM name or `<set>/<instanceId>`.
const VM_RE =
  /(\/subscriptions\/[^/]+\/resourcegroups\/[^/]+\/providers\/microsoft\.compute\/virtualmachines\/([^/]+))/i;
const VMSS_RE =
  /(\/subscriptions\/[^/]+\/resourcegroups\/[^/]+\/providers\/microsoft\.compute\/virtualmachinescalesets\/([^/]+)\/virtualmachines\/([^/]+))/i;
export function azureRemoteExecutionTarget(
  op: string,
  resource: string,
  recordId = "",
): { id: string; display: string } | null {
  if (!/virtualmachines(?:\/[^/]+)?\/runcommands?\/(?:action|write)/i.test(op)) return null;
  const vmss = VMSS_RE.exec(resource);
  if (vmss) return { id: vmss[1].toLowerCase(), display: `${vmss[2]}/${vmss[3]}`.slice(0, 160) };
  const vm = VM_RE.exec(resource);
  if (vm) return { id: vm[1].toLowerCase(), display: vm[2].slice(0, 120) };
  // No parseable machine: the row must stay its own — a per-record identifier keeps it from
  // folding into every other same-operation call with an unknown target (`recordId` is supplied
  // by the mapper from eventDataId / correlationId / operationId).
  const short = resource.split("/").slice(-2).join("/") || "(unknown target)";
  return { id: `${resource.toLowerCase() || "unknown"}#${recordId}`, display: short.slice(0, 160) };
}

// ───────────────────────────── classification ─────────────────────────────

function isGcp(rec: Row): boolean {
  return !!getCI(rec, "protoPayload") || /cloudaudit/i.test(str(getCI(rec, "logName")));
}
function isAzure(rec: Row): boolean {
  const hasOp = !!(
    getCI(rec, "operationName") ||
    getCI(rec, "OperationNameValue") ||
    getCI(rec, "OperationName")
  );
  return (
    hasOp &&
    !!(
      getCI(rec, "caller") ||
      getCI(rec, "Caller") ||
      getCI(rec, "resourceId") ||
      getCI(rec, "ResourceId") ||
      getCI(rec, "correlationId") ||
      /azureactivity/i.test(str(getCI(rec, "Type")))
    )
  );
}

// ───────────────────────────── top-level parse ─────────────────────────────

export function parseCloudActivity(
  text: string,
  opts: CloudActivityImportOptions = {},
): CloudActivityParseResult {
  const maxIocs = opts.maxIocs ?? 5000;
  const { records } = extractRecords(text);
  const total = records.length;
  if (total === 0) {
    return { events: [], iocs: [], total: 0, kept: 0, dropped: 0, groups: 0, format: "empty", coverage: [] };
  }

  const iocSink = new Map<string, SiemIoc>();
  const mapped: MappedEvent[] = [];
  const gcpRecords: Row[] = [];
  const azureRecords: Row[] = [];
  let sawGcp = false,
    sawAzure = false;

  records.forEach((rec, recordIndex) => {
    if (isGcp(rec)) {
      gcpRecords.push(rec);
      const rows = mapGcp(rec, iocSink, `record:${recordIndex}`);
      if (rows.length) sawGcp = true;
      mapped.push(...rows);
    } else if (isAzure(rec)) {
      azureRecords.push(rec);
      const m = mapAzure(rec, iocSink, recordIndex);
      if (m) {
        sawAzure = true;
        mapped.push(m);
      }
    }
  });
  // Coverage (#1063): every GCP/Azure record this upload states about itself, regardless of
  // whether it mapped to a timeline row.
  const uploadId = sourceArtifactHash(text);
  const coverage: CloudCoverageDraft[] = [
    ...gcpCoverage(gcpRecords).map((d) => ({ ...d, uploadId })),
    ...azureCoverage(azureRecords).map((d) => ({ ...d, uploadId })),
  ];
  if (mapped.length === 0) {
    return { events: [], iocs: [], total, kept: 0, dropped: total, groups: 0, format: "empty", coverage };
  }

  const aggregated = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? maxEventsDefault(),
  });
  // The per-service-account join (#1065): built over every GCP record of this export, appended
  // AFTER the source-row cap under its own bound — `maxEvents` bounds source rows, a summary
  // never evicts one, and `kept`/`dropped`/`groups` count source rows alone.
  const summaries = sawGcp
    ? aggregateEvents(gcpServiceAccountJoins(records), {
        aggregate: opts.aggregate,
        minSeverity: opts.minSeverity,
        maxEvents: GCP_SA_JOIN_MAX + 1,
      }).events
    : [];
  const events = [...aggregated.events, ...summaries];
  const groups = aggregated.groups;

  const represented = aggregated.events.reduce((n, e) => n + (e.count ?? 1), 0);
  const format = sawGcp && sawAzure ? "mixed" : sawGcp ? "gcp" : sawAzure ? "azure" : "empty";

  return {
    events,
    iocs: [...iocSink.values()].slice(0, maxIocs),
    total,
    kept: aggregated.events.length,
    dropped: Math.max(0, total - represented),
    groups,
    format,
    coverage,
  };
}
