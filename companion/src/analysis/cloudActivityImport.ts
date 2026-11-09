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
import { azureComputeLifecycles, AZURE_COMPUTE_MAX } from "./azureCompute.js";
import { azureVmssComputeLifecycles, VMSS_COMPUTE_MAX } from "./azureVmssCompute.js";
import { VMSS_MEMBER_RESOURCE_ID } from "./azureVmssComputeState.js";
import { AZURE_RUN_COMMAND_RE } from "./azureComputeState.js";
import { gcpComputeLifecycles, GCP_COMPUTE_MAX } from "./gcpCompute.js";
import { classifyAzureFailure, decodeAzureLogging } from "./loggingChangeCloud.js";
import { renderLoggingDescription } from "./loggingChange.js";
import { createCanonicalEvent, sourceArtifactHash, stampSourceArtifactHash } from "./canonicalEvent.js";
import { gcpCoverage, azureCoverage } from "./cloudCoverageBuilders.js";
import { azureRawRecords, azureRowCanonical } from "./cloudRowCanonical.js";
import { azureActivityRecordId } from "./cloudRecordIdentity.js";
import { adaptAzureDiagnosticActivity } from "./azureDiagnosticRecord.js";
import type { CloudCoverageDraft } from "./cloudCoverage.js";
import {
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
import type { ImportDebugRecorder } from "./importDebug.js";
import { gateRecords, gateRows, isDuplicateRecord, type CloudRecordParseOptions } from "./cloudRecordGate.js";
import { readCloudRecords } from "./cloudRecords.js";
import type { JsonRepairs } from "./tolerantJson.js";
import { applySigmaToRecordRows, sigmaMatchesFor, type SigmaGradingSnapshot } from "./sigmaImportGrade.js";
import { GCP_AUDIT } from "./sigmaLogSources.js";
import { shortGcpMethod } from "./cloudRowWording.js";

type Row = Record<string, unknown>;

export interface CloudActivityImportOptions extends CloudRecordParseOptions {
  aggregate?: boolean;
  minSeverity?: Severity;
  maxEvents?: number;
  maxIocs?: number;
  /** This attempt's import debug recorder (#1736): decisions and counts only, never row content. */
  debug?: ImportDebugRecorder;
  /** The Sigma snapshot this import is graded with (#2346) — GCP audit records only. */
  sigma?: SigmaGradingSnapshot;
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
  /** What the tolerant reader repaired to read the file (#2302), disclosed in the import note. */
  repairs?: JsonRepairs;
  /** The mapped rows, unaggregated — only with `rowsOnly` (#2303). */
  mapped?: MappedEvent[];
  /** For each `mapped` row, the index (in this batch) of the record it came from. */
  rowRecords?: number[];
  /** GCP rows a Sigma rule matched (#2346); 0 without a snapshot. */
  sigmaRowsMatched?: number;
}

type Rule = [RegExp, Severity, string[]];

// Azure operationName patterns ("Microsoft.X/resource/action").
const AZURE_RULES: Rule[] = [
  [/authorization\/roleassignments\/write/, "High", ["T1098.003"]],
  [/authorization\/roledefinitions\/write/, "High", ["T1098.003"]],
  // Remote execution as a FAMILY (#931 item 7): the action form and the managed form
  // (`runCommands/write`, inline or URI-hosted scripts), on a VM or a scale-set instance. T1651 is
  // the precise technique (Cloud Administration Command); T1059 stays for existing expectations.
  // AZURE_RUN_COMMAND_RE (#1066) is the ONE shared source of this pattern — azureCompute.ts and
  // azureRemoteExecutionTarget below both match against it too, so none of the three can drift.
  [AZURE_RUN_COMMAND_RE, "High", ["T1651", "T1059"]],
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

/** A storage-account shared-key listing — the control-plane half of #931 item 4's key→read join. */
function isListKeys(action: string): boolean {
  return /storageaccounts\/listkeys\/action/i.test((action ?? "").trim());
}

/** The non-failure lifecycle words of ONE Azure call — REST/az shape and Log-Analytics shape. */
const AZURE_LIFECYCLE_STATUS_RE = /^(started|accepted|succeeded|start|accept|success)$/i;
const AZURE_LIFECYCLE_KEY = "lifecycle";

/**
 * The status segment of the Azure aggregation key (#2476). The Activity Log writes a Started and
 * a Succeeded (sometimes an Accepted) event for one call, and the row only prints the status when
 * the call failed — so keying on the raw word split one burst into entries that looked identical.
 * Those lifecycle words share one segment; Failed and any other status keep their own.
 */
function azureAggStatus(status: string): string {
  return AZURE_LIFECYCLE_STATUS_RE.test(status.trim()) ? AZURE_LIFECYCLE_KEY : status;
}

function matchRule(rules: Rule[], key: string): { severity: Severity; mitre: string[] } | null {
  const k = key.toLowerCase();
  for (const [re, severity, mitre] of rules) if (re.test(k)) return { severity, mitre };
  return null;
}

// `onKey` hears which candidate key supplied the value (#1736) — the key name, never the value.
function pickStr(row: Row, keys: string[], onKey?: (key: string) => void): string {
  for (const k of keys) {
    const v = k.includes(".") ? getPath(row, k) : getCI(row, k);
    const s = str(v).trim();
    if (s) {
      onKey?.(k);
      return s;
    }
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
  // GCP's own Cloud Audit Log field, recorded by GCP's own infrastructure at call time —
  // edge-observed, not client-asserted (#1184 audit).
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
  // The title shows the method without its versioned package (#2486); the record keeps it whole.
  let head = `GCP ${neutral(shortGcpMethod(method), 120)}${shortSvc ? ` (${neutral(shortSvc, 40)})` : ""}`;
  if (principal) head += ` by ${neutral(principal, 80)}`;
  if (ip) head += ` from ${ip}`;
  // The object name is kept whole here: the row's digest-preserving clip (#940) is what bounds it.
  if (shortRes) head += ` on ${neutral(shortRes, 800)}`;
  // The failure bracket is passed SEPARATELY, never baked into `head` here (#1081, Codex code
  // review): gcpRow.ts's row() appends it — or, for a LOGGING reading, omits it entirely, since
  // that reading's own posture already states the outcome — and bounds the COMBINED string in one
  // pass. Appending-then-bounding twice (once here, once there) let a long head's own truncation
  // split the bracket mid-string, stranding a mangled "[DENIED: NOT_FOUN#…" fragment beside a
  // posture that said "target not found".
  const statusBracket =
    statusCode !== 0 ? ` [DENIED${statusMsg ? `: ${neutral(oneLine(statusMsg), 60)}` : ""}]` : "";
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
    head,
    statusBracket,
    severity,
    mitre,
    baseKey: `gcp|${method}|${principal}|${ip}|${statusCode}${isObjectRead(method) && shortRes ? `|${shortRes}` : ""}`,
    locator,
  });
}

// ───────────────────────────── Azure ─────────────────────────────

function mapAzure(
  rec: Row,
  sink: Map<string, SiemIoc>,
  recordIndex: number,
  debug?: ImportDebugRecorder,
): MappedEvent | null {
  const op = pickStr(
    rec,
    ["operationName.value", "operationName", "OperationNameValue", "OperationName"],
    (k) => debug?.field("action", k),
  );
  if (!op) return null;

  const caller = pickStr(rec, ["caller", "Caller", "identity.claims.name"], (k) => debug?.field("user", k));
  // All four are Azure's own activity-log fields (recorded by Azure's own infrastructure at call
  // time), across the three export shapes this codebase already reads from — edge-observed, not
  // client-asserted (#1184 audit).
  const ip = cleanIp(
    pickStr(
      rec,
      ["httpRequest.clientIpAddress", "claims.ipaddr", "CallerIpAddress", "callerIpAddress"],
      (k) => debug?.field("source_ip", k),
    ),
  );
  const status = pickStr(rec, ["status.value", "status", "ActivityStatusValue", "resultType", "ResultType"]);
  // Microsoft's own schema reference documents subStatus as "usually the HTTP status code of the
  // corresponding REST call" — present, under this same three-shape convention, across all three
  // Azure export shapes this codebase already reads `status` from (#1096).
  const subStatus = pickStr(rec, [
    "subStatus.value",
    "subStatus",
    "ActivitySubstatusValue",
    "resultSignature",
    "ResultSignature",
  ]);
  const resource = pickStr(rec, ["resourceId", "ResourceId", "resourceGroupName", "ResourceGroup"]);
  const failed = /fail/i.test(status);
  const azureFailure = failed ? classifyAzureFailure(subStatus) : null;

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
    azureFailure,
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
  const observed = pickStr(rec, ["eventTimestamp", "time", "TimeGenerated", "timeStamp"], (k) =>
    debug?.field("timestamp", k),
  );
  const recordId = azureActivityRecordId(rec); // the key the Azure record dedup uses (#2485)

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
    // `subStatus` joins the key too, but ONLY for a LOGGING row (#1096, Codex code review finding
    // #1: adding it unconditionally fragmented the broader Azure row family's own aggregation —
    // two otherwise-identical non-logging management calls can legitimately carry different
    // common substatuses, like 200 vs 201, and must still aggregate as one). Unlike AWS's
    // errorCode / GCP's statusCode, which already ride in THEIR OWN outer keys, Azure's own key
    // only ever carried the coarse `status` word — two different LOGGING failure kinds (403 vs
    // 404) against the same target would otherwise collapse into one aggregated row (Codex design
    // review finding #1).
    // Codex review (P1, #931 item 4): a listKeys row needs the resource in its key too — without
    // it, listings of DIFFERENT storage accounts by the same caller/IP collapse into one row, and
    // the key→read correlator can only ever see the first account.
    aggKey: boundedAggKey(
      `azure|${op}|${caller}|${ip}|${azureAggStatus(status)}${logging ? `|${subStatus}` : ""}${exec ? `|${exec.id}` : (isObjectRead(op) || isListKeys(op)) && shortRes ? `|${shortRes}` : ""}${logging?.keySegment ?? ""}`.toLowerCase(),
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
            ...(ip ? { network: { source: { address: ip, provenance: "edge-observed" } } } : {}),
            cloud: { provider: "azure", ...(resource ? { resource } : {}) },
            time: { observed, normalized: normalizeTime(observed) },
            evidence: { rawRecords: azureRawRecords(recordIndex, recordId) },
            producer: {
              importer: "azure-activity",
              parserVersion: "1",
              // v2 (#1096): reads a genuinely new source field, subStatus, that v1 never read —
              // re-running the same stored raw record now produces a different classification.
              mappingVersion: "azure-logging-v2",
              ruleVersions: ["azure-logging-v2"],
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
      : isListKeys(op)
        ? {
            // #931 item 4: the control-plane half of the storage key→read join. No new schema
            // block — same minimal shape the `logging` branch above already establishes for one
            // more Azure row kind.
            canonical: createCanonicalEvent({
              event: {
                category: "cloud",
                type: "storage-key-list",
                action: op,
                outcome: failed ? "failure" : "success",
              },
              ...(caller ? { actor: { kind: "account", name: caller } } : {}),
              ...(ip ? { network: { source: { address: ip, provenance: "edge-observed" } } } : {}),
              cloud: { provider: "azure", ...(resource ? { resource } : {}) },
              time: { observed, normalized: normalizeTime(observed) },
              evidence: { rawRecords: azureRawRecords(recordIndex, recordId) },
              producer: {
                importer: "azure-activity",
                parserVersion: "1",
                mappingVersion: "azure-listkeys-v1",
                ruleVersions: ["azure-listkeys-v1"],
              },
            }),
          }
        : {
            // Every other operation cites its own record too (#2485), not the legacy `event:<id>`.
            canonical: azureRowCanonical({
              operation: op,
              caller,
              ip,
              resource,
              observed,
              normalized: normalizeTime(observed),
              failed,
              index: recordIndex,
              recordId,
            }),
          }),
  };
}

// The machine a Run Command targets, from the operation and the resource id. Null for every other
// operation. `id` is the normalised parent resource id (lowercased) — the identity the key carries;
// `display` is the VM name or `<set>/<instanceId>`.
const VM_RE =
  /(\/subscriptions\/[^/]+\/resourcegroups\/[^/]+\/providers\/microsoft\.compute\/virtualmachines\/([^/]+))/i;
// VMSS matching reuses the SAME shared regex #1078's own azureVmssComputeState.ts exports —
// never a second, independently-drifting copy (Codex design round 1, finding M1).
export function azureRemoteExecutionTarget(
  op: string,
  resource: string,
  recordId = "",
): { id: string; display: string } | null {
  if (!AZURE_RUN_COMMAND_RE.test(op)) return null;
  const vmss = VMSS_MEMBER_RESOURCE_ID.exec(resource);
  if (vmss) return { id: vmss[0].toLowerCase(), display: `${vmss[3]}/${vmss[4]}`.slice(0, 160) };
  const vm = VM_RE.exec(resource);
  if (vm) return { id: vm[1].toLowerCase(), display: vm[2].slice(0, 120) };
  // No parseable machine: the row must stay its own — a per-record identifier keeps it from
  // folding into every other same-operation call with an unknown target (`recordId` is supplied
  // by the mapper from eventDataId / correlationId / operationId).
  const short = resource.split("/").slice(-2).join("/") || "(unknown target)";
  return { id: `${resource.toLowerCase() || "unknown"}#${recordId}`, display: short.slice(0, 160) };
}

/**
 * One GCP record's rows graded by the import's Sigma snapshot (#2346). A record that became several
 * rows (one per binding delta) carries the verdict on its first row only, the Entra-audit rule.
 * Azure Activity records never come here: no Sigma log source reads them.
 */
function gradeGcpRows(
  rows: MappedEvent[],
  rec: Row,
  opts: CloudActivityImportOptions,
  onMatch: () => void,
): MappedEvent[] {
  const snapshot = opts.sigma;
  if (!snapshot || rows.length === 0) return rows;
  const matches = sigmaMatchesFor(snapshot, GCP_AUDIT.id, rec, (n) =>
    opts.debug?.observed("sigma_incomplete", n),
  );
  if (matches.length) onMatch();
  return applySigmaToRecordRows(rows, matches, snapshot);
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

// JSON (tolerant) or a Log Analytics AzureActivity CSV, whose rows carry the same columns as its
// JSON export and map the same way (#2302). A diagnostic-settings (PT1H.json) Activity record names
// its caller in `identity.claims`; it is filled in as REST's `caller` first (#2304).
export function parseCloudActivity(
  text: string,
  opts: CloudActivityImportOptions = {},
): CloudActivityParseResult {
  // Pre-read by the ingest layer (#2301) or read here; either way the same reader (#2302).
  // The diagnostic-settings adapter (#2304) is index-preserving, so #2301's record gate stays aligned.
  const { records, repairs } = opts.records
    ? { records: opts.records, repairs: opts.repairs }
    : readCloudRecords(text);
  return { ...parseActivityRecords(records.map(adaptAzureDiagnosticActivity), text, opts), repairs };
}

function parseActivityRecords(
  all: Row[],
  text: string,
  opts: CloudActivityImportOptions,
): CloudActivityParseResult {
  const maxIocs = opts.maxIocs ?? 5000;
  const total = all.length;
  if (total === 0) {
    return { events: [], iocs: [], total: 0, kept: 0, dropped: 0, groups: 0, format: "empty", coverage: [] };
  }
  const gate = opts.recordGate;
  // Every NEW record (#2301): a duplicate is blanked in place, so it maps to nothing, joins no
  // summary, and every `record:<index>` locator still points into the original upload.
  const records = gateRecords(gate, all);

  const iocSink = new Map<string, SiemIoc>();
  const mapped: MappedEvent[] = [];
  const gcpRecords: Row[] = [];
  const azureRecords: Row[] = [];
  let sawGcp = false,
    sawAzure = false,
    sigmaRows = 0;

  // Over the whole upload: coverage describes the export itself, duplicates included (#2301).
  const indexBase = opts.recordIndexBase ?? 0;
  const rowRecords: number[] = [];
  const noteRows = (recordIndex: number) => {
    while (rowRecords.length < mapped.length) rowRecords.push(recordIndex);
  };
  all.forEach((rec, recordIndex) => {
    const duplicate = isDuplicateRecord(gate, recordIndex);
    if (isGcp(rec)) {
      gcpRecords.push(rec);
      if (duplicate) return;
      const rows = gradeGcpRows(
        gateRows(gate, recordIndex, mapGcp(rec, iocSink, `record:${indexBase + recordIndex}`)),
        rec,
        opts,
        () => sigmaRows++,
      );
      if (rows.length) sawGcp = true;
      // No methodName: the record is never mapped (#1736).
      else opts.debug?.skipped("missing_required_field");
      mapped.push(...rows);
      noteRows(recordIndex);
    } else if (isAzure(rec)) {
      azureRecords.push(rec);
      if (duplicate) return;
      const m = mapAzure(rec, iocSink, indexBase + recordIndex, opts.debug);
      if (m) {
        sawAzure = true;
        mapped.push(...gateRows(gate, recordIndex, [m]));
        noteRows(recordIndex);
      } else opts.debug?.skipped("missing_required_field");
    } else opts.debug?.skipped("unrecognized_record");
  });
  // Coverage (#1063): every GCP/Azure record this upload states about itself, regardless of
  // whether it mapped to a timeline row.
  const uploadId = sourceArtifactHash(text);
  const coverage: CloudCoverageDraft[] = [
    ...gcpCoverage(gcpRecords).map((d) => ({ ...d, uploadId })),
    ...azureCoverage(azureRecords).map((d) => ({ ...d, uploadId })),
  ];
  if (sigmaRows) opts.debug?.observed("sigma_match", sigmaRows);
  if (opts.rowsOnly) {
    const format = sawGcp && sawAzure ? "mixed" : sawGcp ? "gcp" : sawAzure ? "azure" : "empty";
    const iocs = [...iocSink.values()].slice(0, maxIocs);
    const sigmaRowsMatched = sigmaRows;
    return {
      events: [],
      iocs,
      total,
      kept: 0,
      dropped: 0,
      groups: 0,
      format,
      coverage,
      mapped,
      rowRecords,
      sigmaRowsMatched,
    };
  }
  if (mapped.length === 0) {
    return { events: [], iocs: [], total, kept: 0, dropped: total, groups: 0, format: "empty", coverage };
  }

  const aggregated = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? maxEventsDefault(),
    provenance: opts.provenance,
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
  // The Azure VM / GCP instance compute-lifecycle joins (#931 item 8 second half, #1066): the
  // same append-after-the-cap pattern as the per-service-account join above, each under its own
  // bound. Over the FULL original `records` array, never the pre-split azureRecords/gcpRecords —
  // each join's own scan() already does its own provider-appropriate filtering (mirroring
  // gcpServiceAccountJoins' own convention), and a `record:${index}` locator must be the index
  // into the ORIGINAL upload, not into a filtered array, or a mixed-provider upload's two joins
  // would both cite "record:0" for two different raw records (Codex code review, finding #3).
  const azureLifecycles = sawAzure
    ? aggregateEvents(azureComputeLifecycles(records, uploadId), {
        aggregate: opts.aggregate,
        minSeverity: opts.minSeverity,
        maxEvents: AZURE_COMPUTE_MAX + 1,
      }).events
    : [];
  // The VMSS-member half (#1078) — its own scan() self-filters to the VMSS resourceId shape
  // (never colliding with the standalone parser above), so it is safe to run unconditionally
  // alongside it over the SAME full records array, for the same mixed-provider-locator reason.
  const azureVmssLifecycles = sawAzure
    ? aggregateEvents(azureVmssComputeLifecycles(records, uploadId), {
        aggregate: opts.aggregate,
        minSeverity: opts.minSeverity,
        maxEvents: VMSS_COMPUTE_MAX + 1,
      }).events
    : [];
  const gcpLifecycles = sawGcp
    ? aggregateEvents(gcpComputeLifecycles(records, uploadId), {
        aggregate: opts.aggregate,
        minSeverity: opts.minSeverity,
        maxEvents: GCP_COMPUTE_MAX + 1,
      }).events
    : [];
  const rows = [
    ...aggregated.events,
    ...summaries,
    ...azureLifecycles,
    ...azureVmssLifecycles,
    ...gcpLifecycles,
  ];
  // The hash of the parsed text on every row (#2353), as whole-file CloudTrail does. A parse with
  // no text (the streaming providers) stamps nothing: the stream stamps its own reader's hash.
  const events = text ? stampSourceArtifactHash(rows, text) : rows;
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
    sigmaRowsMatched: sigmaRows,
  };
}
