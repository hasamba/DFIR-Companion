// Deterministic importer for Azure Storage resource diagnostic logs (#931 item 4) — the data-plane
// half of the storage key→read correlation. Existing importers already grade the control-plane
// signal (storageAccounts/listKeys/action, High/T1552.001, in cloudActivityImport.ts); nothing
// imported the actual blob/queue/table/file reads Azure Storage itself logs, so there was nothing
// to join the key listing to.
//
// Schema (fetched live from learn.microsoft.com/azure/storage/blobs/monitor-blob-storage-reference
// — the same shape across Blob/Table/Queue/File diagnostic logs, per Microsoft's own docs):
//
//   { "time": "...", "resourceId": ".../storageAccounts/acct1/blobServices/default",
//     "category": "StorageRead", "operationName": "GetBlob", "statusCode": 200,
//     "callerIpAddress": "1.2.3.4:1111", "uri": "https://acct1.blob.core.windows.net/cont1/obj1?...",
//     "identity": { "type": "OAuth" | "Kerberos" | "SAS Key" | "Account Key" | "Anonymous",
//       "tokenHash": "<opaque, format varies by auth type — never the raw key/SAS>",
//       "requester": { "objectId", "tenantId", "upn", "uniqueName", "appId" },
//       "authorization": [{ "result": "Granted" | "Denied" }] },
//     "properties": { "accountName": "acct1" } }
//
// SECURITY: SAS auth is commonly expressed as query parameters (?sv=...&sig=...). The query
// string is stripped from `uri` before it ever touches a description, a canonical field, or an
// IOC — container/object come from the PATH ONLY.
//
// Feeds the existing #908 bulk-read pass (cloudBulkRead.ts) UNCHANGED for reads: `operationName`
// is rendered as "get blob"/"list blobs", the exact tokens that pass's `actionFromDescription`
// already anticipates for Azure. A non-2xx request never gets that label, so a denied/failed
// request can never be miscounted as a successful read (the shared pass's own lack of an outcome
// check for OTHER providers is tracked separately as #1106, not inherited here).
//
// Pure, deterministic, NO AI call.

import type { Severity } from "./stateTypes.js";
import { createCanonicalEvent } from "./canonicalEvent.js";
import { boundedAggKey, boundedTextTo } from "./aggKey.js";
import {
  extractRecords,
  aggregateEvents,
  addIoc,
  cleanIp,
  isObject,
  getCI,
  str,
  oneLine,
  normalizeTime,
  type MappedEvent,
  type SiemEvent,
  type SiemIoc,
  maxEventsDefault,
} from "./siemImport.js";

type Row = Record<string, unknown>;

export interface AzureStorageLogImportOptions {
  aggregate?: boolean;
  minSeverity?: Severity;
  maxEvents?: number;
  maxIocs?: number;
}

// No `hostname` — this is a cloud control-plane-adjacent source, not an endpoint import; matches
// M365ImportOptions'/CloudActivityImportOptions' own result shape, not SiemParseResult's.
export interface AzureStorageLogParseResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  total: number;
  kept: number;
  dropped: number;
  groups: number;
  format: string;
}

export const AZURE_STORAGE_LOG_SOURCE = "Azure Storage Logs";

// Also satisfies isAzure()'s looser check (operationName + resourceId/correlationId) in
// importDetect.ts — MUST be checked before isAzure() there, or every storage log mis-routes to
// the generic Activity Log importer, which has no idea what `identity.tokenHash`/`GetBlob` mean.
export function isAzureStorageLog(s: Row): boolean {
  return (
    /^storage(?:read|write|delete)$/i.test(str(getCI(s, "category")).trim()) && isObject(getCI(s, "identity"))
  );
}

// ───────────────────────────── value helpers ─────────────────────────────

const READ_OPS =
  /^(?:getblob|getblobproperties|getblobmetadata|downloadblob|readfile|getfile|queryblobcontents|getentity|querytable|getmessages|peekmessages)$/i;
const LIST_OPS =
  /^(?:listblobs|listblobsflatsegment|listblobshierarchysegment|listcontainers|listfileshares|listqueues|querytables|querytable)$/i;
const WRITE_OPS =
  /^(?:putblob|putblock|putblocklist|appendblock|createfile|putfile|insertentity|putmessage|createqueue|createshare|createcontainer)$/i;
const DELETE_OPS =
  /^(?:deleteblob|deletecontainer|deletefile|deleteshare|deletequeue|deleteentity|clearmessages)$/i;

/** operationName -> the exact "get blob"/"list blobs" tokens cloudBulkRead.ts's regex expects. */
function renderReadAction(op: string): string {
  const k = op.trim().toLowerCase();
  if (LIST_OPS.test(k)) return "list blobs";
  if (READ_OPS.test(k)) return "get blob";
  return "";
}

function renderWriteAction(op: string): string {
  const k = op.trim().toLowerCase();
  if (DELETE_OPS.test(k)) return "delete blob";
  if (WRITE_OPS.test(k)) return "put blob";
  return op.trim();
}

const MECHANISM_MAP: Record<string, string> = {
  oauth: "oauth",
  kerberos: "kerberos",
  "sas key": "sas",
  sas: "sas",
  "account key": "account-key",
  accountkey: "account-key",
  anonymous: "anonymous",
};

function normalizeMechanism(rawType: string): string {
  return MECHANISM_MAP[rawType.trim().toLowerCase()] ?? "unknown";
}

/** Strips the query string (SAS signatures live there) and returns container/object from the path only. */
function containerObjectFromUri(uri: string): { container: string; object: string } {
  const noQuery = (uri ?? "").split("?")[0] ?? "";
  let path = noQuery;
  const hostMatch = /^[a-z]+:\/\/[^/]+(\/.*)?$/i.exec(noQuery);
  if (hostMatch) path = hostMatch[1] ?? "";
  const parts = path.split("/").filter(Boolean);
  if (parts.length === 0) return { container: "", object: "" };
  return { container: parts[0], object: parts.slice(1).join("/") };
}

// Azure's `callerIpAddress` carries a trailing port — "1.2.3.4:1111" for IPv4, or the bracketed
// "[2001:db8::1]:1111" form for IPv6. Naively splitting on the first colon (Codex review, P2)
// truncated every IPv6 address to its first hextet, which `cleanIp` then rejected outright.
function stripPort(raw: string): string {
  const v = (raw ?? "").trim();
  const bracketed = /^\[([^\]]+)\](?::\d+)?$/.exec(v);
  if (bracketed) return bracketed[1];
  // A single colon before trailing digits is an IPv4:port suffix; more than one colon with no
  // brackets is a bare (portless) IPv6 address and must be kept whole.
  if ((v.match(/:/g) ?? []).length === 1) return v.split(":")[0];
  return v;
}

function isDenied(identity: Row): boolean {
  const auth = getCI(identity, "authorization");
  if (!Array.isArray(auth)) return false;
  return auth.some((a) => isObject(a) && /denied/i.test(str(getCI(a, "result"))));
}

// ───────────────────────────── per-record mapping ─────────────────────────────

export function mapAzureStorageLogRecord(
  rec: Row,
  sink: Map<string, SiemIoc>,
  recordIndex: number,
): MappedEvent | null {
  const category = str(getCI(rec, "category")).trim();
  if (!/^storage(?:read|write|delete)$/i.test(category)) return null;

  const op = oneLine(str(getCI(rec, "operationName"))).trim();
  if (!op) return null;

  const observed = str(getCI(rec, "time")).trim();
  const timestamp = normalizeTime(observed);

  const statusCode = Number(getCI(rec, "statusCode"));
  const success = Number.isFinite(statusCode) && statusCode >= 200 && statusCode < 300;

  const ip = cleanIp(stripPort(str(getCI(rec, "callerIpAddress"))));
  if (ip) addIoc(sink, "ip", ip);

  const uri = str(getCI(rec, "uri")).trim();
  const { container, object } = containerObjectFromUri(uri);
  const properties = getCI(rec, "properties");
  const accountName = isObject(properties) ? str(getCI(properties, "accountName")).trim() : "";
  const resource = [accountName, container, object].filter(Boolean).join("/") || accountName;

  const identity = getCI(rec, "identity");
  const identityObj = isObject(identity) ? identity : {};
  const mechanism = normalizeMechanism(str(getCI(identityObj, "type")));
  // Never the raw key/SAS — Azure's own tokenHash is already an opaque, non-reversible fingerprint,
  // though its FORMAT varies by auth type (a compound value for Account Key/SAS, a bare hash for
  // OAuth) — stored verbatim, never re-labelled as "a SHA-256 hash".
  const tokenHash = oneLine(str(getCI(identityObj, "tokenHash"))).trim();
  const requester = getCI(identityObj, "requester");
  const requesterName = isObject(requester)
    ? str(getCI(requester, "upn")).trim() ||
      str(getCI(requester, "uniqueName")).trim() ||
      str(getCI(requester, "objectId")).trim()
    : "";
  const denied = isDenied(identityObj);

  let action = "";
  let severity: Severity = "Info";
  const mitre: string[] = [];
  if (/^storageread$/i.test(category)) {
    // Only a genuinely successful request gets the action label cloudBulkRead.ts groups on — a
    // denied/failed read must never be counted as a successful one (Codex design review finding).
    action = success ? renderReadAction(op) : "";
    severity = success ? "Low" : "Info";
  } else {
    action = renderWriteAction(op);
    severity = denied || mechanism === "anonymous" ? "Medium" : "Info";
    if (denied) mitre.push("T1530");
  }
  if (!action) action = op;

  let description = `Azure Storage ${op} (${category})`;
  if (accountName) description += ` on ${accountName}`;
  if (container) description += `/${container}${object ? `/${object}` : ""}`;
  description += ` via ${mechanism}`;
  if (requesterName) description += ` by ${requesterName}`;
  if (ip) description += ` from ${ip}`;
  if (!success) description += ` [statusCode ${Number.isFinite(statusCode) ? statusCode : "unknown"}]`;
  if (denied) description += " [authorization denied]";
  description = boundedTextTo(description, 600);

  return {
    timestamp,
    description,
    severity,
    mitre,
    // Codex review (P1): the reader's identity (requester name, credential fingerprint, source
    // IP) MUST be in the key — cloudBulkRead.ts's own grouping is explicitly principal + credential
    // + source, and without these dimensions here two different readers of the same object
    // collapse into one row, with only the first reader's identity surviving.
    aggKey: boundedAggKey(
      `azure-storage|${op}|${accountName}|${container}|${object}|${mechanism}|${success ? "ok" : "fail"}|${requesterName}|${tokenHash}|${ip}`.toLowerCase(),
    ),
    sources: [AZURE_STORAGE_LOG_SOURCE],
    srcIp: ip || undefined,
    canonical: createCanonicalEvent({
      event: {
        category: "cloud",
        type: "storage-object-op",
        // The RENDERED action (Codex review, P1) — readCloudRecord() in cloudBulkRead.ts prefers
        // canonical.event.action over description parsing, and its regex only matches "get
        // blob"/"list blobs", never the raw unspaced operationName. Storing `op` here silently
        // made every successful Azure Storage read invisible to the bulk-read pass.
        action,
        outcome: success ? "success" : "failure",
      },
      ...(requesterName ? { actor: { kind: "account", name: requesterName } } : {}),
      ...(ip ? { network: { source: { address: ip } } } : {}),
      cloud: { provider: "azure", ...(resource ? { resource } : {}) },
      authentication: {
        mechanism,
        ...(tokenHash ? { credentialId: tokenHash } : {}),
      },
      time: { observed, normalized: timestamp },
      evidence: { rawRecords: [{ source: "azure-storage-log", locator: `record:${recordIndex}` }] },
      producer: {
        importer: "azure-storage-log",
        parserVersion: "1",
        mappingVersion: "azure-storage-log-v1",
        ruleVersions: ["azure-storage-log-v1"],
      },
    }),
  };
}

// ───────────────────────────── record extraction ─────────────────────────────

function extractAzureStorageLog(text: string): Row[] {
  const { records } = extractRecords(text);
  return records.filter(isObject);
}

// ───────────────────────────── top level ─────────────────────────────

export function parseAzureStorageLog(
  text: string,
  opts: AzureStorageLogImportOptions = {},
): AzureStorageLogParseResult {
  const records = extractAzureStorageLog(text);
  const maxIocs = opts.maxIocs ?? 5000;
  const sink = new Map<string, SiemIoc>();
  const mapped: MappedEvent[] = [];

  records.forEach((rec, index) => {
    const m = mapAzureStorageLogRecord(rec, sink, index);
    if (m) mapped.push(m);
  });

  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? maxEventsDefault(),
  });

  const represented = events.reduce((n, e) => n + (e.count ?? 1), 0);

  return {
    events,
    iocs: [...sink.values()].slice(0, maxIocs),
    total: records.length,
    kept: events.length,
    dropped: Math.max(0, records.length - represented),
    groups,
    format: "azure-storage-log",
  };
}
