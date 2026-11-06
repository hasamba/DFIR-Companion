// Stable identity for one cloud audit record (#2301), qualified by provider and account, so the
// same record imported twice — a re-upload, or an overlapping export window — is recognised as one.
//
// Each provider's own record id is used where the provider documents one:
//   - CloudTrail: recipientAccountId + eventID
//   - UAL: tenant (OrganizationId) + Id
//   - Graph auditLogRecord: tenant (organizationId) + id
//   - Entra sign-in: tenant + id
//   - GCP: project + timestamp + insertId (Google's own dedup identity; insertId alone is not enough)
//   - Azure Activity: subscription + eventDataId, else correlationId + operationId + eventTimestamp
//   - GuardDuty finding: account + region + Id + UpdatedAt (each update is its own observation)
// A record with no usable id is identified by the SHA-256 of its canonical form and flagged
// `hashIdentified`, so the analyst can tell a provider id from a content hash.
//
// `payloadHash` is always the canonical-form SHA-256: two records under one id whose payloads
// differ are a CONFLICT (kept and flagged), never silently collapsed. Pure.

import { createHash } from "node:crypto";
import { getCI, getPath, isObject, str } from "./siemFieldPick.js";

type Row = Record<string, unknown>;

export type CloudRecordProvider =
  | "cloudtrail"
  | "ual"
  | "graph-audit"
  | "entra-signin"
  | "entra-audit"
  | "gcp"
  | "azure-activity"
  | "guardduty";

export interface CloudRecordIdentity {
  key: string; // "<provider>|<account>|<id…>" or "<provider>|sha256:<hex>"
  payloadHash: string; // hex SHA-256 of canonicalJson(record)
  hashIdentified: boolean; // true when the record carried no usable provider id
}

/** JSON with every object's keys sorted, recursively — the same record always serialises the same. */
export function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map((v) => canonicalJson(v ?? null)).join(",")}]`;
  if (isObject(value)) {
    const keys = Object.keys(value)
      .filter((k) => value[k] !== undefined)
      .sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

function sha256(text: string): string {
  return createHash("sha256").update(text).digest("hex");
}

const text = (rec: Row, key: string): string =>
  str(key.includes(".") ? getPath(rec, key) : getCI(rec, key)).trim();
const first = (rec: Row, keys: readonly string[]): string => {
  for (const k of keys) {
    const v = text(rec, k);
    if (v) return v;
  }
  return "";
};

/** CloudTrail: recipientAccountId + eventID. */
export function cloudTrailRecordId(rec: Row): string | null {
  const id = text(rec, "eventID");
  return id ? `${text(rec, "recipientAccountId")}|${id}` : null;
}

/** UAL (Search-UnifiedAuditLog / MES): OrganizationId + Id. */
export function ualRecordId(rec: Row): string | null {
  const id = text(rec, "Id");
  return id ? `${text(rec, "OrganizationId")}|${id}` : null;
}

/** Graph auditLogRecord (AuditLogQuery): organizationId + id. */
export function graphAuditRecordId(rec: Row): string | null {
  return ualRecordId(rec);
}

/** Entra sign-in: resource (else home) tenant + id. */
export function entraSignInRecordId(rec: Row): string | null {
  const id = text(rec, "id");
  return id ? `${first(rec, ["resourceTenantId", "homeTenantId", "tenantId", "AADTenantId"])}|${id}` : null;
}

/** Entra directory audit: tenant + id. */
export function entraAuditRecordId(rec: Row): string | null {
  const id = text(rec, "id");
  return id ? `${first(rec, ["tenantId", "AADTenantId"])}|${id}` : null;
}

function gcpProject(rec: Row): string {
  const fromLog = /^projects\/([^/]+)\//.exec(text(rec, "logName"));
  return fromLog?.[1] ?? first(rec, ["resource.labels.project_id"]);
}

/** GCP Cloud Audit Log: project + timestamp + insertId. */
export function gcpRecordId(rec: Row): string | null {
  const insertId = text(rec, "insertId");
  return insertId ? `${gcpProject(rec)}|${text(rec, "timestamp")}|${insertId}` : null;
}

function azureSubscription(rec: Row): string {
  const direct = first(rec, ["subscriptionId", "SubscriptionId"]);
  if (direct) return direct.toLowerCase();
  const fromResource = /\/subscriptions\/([^/]+)/i.exec(first(rec, ["resourceId", "ResourceId"]));
  return (fromResource?.[1] ?? "").toLowerCase();
}

/** Azure Activity: subscription + eventDataId, else correlationId + operationId + eventTimestamp. */
export function azureActivityRecordId(rec: Row): string | null {
  const sub = azureSubscription(rec);
  const eventDataId = first(rec, ["eventDataId", "EventDataId"]);
  if (eventDataId) return `${sub}|${eventDataId}`;
  const correlation = first(rec, ["correlationId", "CorrelationId"]);
  const operation = first(rec, ["operationId", "OperationId"]);
  const time = first(rec, ["eventTimestamp", "EventTimestamp", "time"]);
  return correlation && operation && time ? `${sub}|${correlation}|${operation}|${time}` : null;
}

/** When a GuardDuty finding last changed: UpdatedAt, else CreatedAt — the version half of its key. */
export function guardDutyVersion(rec: Row): string {
  return text(rec, "UpdatedAt") || text(rec, "CreatedAt");
}

/**
 * GuardDuty finding (#2361): account + region + finding id + version. GuardDuty keeps a finding's id
 * while its count and update time move, so an identical re-collect is a duplicate and an updated
 * finding is a new observation — never a false "conflict" under one id.
 */
export function guardDutyRecordId(rec: Row): string | null {
  const id = text(rec, "Id");
  return id ? [text(rec, "AccountId"), text(rec, "Region"), id, guardDutyVersion(rec)].join("|") : null;
}

const ID_OF: Record<CloudRecordProvider, (rec: Row) => string | null> = {
  cloudtrail: cloudTrailRecordId,
  ual: ualRecordId,
  "graph-audit": graphAuditRecordId,
  "entra-signin": entraSignInRecordId,
  "entra-audit": entraAuditRecordId,
  gcp: gcpRecordId,
  "azure-activity": azureActivityRecordId,
  guardduty: guardDutyRecordId,
};

/** The identity of `rec` under `provider`'s id rule, falling back to a flagged content hash. */
export function cloudRecordIdentity(provider: CloudRecordProvider, rec: Row): CloudRecordIdentity {
  const payloadHash = sha256(canonicalJson(rec));
  const id = ID_OF[provider](rec);
  return id
    ? { key: `${provider}|${id}`, payloadHash, hashIdentified: false }
    : { key: `${provider}|sha256:${payloadHash}`, payloadHash, hashIdentified: true };
}

// A Graph auditLogRecord spells its fields in camelCase and carries `auditLogRecordType` /
// `auditData`; a UAL record (Search-UnifiedAuditLog, MES) carries `RecordType` / `Workload`.
function isGraphAuditRecord(rec: Row): boolean {
  return "auditLogRecordType" in rec || ("auditData" in rec && "id" in rec && !("Id" in rec));
}

/** The provider of an M365 record by the kind m365Import.ts classified it as. */
export function m365RecordProvider(kind: string, rec: Row): CloudRecordProvider {
  if (kind === "signin" || kind === "spsignin") return "entra-signin";
  if (kind === "audit") return "entra-audit";
  return isGraphAuditRecord(rec) ? "graph-audit" : "ual";
}

/** The provider of a GCP-audit / Azure-Activity record, by the same shape cloudActivityImport.ts routes on. */
export function cloudActivityRecordProvider(rec: Row): CloudRecordProvider {
  const gcp =
    !!getCI(rec, "protoPayload") || !!getCI(rec, "insertId") || /cloudaudit/i.test(text(rec, "logName"));
  return gcp ? "gcp" : "azure-activity";
}
