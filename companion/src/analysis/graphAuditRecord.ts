// Graph `security.auditLogRecord` → the Unified Audit Log record shape the M365 mapper reads (#2304).
//
// MES `Get-UALGraph` and the Graph AuditLogQuery API (which replaces Search-UnifiedAuditLog when it
// retires) return `id, createdDateTime, auditLogRecordType, operation, service, userPrincipalName,
// clientIp, auditData`. The nested `auditData` is the original UAL record and wins for every field
// it carries; the Graph fields only fill what it leaves out. Without that fill, a record whose
// `auditData` omits the envelope rendered as "M365 audit: New-InboxRule" — and every tags.yaml rule
// keyed on "M365 Exchange:" / "M365 AzureActiveDirectory:" silently stopped firing.
// Schema: https://learn.microsoft.com/graph/api/resources/security-auditlogrecord

import { getCI, isObject, str } from "./siemFieldPick.js";

type Row = Record<string, unknown>;

// Graph's auditLogRecordType names are the Management Activity API's RecordType names. Only the
// types a decoder discriminates on are listed; any other name leaves RecordType unset rather than
// passing a string where the mapper compares a number.
const RECORD_TYPE_NUMBER: Record<string, number> = {
  exchangeadmin: 1,
  exchangeitem: 2,
  exchangeitemgroup: 3,
  sharepoint: 4,
  sharepointfileoperation: 6,
  onedrive: 7,
  azureactivedirectory: 8,
  azureactivedirectoryaccountlogon: 9,
  azureactivedirectorystslogon: 15,
  sharepointsharingoperation: 14,
  exchangeitemaggregated: 50,
};

/** A Graph auditLogRecord: its own record-type, operation and time fields, no UAL `Operation` key. */
export function isGraphAuditLogRecord(rec: Row): boolean {
  return (
    "auditLogRecordType" in rec &&
    typeof rec.operation === "string" &&
    typeof rec.createdDateTime === "string" &&
    !("Operation" in rec)
  );
}

function parsedAuditData(rec: Row): Row {
  const ad = getCI(rec, "auditData");
  if (isObject(ad)) return ad;
  if (typeof ad === "string" && ad.trim().startsWith("{")) {
    try {
      const parsed: unknown = JSON.parse(ad);
      return isObject(parsed) ? parsed : {};
    } catch {
      return {};
    }
  }
  return {};
}

function present(v: unknown): boolean {
  return v !== undefined && v !== null && str(v).trim() !== "";
}

/** The UAL envelope the Graph fields state, each key only when Graph carries a value for it. */
function graphEnvelope(rec: Row): Row {
  const recordType = RECORD_TYPE_NUMBER[str(rec.auditLogRecordType).trim().toLowerCase()];
  const pairs: Array<[string, unknown]> = [
    ["Id", rec.id],
    ["CreationTime", rec.createdDateTime],
    ["Operation", rec.operation],
    ["Workload", rec.service],
    ["UserId", present(rec.userPrincipalName) ? rec.userPrincipalName : rec.userId],
    ["ClientIP", rec.clientIp],
    ["OrganizationId", rec.organizationId],
    ["ObjectId", rec.objectId],
    ["RecordType", recordType],
  ];
  return Object.fromEntries(pairs.filter(([, v]) => present(v)));
}

/** The Graph record as a UAL record: Graph fields kept, the envelope filled, `auditData` over both. */
export function adaptGraphAuditRecord(rec: Row): Row {
  const auditData = parsedAuditData(rec);
  const rest = Object.fromEntries(Object.entries(rec).filter(([k]) => k.toLowerCase() !== "auditdata"));
  // An empty auditData value never hides the Graph field that states it.
  const filled = Object.fromEntries(Object.entries(auditData).filter(([, v]) => v !== null && v !== ""));
  return { ...rest, ...graphEnvelope(rec), ...filled };
}
