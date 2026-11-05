// Signatures for cloud exports that carry another product's column names (#2302): Log Analytics
// tables (SigninLogs, AADNonInteractiveUserSignInLogs, AuditLogs, OfficeActivity, AzureActivity),
// the Microsoft-Extractor-Suite mailbox audit CSV, and the AWS console "Event history" CSV.
//
// Every signature is a COMBINATION of fields, never one: a Log Analytics sign-in row also carries
// OperationName + ResourceId + CorrelationId, which is exactly what the Azure Activity catch-all
// (isAzure) claims, so the JSON signatures here are asked before it. The negative collisions —
// Azure Activity (REST and PT1H.json), Sentinel rows, Velociraptor `_Source` rows, generic SIEM
// JSON — are pinned in tests/analysis/cloudExportDetect.test.ts.

import { getCI } from "./siemFieldPick.js";

type Row = Record<string, unknown>;

const present = (s: Row, key: string): boolean => {
  const v = getCI(s, key);
  return v !== undefined && v !== null && v !== "";
};

/** A Log Analytics Entra sign-in row: ResultType + UserPrincipalName + (AppDisplayName | ConditionalAccessStatus). */
export function isLogAnalyticsSignIn(s: Row): boolean {
  return (
    present(s, "ResultType") &&
    present(s, "UserPrincipalName") &&
    (present(s, "AppDisplayName") || present(s, "ConditionalAccessStatus"))
  );
}

/**
 * A Log Analytics AuditLogs row: ActivityDisplayName + (InitiatedBy | TargetResources) + OperationName.
 * Graph's directoryAudit has the first two but no OperationName, and isM365 already claims it.
 */
export function isLogAnalyticsAudit(s: Row): boolean {
  return (
    present(s, "ActivityDisplayName") &&
    (present(s, "InitiatedBy") || present(s, "TargetResources")) &&
    present(s, "OperationName")
  );
}

/** A JSON record the M365 importer reads although isAzure would claim it. */
export function isLogAnalyticsEntra(s: Row): boolean {
  return isLogAnalyticsSignIn(s) || isLogAnalyticsAudit(s);
}

// ───────────────────────────── CSV header signatures ─────────────────────────────

type CloudCsvKind = "m365" | "cloud" | "aws";

const all = (h: Set<string>, ...keys: string[]): boolean => keys.every((k) => h.has(k));
const any = (h: Set<string>, ...keys: string[]): boolean => keys.some((k) => h.has(k));

function m365ExportCsv(h: Set<string>): boolean {
  return (
    // Log Analytics SigninLogs / AADNonInteractiveUserSignInLogs
    (all(h, "resulttype", "userprincipalname") && any(h, "appdisplayname", "conditionalaccessstatus")) ||
    // Log Analytics AuditLogs
    (h.has("activitydisplayname") && any(h, "initiatedby", "targetresources")) ||
    // Log Analytics OfficeActivity: singular Operation, which the UAL CSV signature does not accept
    all(h, "operation", "recordtype", "officeworkload") ||
    // Microsoft-Extractor-Suite mailboxAuditLog-<UPN>.csv
    all(h, "operation", "logontype", "mailboxownerupn", "lastaccessed")
  );
}

/** The importer a cloud export CSV belongs to, from its lowercased header set; null when none. */
export function cloudExportCsvKind(h: Set<string>): CloudCsvKind | null {
  if (m365ExportCsv(h)) return "m365";
  // Log Analytics AzureActivity
  if (all(h, "operationnamevalue", "caller", "correlationid")) return "cloud";
  // AWS CloudTrail console "Event history" download
  if (all(h, "event name", "event source", "event time")) return "aws";
  return null;
}
