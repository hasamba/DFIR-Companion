// The cloud tool compatibility matrix (#2300): one row per tool output file, with the importer the
// companion picks for it TODAY and the importer that should read it. The per-tool test files assert
// every `detectedToday` value against the real detector, so this table cannot drift from the code;
// matrixDocs.test.ts holds the published table in mkdocs-docs/reference/importing.md to these rows.
//
// The fixtures under tests/fixtures/cloudCompat/ are SYNTHETIC. They are built from each tool's
// documented output format, use example.com names, RFC 5737 addresses and fake ids only, and have
// not been checked against real tool output.
//
// Status, as used here and on the manual page:
//   works       — routed to an importer that maps the rows.
//   misrouted   — routed elsewhere (another importer, or the generic AI CSV path) although an
//                 existing importer maps the rows. A detection change alone moves it.
//   unsupported — no importer maps this content today: it is refused, or it reaches an importer
//                 or the generic AI path that cannot read its meaning. Needs parser work.

import { readFileSync } from "node:fs";
import { gzipSync } from "node:zlib";

export type CompatStatus = "works" | "misrouted" | "unsupported";

/** What the importer a "works" row dispatches to maps from the fixture — mandatory for that status. */
export interface ParserEvidence {
  /** Records the importer reads from the fixture (its `total`, before any aggregation). */
  records: number;
  /** Text one mapped event's description carries: the operation and who did it. */
  shows: string;
}

interface CompatRowBase {
  tool: string;
  version: string;
  /** The output file as the tool names it. */
  output: string;
  /** Fixture path under tests/fixtures/cloudCompat/. */
  fixture: string;
  /** Feed the fixture gzip-compressed, as an S3 CloudTrail object arrives. */
  gzip?: boolean;
  /** The kind the server's import route resolves today (resolveImportKind). */
  detectedToday: string;
  /** The importer that should read it, or a plain-language note when none exists yet. */
  expected: string;
  /** For misrouted rows: the importer the test forces the fixture through to prove it maps rows. */
  provenWith?: "m365";
  note: string;
}

/** A "works" row must carry parser evidence; the type and harness.ts both refuse one without it. */
export type CompatRow =
  | (CompatRowBase & { status: "works"; parsed: ParserEvidence })
  | (CompatRowBase & { status: Exclude<CompatStatus, "works">; parsed?: undefined });

const MES = { tool: "Microsoft-Extractor-Suite", version: "4.1.0" };
const O365RC = { tool: "DFIR-O365RC", version: "2.0.x" };
const LA = { tool: "Log Analytics export", version: "—" };
const DIAG = { tool: "Azure diagnostic settings", version: "—" };
const AWS = { tool: "AWS CloudTrail", version: "—" };
const GCP = { tool: "GCP Cloud Audit Logs", version: "—" };
const SNAPSHOT = "none yet — configuration snapshot (#2305)";

export const COMPAT_ROWS: readonly CompatRow[] = [
  // ── Microsoft-Extractor-Suite 4.1.0 ──
  {
    ...MES,
    output: "UAL-Combined.csv",
    fixture: "mes-4.1.0/UAL-Combined.csv",
    detectedToday: "m365",
    expected: "m365",
    status: "works",
    parsed: { records: 4, shows: "New-InboxRule by user1@example.com" },
    note: "`AuditData` column claims it.",
  },
  {
    ...MES,
    output: "UAL-Combined.json",
    fixture: "mes-4.1.0/UAL-Combined.json",
    detectedToday: "m365",
    expected: "m365",
    status: "works",
    parsed: { records: 4, shows: "New-InboxRule by user1@example.com" },
    note: "",
  },
  {
    ...MES,
    output: "UAL-Combined.jsonl",
    fixture: "mes-4.1.0/UAL-Combined.jsonl",
    detectedToday: "m365",
    expected: "m365",
    status: "works",
    parsed: { records: 4, shows: "New-InboxRule by user1@example.com" },
    note: "",
  },
  {
    ...MES,
    output: "UAL `-AuditDataOnly` JSON",
    fixture: "mes-4.1.0/UAL-Combined-AuditDataOnly.json",
    detectedToday: "m365",
    expected: "m365",
    status: "works",
    parsed: { records: 4, shows: "New-InboxRule by user1@example.com" },
    note: "",
  },
  {
    ...MES,
    output: "`<date>-<search>-UnifiedAuditLog.json` (Get-UALGraph)",
    fixture: "mes-4.1.0/20261101100000-search1-UnifiedAuditLog.json",
    detectedToday: "m365",
    expected: "m365",
    status: "works",
    parsed: { records: 4, shows: "New-InboxRule by user1@example.com" },
    note: "Graph `auditLogRecord`; the nested `auditData` is merged, and the Graph fields fill any envelope field it omits — graded like the legacy UAL record (#2304).",
  },
  {
    ...MES,
    output: "`SignInLogs*.json` (Graph signIn)",
    fixture: "mes-4.1.0/SignInLogs-20261101.json",
    detectedToday: "m365",
    expected: "m365",
    status: "works",
    parsed: { records: 2, shows: "Entra sign-in: user1@example.com" },
    note: "",
  },
  {
    ...MES,
    output: "ActivityLog.json",
    fixture: "mes-4.1.0/ActivityLog.json",
    detectedToday: "cloud",
    expected: "cloud",
    status: "works",
    parsed: { records: 2, shows: "runCommand/action by admin@example.com" },
    note: "Azure Activity Log.",
  },
  {
    ...MES,
    output: "InboxRules.csv",
    fixture: "mes-4.1.0/InboxRules.csv",
    detectedToday: "csv",
    expected: SNAPSHOT,
    status: "unsupported",
    note: "Goes to the generic AI CSV path.",
  },
  {
    ...MES,
    output: "TransportRules.csv",
    fixture: "mes-4.1.0/TransportRules.csv",
    detectedToday: "csv",
    expected: SNAPSHOT,
    status: "unsupported",
    note: "Goes to the generic AI CSV path.",
  },
  {
    ...MES,
    output: "OAuth permissions CSV",
    fixture: "mes-4.1.0/OAuthPermissions.csv",
    detectedToday: "csv",
    expected: SNAPSHOT,
    status: "unsupported",
    note: "Goes to the generic AI CSV path.",
  },
  {
    ...MES,
    output: "`mailboxAuditLog-<UPN>.csv`",
    fixture: "mes-4.1.0/mailboxAuditLog-user1@example.com.csv",
    detectedToday: "m365",
    expected: "m365",
    status: "works",
    parsed: { records: 3, shows: "HardDelete by user1@example.com" },
    note: "Claimed by `Operation` + `LogonType` + `MailboxOwnerUPN` + `LastAccessed`. The day/month order of `LastAccessed` is decided per file from a date with a part above 12 (never from AM/PM), read as naive UTC; with no such date the rows have no time, and the import note counts them.",
  },
  {
    ...MES,
    output: "MFA CSV",
    fixture: "mes-4.1.0/MFA-AuthenticationMethods.csv",
    detectedToday: "csv",
    expected: SNAPSHOT,
    status: "unsupported",
    note: "Goes to the generic AI CSV path.",
  },
  // ── DFIR-O365RC 2.0.x ──
  {
    ...O365RC,
    output: "`UnifiedAuditLog_<tenant>_YYYY-MM-DD_HH-00-00.json`",
    fixture: "dfir-o365rc-2.0/UnifiedAuditLog_example.com_2026-11-01_10-00-00.json",
    detectedToday: "m365",
    expected: "m365",
    status: "works",
    parsed: { records: 2, shows: "New-InboxRule by user1@example.com" },
    note: "",
  },
  {
    ...O365RC,
    output: "same, with the concatenated-arrays bug (`][`)",
    fixture: "dfir-o365rc-2.0/UnifiedAuditLog_example.com_2026-11-01_11-00-00.json",
    detectedToday: "m365",
    expected: "m365",
    status: "works",
    parsed: { records: 4, shows: "FileDownloaded by user2@example.com" },
    note: "Every record of both arrays is read, and the join is disclosed in the import note.",
  },
  {
    ...O365RC,
    output: "`AADSigninLog_*`",
    fixture: "dfir-o365rc-2.0/AADSigninLog_example.com_2026-11-01.json",
    detectedToday: "m365",
    expected: "m365",
    status: "works",
    parsed: { records: 2, shows: "Entra sign-in: user1@example.com" },
    note: "",
  },
  {
    ...O365RC,
    output: "`AADAuditLog_*`",
    fixture: "dfir-o365rc-2.0/AADAuditLog_example.com_2026-11-01.json",
    detectedToday: "m365",
    expected: "m365",
    status: "works",
    parsed: { records: 1, shows: "Add member to role by admin@example.com" },
    note: "",
  },
  {
    ...O365RC,
    output: "`AzRM_*`",
    fixture: "dfir-o365rc-2.0/AzRM_example.com_00000000-0000-4000-8000-000000000700_2026-11-01.json",
    detectedToday: "cloud",
    expected: "cloud",
    status: "works",
    parsed: { records: 2, shows: "runCommand/action by admin@example.com" },
    note: "Azure Activity Log.",
  },
  // ── Log Analytics exports ──
  {
    ...LA,
    output: "`SigninLogs` (JSON)",
    fixture: "log-analytics/SigninLogs.json",
    detectedToday: "m365",
    expected: "m365",
    status: "works",
    parsed: { records: 2, shows: "Entra sign-in: user1@example.com" },
    note: "`ResultType` + `UserPrincipalName` + `AppDisplayName` claim it ahead of Azure Activity. The `Status` string (or `ResultType`) is read, so a wrong password grades Medium as in Graph.",
  },
  {
    ...LA,
    output: "`SigninLogs` (CSV)",
    fixture: "log-analytics/SigninLogs.csv",
    detectedToday: "m365",
    expected: "m365",
    status: "works",
    parsed: { records: 2, shows: "Entra sign-in: user1@example.com" },
    note: "Same columns and mapping as the JSON row.",
  },
  {
    ...LA,
    output: "`AADNonInteractiveUserSignInLogs` (JSON)",
    fixture: "log-analytics/AADNonInteractiveUserSignInLogs.json",
    detectedToday: "m365",
    expected: "m365",
    status: "works",
    parsed: { records: 1, shows: "Entra sign-in: user1@example.com" },
    note: "As `SigninLogs` (JSON).",
  },
  {
    ...LA,
    output: "`AADNonInteractiveUserSignInLogs` (CSV)",
    fixture: "log-analytics/AADNonInteractiveUserSignInLogs.csv",
    detectedToday: "m365",
    expected: "m365",
    status: "works",
    parsed: { records: 1, shows: "Entra sign-in: user1@example.com" },
    note: "As `SigninLogs` (CSV).",
  },
  {
    ...LA,
    output: "`AuditLogs` (JSON)",
    fixture: "log-analytics/AuditLogs.json",
    detectedToday: "m365",
    expected: "m365",
    status: "works",
    parsed: { records: 1, shows: "Add member to role by admin@example.com" },
    note: "`ActivityDisplayName` + `InitiatedBy`/`TargetResources` claim it ahead of Azure Activity; the JSON-string columns are read.",
  },
  {
    ...LA,
    output: "`AuditLogs` (CSV)",
    fixture: "log-analytics/AuditLogs.csv",
    detectedToday: "m365",
    expected: "m365",
    status: "works",
    parsed: { records: 1, shows: "Add member to role by admin@example.com" },
    note: "Same columns and mapping as the JSON row.",
  },
  {
    ...LA,
    output: "`AzureActivity` (JSON)",
    fixture: "log-analytics/AzureActivity.json",
    detectedToday: "cloud",
    expected: "cloud",
    status: "works",
    parsed: { records: 1, shows: "Run Command on Virtual Machine by admin@example.com" },
    note: "",
  },
  {
    ...LA,
    output: "`AzureActivity` (CSV)",
    fixture: "log-analytics/AzureActivity.csv",
    detectedToday: "cloud",
    expected: "cloud",
    status: "works",
    parsed: { records: 1, shows: "Run Command on Virtual Machine by admin@example.com" },
    note: "Claimed by `OperationNameValue` + `Caller` + `CorrelationId`; rows map as the JSON export does.",
  },
  {
    ...LA,
    output: "`OfficeActivity` (JSON)",
    fixture: "log-analytics/OfficeActivity.json",
    detectedToday: "m365",
    expected: "m365",
    status: "works",
    parsed: { records: 1, shows: "New-InboxRule by user1@example.com" },
    note: "",
  },
  {
    ...LA,
    output: "`OfficeActivity` (CSV)",
    fixture: "log-analytics/OfficeActivity.csv",
    detectedToday: "m365",
    expected: "m365",
    status: "works",
    parsed: { records: 1, shows: "New-InboxRule by user1@example.com" },
    note: "Claimed by `Operation` + `RecordType` + `OfficeWorkload`.",
  },
  // ── Azure diagnostic settings → storage account ──
  {
    ...DIAG,
    output: "`PT1H.json`, Entra `SignInLogs` category",
    fixture: "azure-diagnostic/signinlogs/PT1H.json",
    detectedToday: "m365",
    expected: "m365",
    status: "works",
    parsed: { records: 1, shows: "Entra sign-in: user1@example.com" },
    note: "Claimed by an Entra (`microsoft.aadiam`) `resourceId` + Entra category + `properties`; the Graph sign-in under `properties` is unwrapped and grades like the Graph record (#2304).",
  },
  {
    ...DIAG,
    output: "`PT1H.json`, Azure resource log (Key Vault `AuditEvent`)",
    fixture: "azure-diagnostic/keyvault/PT1H.json",
    detectedToday: "cloud",
    expected: "cloud",
    status: "works",
    parsed: { records: 1, shows: "SecretGet from 203.0.113.40" },
    note: "Routing depends on `resourceId`; a record without it and without `correlationId` is not claimed.",
  },
  // ── AWS CloudTrail ──
  {
    ...AWS,
    output: "S3 object `…_CloudTrail_<region>_….json` (decompressed)",
    fixture: "aws-cloudtrail/123456789012_CloudTrail_us-east-1_20261101T1005Z_EXAMPLE0000000001.json",
    detectedToday: "aws",
    expected: "aws",
    status: "works",
    parsed: { records: 3, shows: "CreateAccessKey (iam) by user1" },
    note: "",
  },
  {
    ...AWS,
    output: "S3 object `…_CloudTrail_<region>_….json.gz` (as downloaded)",
    fixture: "aws-cloudtrail/123456789012_CloudTrail_us-east-1_20261101T1005Z_EXAMPLE0000000001.json",
    gzip: true,
    detectedToday: "unknown",
    expected: "aws",
    status: "unsupported",
    note: "Refused as binary: nothing in the import path decompresses gzip. Decompress first.",
  },
  {
    ...AWS,
    output: "Console Event history CSV",
    fixture: "aws-cloudtrail/event_history.csv",
    detectedToday: "aws",
    expected: "aws",
    status: "works",
    parsed: { records: 3, shows: "CreateAccessKey (iam) by user1" },
    note: "Claimed by `Event name` + `Event source` + `Event time`. The CSV has no identity type, ARN or request parameters, so rows read from a `CloudTrail event` column when present, else from the columns alone.",
  },
  // ── GCP ──
  {
    ...GCP,
    output: "`gcloud logging read --format=json` (array)",
    fixture: "gcp/gcloud-logging-read.json",
    detectedToday: "cloud",
    expected: "cloud",
    status: "works",
    parsed: { records: 2, shows: "CreateServiceAccountKey (iam) by admin@example.com" },
    note: "",
  },
  {
    ...GCP,
    output: "GCS sink JSON lines",
    fixture: "gcp/cloudaudit.googleapis.com/activity/2026/11/01/15-00-00_15-59-59_S0.json",
    detectedToday: "cloud",
    expected: "cloud",
    status: "works",
    parsed: { records: 2, shows: "CreateServiceAccountKey (iam) by admin@example.com" },
    note: "",
  },
];

const FIXTURES = new URL("../../fixtures/cloudCompat/", import.meta.url);

/** The fixture as the import route receives it: UTF-8 text, or a gzip read as text by the browser. */
export function fixtureText(row: CompatRow): string {
  const bytes = readFileSync(new URL(row.fixture, FIXTURES));
  return row.gzip ? gzipSync(bytes).toString("utf8") : bytes.toString("utf8");
}

/** The file name the analyst drops (the fixture's base name, plus `.gz` for a compressed row). */
export function uploadName(row: CompatRow): string {
  const base = row.fixture.slice(row.fixture.lastIndexOf("/") + 1);
  return row.gzip ? `${base}.gz` : base;
}

export function rowsFor(tool: string): CompatRow[] {
  return COMPAT_ROWS.filter((r) => r.tool === tool);
}

/** The published table's header (mkdocs-docs/reference/importing.md → "Cloud tools"). */
export const DOC_TABLE_HEADER = [
  "| Tool | Version | Output file | Detected today | Should go to | Status | Notes |",
  "|---|---|---|---|---|---|---|",
];

/** One published table line, built from the row so the page and the tests cannot disagree. */
export function docRow(r: CompatRow): string {
  const code = (k: string): string => (/^[a-z0-9]+$/.test(k) ? `\`${k}\`` : k);
  const status = r.status === "works" ? "works" : `**${r.status}**`;
  return `| ${r.tool} | ${r.version} | ${r.output} | ${code(r.detectedToday)} | ${code(r.expected)} | ${status} | ${r.note || "—"} |`;
}
