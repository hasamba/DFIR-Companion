// Normalizing adapters for M365 / Entra exports whose columns differ from the shapes the M365
// mapper reads (#2302). Detection alone does not rename a field: a Log Analytics sign-in carries its
// outcome in a `Status` JSON *string* (or the `ResultType` column), so the mapper — which reads
// `status.errorCode` — saw an unreadable status and graded a wrong password Low instead of Medium.
// Each adapter returns a NEW row in the Graph / UAL shape and leaves any other record untouched.

import { getCI, isObject, str } from "./siemFieldPick.js";
import { isLogAnalyticsAudit, isLogAnalyticsSignIn } from "./cloudExportDetect.js";

type Row = Record<string, unknown>;

// Log Analytics "dynamic" columns arrive as JSON text in a CSV and often in a JSON export too.
// Each is re-keyed to the Graph property the mapper reads.
const LA_DYNAMIC: Record<string, string> = {
  status: "status",
  locationdetails: "location",
  devicedetail: "deviceDetail",
  initiatedby: "initiatedBy",
  targetresources: "targetResources",
  additionaldetails: "additionalDetails",
  conditionalaccesspolicies: "conditionalAccessPolicies",
  authenticationdetails: "authenticationDetails",
  mfadetail: "mfaDetail",
};

function parseDynamic(v: unknown): unknown {
  if (typeof v !== "string") return v;
  const t = v.trim();
  if (t[0] !== "{" && t[0] !== "[") return v;
  try {
    return JSON.parse(t);
  } catch {
    return v;
  }
}

function graphKeys(rec: Row): Row {
  return Object.fromEntries(
    Object.entries(rec).map(([k, v]) => {
      const graph = LA_DYNAMIC[k.toLowerCase()];
      return graph ? [graph, parseDynamic(v)] : [k, v];
    }),
  );
}

// The sign-in outcome: the parsed Status when it holds an errorCode, else ResultType/ResultDescription.
function signInStatus(row: Row, rec: Row): Row | undefined {
  const status = row.status;
  if (isObject(status) && getCI(status, "errorCode") != null) return status;
  const code = str(getCI(rec, "ResultType")).trim();
  if (!code) return undefined;
  return {
    errorCode: /^\d+$/.test(code) ? Number(code) : code,
    failureReason: str(getCI(rec, "ResultDescription")),
  };
}

function adaptLogAnalytics(rec: Row, signIn: boolean): Row {
  const row = graphKeys(rec);
  if (!signIn) return row;
  const status = signInStatus(row, rec);
  const created = str(getCI(rec, "CreatedDateTime")) || str(getCI(rec, "TimeGenerated"));
  return {
    ...row,
    ...(status ? { status } : {}),
    ...(created ? { createdDateTime: created } : {}),
  };
}

// ───────────────────────────── MES mailbox audit CSV ─────────────────────────────

const LOCAL_TIME = /^(\d{1,2})\/(\d{1,2})\/(\d{4})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*([AP]M)?$/i;
const pad = (n: number): string => String(n).padStart(2, "0");

/**
 * A PowerShell Export-Csv date as UTC ISO (naive-is-UTC), or "" when it cannot be read safely.
 * With AM/PM it is the en-US culture, month first. Without it, the order is decided only when one
 * part is above 12; `1/2/2026` stays unread rather than risk a month/day swap.
 */
export function exportCsvTime(raw: string): string {
  const m = LOCAL_TIME.exec(raw.trim());
  if (!m) return "";
  const [a, b, y, h12, mi, s] = [1, 2, 3, 4, 5, 6].map((i) => Number(m[i] ?? 0));
  const ampm = (m[7] ?? "").toUpperCase();
  const monthFirst = ampm !== "" || (b > 12 && a <= 12);
  if (!monthFirst && !(a > 12 && b <= 12)) return "";
  const [mo, d] = monthFirst ? [a, b] : [b, a];
  const h = ampm ? (h12 % 12) + (ampm === "PM" ? 12 : 0) : h12;
  if (ampm && (h12 < 1 || h12 > 12)) return "";
  const t = new Date(Date.UTC(y, mo - 1, d, h, mi, s));
  if (t.getUTCMonth() !== mo - 1 || t.getUTCDate() !== d || t.getUTCHours() !== h) return "";
  return `${y}-${pad(mo)}-${pad(d)}T${pad(h)}:${pad(mi)}:${pad(s)}Z`;
}

function isMailboxAuditRow(rec: Row): boolean {
  return (
    !!str(getCI(rec, "Operation")) &&
    !!str(getCI(rec, "MailboxOwnerUPN")) &&
    getCI(rec, "LogonType") !== undefined &&
    getCI(rec, "LastAccessed") !== undefined &&
    getCI(rec, "CreationTime") === undefined &&
    getCI(rec, "AuditData") === undefined
  );
}

// The actor: the owner's UPN on an owner logon, else the delegate or admin who logged on.
function adaptMailboxAudit(rec: Row): Row {
  const owner = /^owner$/i.test(str(getCI(rec, "LogonType")).trim());
  const actor = owner
    ? str(getCI(rec, "MailboxOwnerUPN"))
    : str(getCI(rec, "LogonUserDisplayName")) || str(getCI(rec, "LogonUserSid"));
  const time = exportCsvTime(str(getCI(rec, "LastAccessed")));
  return {
    ...rec,
    Workload: "Exchange",
    ...(actor ? { UserId: actor } : {}),
    ...(time ? { CreationTime: time } : {}),
  };
}

/** The record in the shape the M365 mapper reads; any record no adapter claims comes back as is. */
export function adaptM365ExportRow(rec: Row): Row {
  if (getCI(rec, "TimeGenerated") !== undefined) {
    if (isLogAnalyticsSignIn(rec)) return adaptLogAnalytics(rec, true);
    if (isLogAnalyticsAudit(rec)) return adaptLogAnalytics(rec, false);
  }
  return isMailboxAuditRow(rec) ? adaptMailboxAudit(rec) : rec;
}
