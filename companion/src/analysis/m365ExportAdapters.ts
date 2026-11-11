// Normalizing adapters for M365 / Entra exports whose columns differ from the shapes the M365
// mapper reads (#2302). Detection alone does not rename a field: a Log Analytics sign-in carries its
// outcome in a `Status` JSON *string* (or the `ResultType` column), so the mapper — which reads
// `status.errorCode` — saw an unreadable status and graded a wrong password Low instead of Medium.
// Each adapter returns a NEW row in the Graph / UAL shape and leaves any other record untouched.

import { getCI, isObject, str } from "./siemFieldPick.js";
import { isLogAnalyticsAudit, isLogAnalyticsSignIn } from "./cloudExportDetect.js";
import { adaptGraphAuditRecord, isGraphAuditLogRecord } from "./graphAuditRecord.js";
import { adaptAzureDiagnosticEntra, isAzureDiagnosticEntra } from "./azureDiagnosticRecord.js";

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

/** Which of the two leading date parts is the month. Never inferred from AM/PM. */
export type DateOrder = "day-first" | "month-first";

interface LocalTime {
  a: number;
  b: number;
  y: number;
  h: number;
  mi: number;
  s: number;
}

// "a/b/yyyy h:mm[:ss] [AM|PM]" with the hour on a 24-hour clock; null when it is not that shape.
function readLocal(raw: string): LocalTime | null {
  const m = LOCAL_TIME.exec(raw.trim());
  if (!m) return null;
  const [a, b, y, h12, mi, s] = [1, 2, 3, 4, 5, 6].map((i) => Number(m[i] ?? 0));
  const ampm = (m[7] ?? "").toUpperCase();
  if (ampm && (h12 < 1 || h12 > 12)) return null;
  const h = ampm ? (h12 % 12) + (ampm === "PM" ? 12 : 0) : h12;
  return { a, b, y, h, mi, s };
}

// The only order a value can have when one part is above 12; null when both could be the month.
function ownOrder(t: LocalTime): DateOrder | null {
  if (t.a > 12 && t.b <= 12) return "day-first";
  if (t.b > 12 && t.a <= 12) return "month-first";
  return null;
}

/**
 * A PowerShell Export-Csv date as UTC ISO (naive-is-UTC), or "" when it cannot be read safely. A
 * value with a part above 12 is read in its only possible order; any other value needs the file's
 * order. AM/PM says nothing about the order: a day-first culture can use a 12-hour clock.
 */
export function exportCsvTime(raw: string, fileOrder: DateOrder | null = null): string {
  const t = readLocal(raw);
  if (!t) return "";
  const order = ownOrder(t) ?? fileOrder;
  if (!order) return "";
  const [mo, d] = order === "month-first" ? [t.a, t.b] : [t.b, t.a];
  const at = new Date(Date.UTC(t.y, mo - 1, d, t.h, t.mi, t.s));
  if (at.getUTCMonth() !== mo - 1 || at.getUTCDate() !== d || at.getUTCHours() !== t.h) return "";
  return `${t.y}-${pad(mo)}-${pad(d)}T${pad(t.h)}:${pad(t.mi)}:${pad(t.s)}Z`;
}

/** One file's date order, from every value in it; `mixed` when it holds both orders. */
export function fileDateOrder(values: readonly string[]): { order: DateOrder | null; mixed: boolean } {
  const orders = new Set(values.map((v) => readLocal(v)).map((t) => (t ? ownOrder(t) : null)));
  const dayFirst = orders.has("day-first");
  const monthFirst = orders.has("month-first");
  if (dayFirst && monthFirst) return { order: null, mixed: true };
  return { order: dayFirst ? "day-first" : monthFirst ? "month-first" : null, mixed: false };
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
function adaptMailboxAudit(rec: Row, order: DateOrder | null): Row {
  const owner = /^owner$/i.test(str(getCI(rec, "LogonType")).trim());
  const actor = owner
    ? str(getCI(rec, "MailboxOwnerUPN"))
    : str(getCI(rec, "LogonUserDisplayName")) || str(getCI(rec, "LogonUserSid"));
  const time = exportCsvTime(str(getCI(rec, "LastAccessed")), order);
  return {
    ...rec,
    Workload: "Exchange",
    ...(actor ? { UserId: actor } : {}),
    ...(time ? { CreationTime: time } : {}),
  };
}

// ───────────────────────────── UAL CSV CreationDate (#2552) ─────────────────────────────

/** Whether a raw value has the Export-Csv local date shape ("3/25/2021 12:36:42 PM"). */
export function isExportCsvLocalTime(raw: string): boolean {
  return LOCAL_TIME.test(raw.trim());
}

// A Search-UnifiedAuditLog CSV row: the outer `CreationDate` beside the `AuditData` JSON.
function isUalCsvRow(rec: Row): boolean {
  return getCI(rec, "AuditData") !== undefined && getCI(rec, "CreationDate") !== undefined;
}

// AuditData's own CreationTime, when it parses; the mapper merges it over the outer row.
function auditDataHasTime(rec: Row): boolean {
  const ad = getCI(rec, "AuditData");
  if (isObject(ad)) return !!str(getCI(ad, "CreationTime")).trim();
  if (typeof ad !== "string" || !ad.trim().startsWith("{")) return false;
  try {
    const parsed: unknown = JSON.parse(ad);
    return isObject(parsed) && !!str(getCI(parsed, "CreationTime")).trim();
  } catch {
    return false;
  }
}

// The Export-Csv local date a row carries (mailbox `LastAccessed`, UAL `CreationDate`), if any.
function localDateCell(rec: Row): string | undefined {
  if (isMailboxAuditRow(rec)) return str(getCI(rec, "LastAccessed"));
  return isUalCsvRow(rec) ? str(getCI(rec, "CreationDate")) : undefined;
}

// Whether the row's time comes from that local date: always for a mailbox row; for a UAL row only
// when neither a top-level nor an AuditData CreationTime dates it. Parses AuditData, so callers ask
// only about rows the file's order could not date.
function timeNeedsLocalDate(rec: Row): boolean {
  if (isMailboxAuditRow(rec)) return true;
  return !str(getCI(rec, "CreationTime")).trim() && !auditDataHasTime(rec);
}

// The UAL fallback time: CreationDate read in the file's order. CreationDate itself stays raw, and a
// parsed AuditData CreationTime still wins when normalizeRecord merges it over this row.
function adaptUalCsv(rec: Row, order: DateOrder | null): Row {
  if (str(getCI(rec, "CreationTime")).trim()) return rec;
  const time = exportCsvTime(str(getCI(rec, "CreationDate")), order);
  return time ? { ...rec, CreationTime: time } : rec;
}

// An ambiguous local date the file's order left unread, on a row whose time depends on it.
function isUndated(rec: Row, order: DateOrder | null): boolean {
  if (order !== null) return false;
  const t = readLocal(localDateCell(rec) ?? "");
  return t !== null && ownOrder(t) === null && timeNeedsLocalDate(rec);
}

/** The record in the shape the M365 mapper reads; any record no adapter claims comes back as is. */
export function adaptM365ExportRow(rec: Row, order: DateOrder | null = null): Row {
  if (getCI(rec, "TimeGenerated") !== undefined) {
    if (isLogAnalyticsSignIn(rec)) return adaptLogAnalytics(rec, true);
    if (isLogAnalyticsAudit(rec)) return adaptLogAnalytics(rec, false);
  }
  if (isGraphAuditLogRecord(rec)) return adaptGraphAuditRecord(rec);
  if (isAzureDiagnosticEntra(rec)) return adaptAzureDiagnosticEntra(rec);
  if (isMailboxAuditRow(rec)) return adaptMailboxAudit(rec, order);
  return isUalCsvRow(rec) ? adaptUalCsv(rec, order) : rec;
}

/** Mailbox audit and UAL CSV rows left without a time because the file's day/month order is unknown. */
export interface UndatedRows {
  rows: number;
  /** The file holds both day-first and month-first dates. */
  mixedOrders: boolean;
}

/**
 * Every record of one upload, adapted. The Export-Csv date order (mailbox `LastAccessed`, UAL
 * `CreationDate`) is decided once for the whole file (a value with a part above 12 fixes it), and
 * each ambiguous row it could not date, and that nothing else dates, is counted.
 */
export function adaptM365ExportRows(records: readonly Row[]): { rows: Row[]; undated: UndatedRows } {
  const cells = records.map(localDateCell).filter((v): v is string => v !== undefined);
  const { order, mixed } = fileDateOrder(cells);
  const rows = records.map((r) => adaptM365ExportRow(r, order));
  const undatedCount = records.filter((r) => isUndated(r, order)).length;
  return { rows, undated: { rows: undatedCount, mixedOrders: mixed } };
}

/**
 * adaptM365ExportRows' whole-file date-order decision, one batch at a time (#2303): the streaming
 * import's preliminary pass feeds every batch, and `finish()` gives the order the whole-file read
 * would pick, with the same undated-row count.
 */
export function createMailboxDateOrderLearner(): {
  add(records: readonly Row[]): void;
  finish(): { order: DateOrder | null; undated: UndatedRows };
} {
  let dayFirst = false;
  let monthFirst = false;
  let ambiguous = 0;
  return {
    add(records) {
      for (const r of records) {
        const cell = localDateCell(r);
        if (cell === undefined) continue;
        const t = readLocal(cell);
        const own = t ? ownOrder(t) : null;
        if (own === "day-first") dayFirst = true;
        else if (own === "month-first") monthFirst = true;
        else if (t && timeNeedsLocalDate(r)) ambiguous++;
      }
    },
    finish() {
      const mixed = dayFirst && monthFirst;
      const order: DateOrder | null = mixed
        ? null
        : dayFirst
          ? "day-first"
          : monthFirst
            ? "month-first"
            : null;
      return { order, undated: { rows: order === null ? ambiguous : 0, mixedOrders: mixed } };
    },
  };
}

/** The import-note clause for undated mailbox audit and UAL CSV rows; "" when every row could be dated. */
export function undatedRowsNote(u: UndatedRows | undefined): string {
  if (!u || u.rows === 0) return "";
  const mixed = u.mixedOrders ? " (it mixes day-first and month-first dates)" : "";
  return `; ${u.rows} audit row(s) have no time: the file's day/month order could not be determined${mixed}`;
}
