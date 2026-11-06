// The Cloud Logging request the GCP collector sends (#2314). Pure.
//
//   POST https://logging.googleapis.com/v2/entries:list
//   { resourceNames: ["projects/<p>"], filter, orderBy: "timestamp asc", pageSize: 1000, pageToken? }
//
// The filter is exactly the issue's: the project's four Cloud Audit Logs, `timestamp>=start` and
// `timestamp<end` (start inclusive, end exclusive — the engine's sub-windows tile without overlap).
// A logName partition (#2312) narrows it to one of the four.

import type { CollectWindow } from "../cloudCollect/collectTypes.js";
import { GCP_AUDIT_LOG_NAMES } from "../cloudCollect/collectDefaults.js";

export const GCP_ENTRIES_LIST_URL = "https://logging.googleapis.com/v2/entries:list";
/** The largest page entries:list returns. */
export const GCP_PAGE_SIZE = 1000;

export type GcpAuditLog = (typeof GCP_AUDIT_LOG_NAMES)[number];
export const GCP_AUDIT_LOGS: readonly GcpAuditLog[] = GCP_AUDIT_LOG_NAMES;

const isAuditLog = (v: string): v is GcpAuditLog => (GCP_AUDIT_LOGS as readonly string[]).includes(v);

/** The logs one request covers: all four, or the one a logName partition names. */
export function logsFor(partition: Record<string, string> | undefined): readonly GcpAuditLog[] {
  const one = partition?.logName;
  if (one === undefined) return GCP_AUDIT_LOGS;
  if (!isAuditLog(one)) throw new Error(`"${one.slice(0, 40)}" is not a GCP audit log`);
  return [one];
}

/** The full log name, URL-encoded slash and all, as Cloud Logging stores it. */
export function auditLogName(projectId: string, log: GcpAuditLog): string {
  return `projects/${projectId}/logs/cloudaudit.googleapis.com%2F${log}`;
}

export function gcpAuditFilter(
  projectId: string,
  window: CollectWindow,
  logs: readonly GcpAuditLog[],
): string {
  const names = logs.map((l) => `"${auditLogName(projectId, l)}"`).join(" OR ");
  return `logName=(${names}) AND timestamp>="${window.start}" AND timestamp<"${window.end}"`;
}

export interface EntriesListBody {
  resourceNames: string[];
  filter: string;
  orderBy: "timestamp asc";
  pageSize: number;
  pageToken?: string;
}

export function entriesListBody(
  projectId: string,
  filter: string,
  pageToken: string | undefined,
): EntriesListBody {
  return {
    resourceNames: [`projects/${projectId}`],
    filter,
    orderBy: "timestamp asc",
    pageSize: GCP_PAGE_SIZE,
    ...(pageToken ? { pageToken } : {}),
  };
}
