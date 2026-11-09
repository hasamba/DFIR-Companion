// GCP read check (#2309). Every call it makes is a read: once per source,
//
//   POST https://logging.googleapis.com/v2/entries:list   one page of one entry
//
// and, only when Data Access comes back empty (#2450), one permission test:
//
//   POST https://cloudresourcemanager.googleapis.com/v1/projects/<p>:testIamPermissions
//
// (entries:list is a POST because the filter travels in the body; it reads and changes nothing.)
// The sign-in — a token for the service account — happens inside the auth client on that call.
//
//   "audit-logs"        Admin Activity, System Event and Policy logs  (roles/logging.viewer)
//   "data-access-logs"  Data Access logs                              (roles/logging.privateLogViewer)
//
// An answer with no Data Access entry does not prove that role. Worse, an account WITHOUT the role
// gets the same empty answer, not an error: Google hides the private log (#2450). So an empty
// answer asks Google whether the account holds the permission. Missing → failed, naming the role.
// Held → not tested (the project wrote no Data Access logs). The test itself failed → not tested,
// and the reason says the role may be missing.

import {
  CHECK_CALL_TIMEOUT_MS,
  sourceResult,
  type GcpCheckSource,
  type SourceCheckResult,
} from "./readCheckTypes.js";
import { checkFailureReason } from "./readCheckWording.js";
import {
  MISSING_ROLE_REASON,
  looksLikeResourceManagerOff,
  privateLogAccessFrom,
  resourceManagerOffReason,
  testIamPermissionsBody,
  testIamPermissionsUrl,
  unknownAccess,
  type PrivateLogAccess,
} from "../cloudTransport/googlePrivateLogs.js";

export const GCP_ENTRIES_LIST_URL = "https://logging.googleapis.com/v2/entries:list";

/** The structural part of a google-auth-library AuthClient the check uses. */
export interface GcpRequester {
  request(options: {
    url: string;
    method: "POST";
    data: unknown;
    timeout: number;
  }): Promise<{ data?: unknown }>;
}

export interface GcpCheckInput {
  projectId: string;
  sources: GcpCheckSource[];
  secrets: readonly string[];
  /** The time of the check; the filter looks back LOOKBACK_DAYS from it. */
  now?: Date;
}

const LOOKBACK_DAYS = 30;
const DAY_MS = 86_400_000;

const SOURCE_LOGS: Readonly<Record<GcpCheckSource, readonly string[]>> = {
  "audit-logs": ["activity", "system_event", "policy"],
  "data-access-logs": ["data_access"],
};

/** The entries:list filter for one source: its audit logs, over the lookback window. */
export function gcpCheckFilter(projectId: string, source: GcpCheckSource, now: Date): string {
  const names = SOURCE_LOGS[source].map(
    (l) => `"projects/${projectId}/logs/cloudaudit.googleapis.com%2F${l}"`,
  );
  const since = new Date(now.getTime() - LOOKBACK_DAYS * DAY_MS).toISOString();
  return `logName=(${names.join(" OR ")}) AND timestamp>="${since}"`;
}

async function privateLogAccess(client: GcpRequester, input: GcpCheckInput): Promise<PrivateLogAccess> {
  try {
    const res = await client.request({
      url: testIamPermissionsUrl(input.projectId),
      method: "POST",
      data: testIamPermissionsBody(),
      timeout: CHECK_CALL_TIMEOUT_MS,
    });
    return privateLogAccessFrom(res.data);
  } catch (err) {
    const reason = checkFailureReason(err, input.secrets);
    const details = JSON.stringify((err as { response?: { data?: unknown } } | null)?.response?.data ?? "");
    if (looksLikeResourceManagerOff(`${reason} ${details}`))
      return unknownAccess(resourceManagerOffReason(input.projectId));
    return unknownAccess(reason);
  }
}

/** An empty Data Access answer: the project wrote none, or Google hid them (#2450). */
async function emptyDataAccess(client: GcpRequester, input: GcpCheckInput): Promise<SourceCheckResult> {
  const source = "data-access-logs";
  const access = await privateLogAccess(client, input);
  if (access.state === "missing") return sourceResult(source, "failed", MISSING_ROLE_REASON);
  const none = `the last ${LOOKBACK_DAYS} days hold no Data Access entry, so reading them could not be proven`;
  if (access.state === "granted") return sourceResult(source, "not-tested", none);
  return sourceResult(
    source,
    "not-tested",
    `${none}; whether the account holds the Private Logs Viewer role could not be tested ` +
      `(${access.reason}), and without it Google hides Data Access logs instead of refusing them`,
  );
}

async function checkOne(
  client: GcpRequester,
  input: GcpCheckInput,
  source: GcpCheckSource,
): Promise<SourceCheckResult> {
  const data = {
    resourceNames: [`projects/${input.projectId}`],
    filter: gcpCheckFilter(input.projectId, source, input.now ?? new Date()),
    orderBy: "timestamp desc",
    pageSize: 1,
  };
  try {
    const res = await client.request({
      url: GCP_ENTRIES_LIST_URL,
      method: "POST",
      data,
      timeout: CHECK_CALL_TIMEOUT_MS,
    });
    const entries = (res.data as { entries?: unknown[] } | undefined)?.entries;
    const empty = !Array.isArray(entries) || entries.length === 0;
    if (source === "data-access-logs" && empty) return emptyDataAccess(client, input);
    return sourceResult(source, "succeeded");
  } catch (err) {
    return sourceResult(source, "failed", checkFailureReason(err, input.secrets));
  }
}

/** Runs the GCP check: one entries:list page per selected source, in order. */
export async function runGcpReadCheck(
  client: GcpRequester,
  input: GcpCheckInput,
): Promise<SourceCheckResult[]> {
  const results: SourceCheckResult[] = [];
  for (const source of input.sources) results.push(await checkOne(client, input, source));
  return results;
}
