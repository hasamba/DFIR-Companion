// Can this GCP account read the project's Data Access logs? (#2450). Shared by the read check and
// live collection.
//
// Data Access audit logs are "private" logs. An account without logging.privateLogEntries.list (the
// Private Logs Viewer role) gets NO error from entries:list: Google drops the private log from the
// answer and returns the rest, so "no Data Access entries" looks exactly like "none were written".
// Measured on a lab project in the #2314 run. The only way to tell is to ask Google directly:
//
//   POST https://cloudresourcemanager.googleapis.com/v1/projects/<p>:testIamPermissions
//   { "permissions": ["logging.privateLogEntries.list"] }   →   { "permissions": [<the granted ones>] }
//
// The call needs no role of its own (any caller may test its own permissions), only the
// cloud-platform.read-only scope. It reads and changes nothing. Pure.

export const PRIVATE_LOG_PERMISSION = "logging.privateLogEntries.list";

/** The OAuth scope projects.testIamPermissions accepts for a read-only caller. */
export const RESOURCE_MANAGER_READ_SCOPE = "https://www.googleapis.com/auth/cloud-platform.read-only";

/** The longest reason kept from a failed permission test. */
const REASON_MAX = 200;

export type PrivateLogAccess =
  { state: "granted" } | { state: "missing" } | { state: "unknown"; reason: string };

export function testIamPermissionsUrl(projectId: string): string {
  return `https://cloudresourcemanager.googleapis.com/v1/projects/${encodeURIComponent(projectId)}:testIamPermissions`;
}

export function testIamPermissionsBody(): { permissions: string[] } {
  return { permissions: [PRIVATE_LOG_PERMISSION] };
}

/** Google's answer, read: the permission is granted only when the answer lists it. */
export function privateLogAccessFrom(answer: unknown): PrivateLogAccess {
  const granted = (answer && typeof answer === "object" ? answer : {}) as { permissions?: unknown };
  const list = Array.isArray(granted.permissions) ? granted.permissions : [];
  return list.includes(PRIVATE_LOG_PERMISSION) ? { state: "granted" } : { state: "missing" };
}

export function unknownAccess(reason: string): PrivateLogAccess {
  return { state: "unknown", reason: reason.slice(0, REASON_MAX) || "no reason given" };
}

/** Why Data Access came back empty, when the account lacks the role. */
export const MISSING_ROLE_REASON =
  "this account lacks the Private Logs Viewer role (roles/logging.privateLogViewer), and without it " +
  "Google hides Data Access logs instead of refusing them";

/** The collection note for each Data Access page, by what the permission test said. */
export function dataAccessNote(access: PrivateLogAccess): string | undefined {
  if (access.state === "missing")
    return (
      `Data Access logs were not collected: ${MISSING_ROLE_REASON}. "No Data Access records" here ` +
      "says nothing about what happened. Grant the role and collect again."
    );
  if (access.state === "unknown")
    return (
      "Whether this account may read Data Access logs could not be tested " +
      `(${access.reason}). Without the Private Logs Viewer role Google hides them instead of ` +
      "refusing, so an empty Data Access result may mean the role is missing."
    );
  return undefined;
}
