import { isLockedRejection } from "./casePasswordSession.js";

// Refusals that are about WHO is asking or the case's server-side state, not about the screenshot
// itself (#2254). The capture is evidence and must be kept: a missing, expired or rotated service
// token (401), a case role that cannot capture (403), or a case whose capture log needs repair
// (409 with that code, #2252). Retrying later — after the analyst fixes the token, role or log —
// can succeed, so these are never dropped.

/** The body `code` the companion sends when the case capture log must be repaired first (#2252). */
export const CAPTURE_LOG_NEEDS_REPAIR = "capture-log-needs-repair";

/**
 * Team auth answers 404 with this exact message when the token cannot see the case, so a hidden
 * case cannot be told apart from a deleted one by status alone. Only the message distinguishes it.
 */
export const ACCESS_DENIED_404_MESSAGE = "case not found or access denied";

/** The live capture should be queued (held) rather than rejected. A locked 401 has its own path. */
export function isHeldRefusal(status: number, errorMessage?: string, errorCode?: string): boolean {
  if (status === 401) return !isLockedRejection(status, errorMessage);
  if (status === 403) return true;
  return status === 409 && errorCode === CAPTURE_LOG_NEEDS_REPAIR;
}

/**
 * A capture already in the queue should be kept and skipped (not dropped, not retried). Wider than
 * isHeldRefusal: after a token or case switch, a queued capture for the old case can get team
 * auth's 404 — which may mean "no access", not "case gone".
 */
export function isKeptQueuedRefusal(status: number, errorMessage?: string, errorCode?: string): boolean {
  if (isHeldRefusal(status, errorMessage, errorCode)) return true;
  return status === 404 && errorMessage === ACCESS_DENIED_404_MESSAGE;
}
