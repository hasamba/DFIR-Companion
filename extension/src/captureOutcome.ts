import { lockedQueueMessage, lockedQueuedMessage } from "./casePasswordSession.js";
import { CAPTURE_LOG_NEEDS_REPAIR } from "./captureRefusal.js";
import type { ConnectionStatus, DroppedCapture } from "./types.js";

// What the toolbar badge, the popup's last-capture line and the capture's caller are told about one
// capture attempt. Pure — the service worker applies it — so the badge logic is unit-testable.
//
// Priority: the current capture was locked > held for access (amber count, #2254) > rejected /
// queued captures discarded ("!") > a queued capture for another case is waiting for its password
// (#2185) or was kept for access (#2254) (amber count) > normal online/offline.

const AMBER = "#d18616";
const BLUE = "#2d6cdf";
const RED = "#cc3333";

export interface CaptureOutcome {
  diag: string;
  badgeText: string;
  badgeColor: string;
  /** Forget the stored case password: it was sent with this capture and refused (#2135). */
  forgetCredential: boolean;
  /** False when the current capture was not saved (rejected, or waiting for its password). */
  ok: boolean;
  error?: string;
}

// Statuses that really mean the case is gone or closed. Anything else permanent (400, 413, …) is
// a refusal of the capture itself, and must not be blamed on the case (#2254).
const CASE_GONE: ReadonlySet<number> = new Set([404, 410, 423]);
const CHECK_ACCESS = "check the service token / case role";
const NEEDS_REPAIR = "case capture log needs repair — captures are being queued";

function codesOf(list: readonly DroppedCapture[]): string {
  return [...new Set(list.map((d) => d.status))].join(", ");
}

// Captures that had been waiting in the offline queue but which the companion has now refused for
// good (their case was deleted/closed while they waited). Their loss has to be SAID (#215).
function droppedNote(status: ConnectionStatus): string {
  if (!status.dropped?.length) return "";
  const reason = status.dropped.every((d) => CASE_GONE.has(d.status)) ? "case gone/closed" : "refused by the companion";
  return ` · ${status.dropped.length} queued capture(s) discarded — ${reason} (HTTP ${codesOf(status.dropped)})`;
}

// Queued captures refused for access (or a capture log needing repair) — KEPT, not lost (#2254).
function keptNote(status: ConnectionStatus): string {
  if (!status.kept?.length) return "";
  const repair = status.kept.filter((k) => k.errorCode === CAPTURE_LOG_NEEDS_REPAIR);
  const access = status.kept.filter((k) => k.errorCode !== CAPTURE_LOG_NEEDS_REPAIR);
  const parts = [
    ...(access.length ? [`refused (HTTP ${codesOf(access)}); ${CHECK_ACCESS}`] : []),
    ...(repair.length ? [NEEDS_REPAIR] : []),
  ];
  return ` · ${status.kept.length} queued capture(s) kept — ${parts.join("; ")}`;
}

function heldDiag(status: ConnectionStatus): string {
  const why = status.heldCode === CAPTURE_LOG_NEEDS_REPAIR
    ? ` — ${NEEDS_REPAIR}`
    : `${status.heldMessage ? ` — ${status.heldMessage}` : ""}; ${CHECK_ACCESS}`;
  return `queued (HTTP ${status.held})${why} (queued=${status.queued})`;
}

function baseDiag(status: ConnectionStatus, hadCredential: boolean): string {
  if (status.locked) {
    return `${lockedQueueMessage(status.queued)}${hadCredential ? " (the password was not accepted)" : ""}`;
  }
  if (status.held) return heldDiag(status);
  if (status.rejected) {
    return status.rejectedMessage
      ? `rejected (HTTP ${status.rejected}) — ${status.rejectedMessage}`
      : `rejected (HTTP ${status.rejected}) — case missing? create/select it in the dashboard`;
  }
  if (status.lockedQueuedCaseId) return lockedQueuedMessage(status.queued, status.lockedQueuedCaseId);
  return status.online
    ? `ok (online=true, queued=${status.queued})`
    : `offline — capture queued for retry (queued=${status.queued})`;
}

function badge(status: ConnectionStatus): { badgeText: string; badgeColor: string } {
  // Amber with the count — evidence is waiting for a case password, not lost (#2135, #2185).
  if (status.locked) return { badgeText: String(status.queued), badgeColor: AMBER };
  // Amber with the count — kept in the queue until the token / role / log is fixed (#2254).
  if (status.held) return { badgeText: String(status.queued), badgeColor: AMBER };
  // Amber "!" — this capture was rejected, and/or queued captures had to be discarded (#215).
  if (status.rejected || status.dropped?.length) return { badgeText: "!", badgeColor: AMBER };
  if (status.lockedQueuedCaseId || status.kept?.length) return { badgeText: String(status.queued), badgeColor: AMBER };
  if (!status.online) return { badgeText: "off", badgeColor: RED };
  return { badgeText: status.queued ? String(status.queued) : "", badgeColor: BLUE };
}

export function describeCaptureOutcome(status: ConnectionStatus, hadCredential: boolean): CaptureOutcome {
  const diag = baseDiag(status, hadCredential) + droppedNote(status) + keptNote(status);
  // A held capture is saved but not delivered, and needs the analyst — report it like locked.
  const ok = !(status.rejected || status.locked || status.held);
  return {
    diag,
    ...badge(status),
    // A wrong password is tried ONCE (#2135). Only the CURRENT capture's locked answer says so — a
    // queued capture for another case being locked says nothing about this case's password (#2185).
    forgetCredential: Boolean(status.locked && hadCredential),
    ok,
    ...(ok ? {} : { error: diag }),
  };
}
