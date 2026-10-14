import { lockedQueueMessage, lockedQueuedMessage } from "./casePasswordSession.js";
import type { ConnectionStatus } from "./types.js";

// What the toolbar badge, the popup's last-capture line and the capture's caller are told about one
// capture attempt. Pure — the service worker applies it — so the badge logic is unit-testable.
//
// Priority: the current capture was locked > rejected / queued captures discarded ("!") > a queued
// capture for another case is waiting for its password (amber count, #2185) > normal online/offline.

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

// Captures that had been waiting in the offline queue but which the companion has now refused for
// good (their case was deleted/closed while they waited). Their loss has to be SAID (#215).
function droppedNote(status: ConnectionStatus): string {
  if (!status.dropped?.length) return "";
  const codes = [...new Set(status.dropped.map((d) => d.status))].join(", ");
  return ` · ${status.dropped.length} queued capture(s) discarded — case gone/closed (HTTP ${codes})`;
}

function baseDiag(status: ConnectionStatus, hadCredential: boolean): string {
  if (status.locked) {
    return `${lockedQueueMessage(status.queued)}${hadCredential ? " (the password was not accepted)" : ""}`;
  }
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
  // Amber "!" — this capture was rejected, and/or queued captures had to be discarded (#215).
  if (status.rejected || status.dropped?.length) return { badgeText: "!", badgeColor: AMBER };
  if (status.lockedQueuedCaseId) return { badgeText: String(status.queued), badgeColor: AMBER };
  if (!status.online) return { badgeText: "off", badgeColor: RED };
  return { badgeText: status.queued ? String(status.queued) : "", badgeColor: BLUE };
}

export function describeCaptureOutcome(status: ConnectionStatus, hadCredential: boolean): CaptureOutcome {
  const diag = baseDiag(status, hadCredential) + droppedNote(status);
  const ok = !(status.rejected || status.locked);
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
