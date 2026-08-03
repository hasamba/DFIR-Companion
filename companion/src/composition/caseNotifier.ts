/**
 * Binds a `Notifier` (the transport fan-out) to THIS server's dashboard URL, so every notification
 * the app raises carries a deep link back to the case it is about. Lifted out of createApp by #416.
 *
 * FIRE-AND-FORGET IS THE CONTRACT, not an oversight. Notifications are a side channel: a Slack
 * webhook that 500s, an SMTP host that hangs, a Teams URL that rotated — none of that may surface
 * in, or delay, the request that triggered it. So this returns void, swallows the rejection into a
 * log line, and callers never await it.
 */
import { logLine } from "../logging/serverLogger.js";
import type { NotificationEvent } from "../analysis/notifications.js";
import type { Notifier } from "../integrations/notify/notifyDispatch.js";

export interface CaseNotifierDeps {
  /** Absent → dispatch is a no-op (notifications are opt-in; tests omit it). */
  notifier?: Notifier;
  /** Public base URL used to deep-link back to the dashboard. Absent → no link is added. */
  dashboardBaseUrl?: string;
}

/**
 * Returns the `dispatchNotify` every caller in the app shares: fill in the case deep link (unless
 * the event already carries its own url), hand it to the notifier, and never let a failure escape.
 */
export function createCaseNotifier(deps: CaseNotifierDeps): (event: NotificationEvent) => void {
  const caseLink = (caseId: string): string | undefined =>
    deps.dashboardBaseUrl
      ? `${deps.dashboardBaseUrl.replace(/\/+$/, "")}/dashboard?caseId=${encodeURIComponent(caseId)}`
      : undefined;

  return (event: NotificationEvent): void => {
    if (!deps.notifier) return;
    const enriched = event.url ? event : { ...event, url: caseLink(event.caseId) };
    deps.notifier
      .dispatch(enriched)
      .catch((err) => logLine(`[notify] dispatch error: ${(err as Error).message}`));
  };
}
