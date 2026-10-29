import {
  DEFAULT_SETTINGS,
  MIN_INTERVAL_SECONDS,
  normalizeCompanionUrl,
  type Settings,
} from "./types.js";

/**
 * The capture-timer interval to use, never under the browser's 30 s alarm floor (#2257).
 *
 * Accepts the raw form string or a stored number; a missing, zero or non-numeric value falls back
 * to the default. An interval stored by an older build (e.g. the old 10 s default) is raised.
 */
export function clampIntervalSeconds(raw: unknown): number {
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) return DEFAULT_SETTINGS.intervalSeconds;
  return Math.max(MIN_INTERVAL_SECONDS, n);
}

/**
 * The popup's editable fields, as raw strings straight out of the DOM.
 *
 * `running` is deliberately absent: capture state is owned by the service worker, not by the
 * form, so every caller supplies it from the stored settings instead of from an input.
 */
export interface PopupForm {
  caseId: string;
  companionUrl: string;
  serviceToken: string;
  intervalSeconds: string;
}

/**
 * Fold the popup form into the settings to persist.
 *
 * This is the ONLY shape the popup writes. It used to be possible to persist a mix — the case
 * dropdown saved the STORED token beside the freshly picked case id — which silently discarded a
 * token the analyst had just typed. Every import then went out with no Authorization header and
 * the companion answered 401.
 */
export function settingsFromForm(form: PopupForm, running: boolean): Settings {
  return {
    caseId: form.caseId.trim(),
    companionUrl: normalizeCompanionUrl(form.companionUrl),
    serviceToken: form.serviceToken.trim(),
    intervalSeconds: clampIntervalSeconds(form.intervalSeconds),
    running,
  };
}

/**
 * Explain why the case list could not be read.
 *
 * A rejected credential is not an unreachable companion. The popup reported every failure as
 * "companion offline", which sent analysts to restart a server that was answering perfectly — the
 * companion was in team mode and the request carried no usable token.
 *
 * @param status The HTTP status, or 0 when the fetch itself failed (no response at all).
 */
export function caseListFailure(status: number): string {
  if (status === 401) return "token rejected — check the Team service token";
  if (status === 403)
    return "token lacks access — check the token's case and permissions";
  if (status === 0) return "companion offline — start it, then Refresh";
  return `companion refused the case list (HTTP ${status})`;
}
