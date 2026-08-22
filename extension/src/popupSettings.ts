import {
  DEFAULT_SETTINGS,
  normalizeCompanionUrl,
  type Settings,
} from "./types.js";

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
  dedupThreshold: string;
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
    intervalSeconds: Math.max(
      5,
      Number(form.intervalSeconds) || DEFAULT_SETTINGS.intervalSeconds,
    ),
    dedupThreshold: Math.max(
      0,
      Number(form.dedupThreshold) || DEFAULT_SETTINGS.dedupThreshold,
    ),
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
