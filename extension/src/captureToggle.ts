import type { Settings } from "./types.js";

/**
 * Why the keyboard shortcut may not turn capture ON, or undefined when it may.
 *
 * The case is checked first (#2257): without one, the shortcut used to set the red REC badge while
 * every capture returned "select a case", so the badge claimed recording that never happened. The
 * popup's Start button already refuses to start without a case.
 */
export function startCaptureBlockReason(
  settings: Pick<Settings, "caseId">,
  hasSiteAccess: boolean,
): string | undefined {
  if (!settings.caseId.trim()) return "select a case before capturing";
  if (!hasSiteAccess) return "site access is required; open the extension on this site";
  return undefined;
}
