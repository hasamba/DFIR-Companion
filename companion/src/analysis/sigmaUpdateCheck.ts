// The SigmaHQ update check's result (#2204), read against the release in use now (#2389), and the
// main-branch summary it carries (#2518). Pure.

import type { SigmaMainSummary } from "./sigmaMainBranchClient.js";

export interface SigmaLatestCheck {
  checkedAt: string;
  latest?: string;
  publishedAt?: string;
  installed: string;
  updateAvailable: boolean;
  error?: string;
  /**
   * SigmaHQ's main branch (#2518): newer unreleased changes to the graded folders, so the check never
   * says "up to date" while they exist. Absent when not asked; `error` when GitHub could not answer.
   */
  main?: SigmaMainSummary | { error: string };
}

/**
 * #2389: the last check, read against the release in use NOW. A check made before an install still
 * said "New Sigma release available" after that release was installed (or the reverse after a roll
 * back). An errored check is left as it is.
 */
export function sigmaCheckAsOfNow(check: SigmaLatestCheck, installed: string): SigmaLatestCheck {
  if (check.error || !check.latest) return { ...check, installed };
  return {
    ...check,
    installed,
    updateAvailable: releaseIsUpdate(check.latest, check.publishedAt, installed),
  };
}

/**
 * Whether the latest release is an update over what is installed. Over a main-branch install
 * (#2518, "main-<date>-<sha>-unreleased") only a release published after that commit's date is.
 */
export function releaseIsUpdate(latest: string, publishedAt: string | undefined, installed: string): boolean {
  const main = /^main-(\d{4}-\d{2}-\d{2})-[0-9a-f]{7}-unreleased$/.exec(installed);
  if (!main) return latest !== installed;
  return !!publishedAt && publishedAt.slice(0, 10) > main[1];
}
