// Feedback, provenance and retry for one-click artifact pushes to the companion's /import (#2258).
// Pure helpers so the service worker (which cannot be imported in tests) stays a thin caller.
import type { PushArtifactResult } from "./types.js";

// One automatic retry, this long after the first failure. A transient outage (companion restarting,
// a 5xx, a 429 rate window) usually clears in seconds; one retry hides the blip without hammering.
export const PUSH_RETRY_DELAY_MS = 2000;

// The companion refuses any sourceUrl that is not a plain http(s) URL of at most this length (400),
// so the extension drops such a URL rather than losing the whole push over provenance.
const MAX_SOURCE_URL_LENGTH = 2048;

/** Unreachable (0), rate-limited (429) or a server error (5xx) — worth one retry. */
export function isRetryablePushStatus(status: number): boolean {
  return status === 0 || status === 429 || status >= 500;
}

const defaultSleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/** `send()`, and once more after PUSH_RETRY_DELAY_MS when the first answer is retryable. */
export async function postWithOneRetry<T extends { ok: boolean; status: number }>(
  send: () => Promise<T>,
  sleep: (ms: number) => Promise<void> = defaultSleep,
): Promise<T> {
  const first = await send();
  if (first.ok || !isRetryablePushStatus(first.status)) return first;
  await sleep(PUSH_RETRY_DELAY_MS);
  return send();
}

/** The page URL to record as the import's provenance, or undefined when the companion would refuse it. */
export function importSourceUrl(url: string | undefined): string | undefined {
  if (!url || url.length > MAX_SOURCE_URL_LENGTH) return undefined;
  try {
    const { protocol } = new URL(url);
    return protocol === "http:" || protocol === "https:" ? url : undefined;
  } catch {
    return undefined;
  }
}

/** True when the companion saved the push as evidence but did not analyze it because AI is off. */
export function isSavedNotAnalyzed(res: Pick<PushArtifactResult, "analyzed" | "reason">): boolean {
  return res.analyzed === false && res.reason === "ai-off";
}

/** The analyst-facing line for a successful push (no leading ✓ — callers add their own marker). */
export function artifactPushSuccessText(res: PushArtifactResult): string {
  if (isSavedNotAnalyzed(res)) {
    const rows = res.rows ? ` (${res.rows} rows)` : "";
    return `Saved as evidence in "${res.caseId}"${rows} — not analyzed (AI is off)`;
  }
  return `Pushed ${res.rows ? `${res.rows} rows ` : ""}to "${res.caseId}"`;
}
