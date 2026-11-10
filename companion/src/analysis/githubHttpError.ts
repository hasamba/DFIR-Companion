// Explain a failed GitHub API answer (#2520). The rule and update checks call GitHub anonymously,
// which allows 60 requests per hour per IP. Past that, GitHub answers 403 (or 429) and the analyst
// used to see only "GitHub returned 403". This turns the rate-limit headers into a sentence that
// says what happened and when to try again; every other failure keeps the generic wording.
//
// Primary limit: the hourly quota is used up (x-ratelimit-remaining: 0, reset at x-ratelimit-reset).
// Secondary limit: GitHub's short-term throttling (429, or retry-after) — it says nothing about the
// hourly quota, so its message does not claim the quota is used up.
//
// The time is absolute and names its zone: the message is stored with the check result and shown
// again later, where a relative "in 5 minutes" would be wrong.

export interface GithubThrottle {
  kind: "primary" | "secondary";
  retryAt?: Date;
}

const MAX_WAIT_MS = 24 * 60 * 60 * 1000;

function header(resp: Response, name: string): string | undefined {
  const value = resp.headers?.get?.(name);
  return value == null ? undefined : value.trim();
}

/** A whole, non-negative number of seconds, or undefined. */
function seconds(value: string | undefined): number | undefined {
  if (!value || !/^\d{1,12}$/.test(value)) return undefined;
  return Number(value);
}

/** The retry time only when it is in the future and not absurdly far away. */
function plausible(at: Date, now: Date): Date | undefined {
  const wait = at.getTime() - now.getTime();
  return wait > 0 && wait <= MAX_WAIT_MS ? at : undefined;
}

export function classifyGithubThrottle(resp: Response, now = new Date()): GithubThrottle | undefined {
  if (resp.status !== 403 && resp.status !== 429) return undefined;
  if (header(resp, "x-ratelimit-remaining") === "0") {
    const reset = seconds(header(resp, "x-ratelimit-reset"));
    const retryAt = reset === undefined ? undefined : plausible(new Date(reset * 1000), now);
    return retryAt ? { kind: "primary", retryAt } : { kind: "primary" };
  }
  const retryAfterRaw = header(resp, "retry-after");
  if (resp.status === 429 || retryAfterRaw !== undefined) {
    const after = seconds(retryAfterRaw);
    const retryAt = after === undefined ? undefined : plausible(new Date(now.getTime() + after * 1000), now);
    return retryAt ? { kind: "secondary", retryAt } : { kind: "secondary" };
  }
  return undefined;
}

function clock(at: Date): string {
  return at.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", timeZoneName: "short" });
}

/** The error message for a non-OK GitHub response; `what` names the operation ("listing …"). */
export function githubErrorMessage(resp: Response, what?: string, now = new Date()): string {
  const throttle = classifyGithubThrottle(resp, now);
  if (!throttle) return what ? `GitHub returned ${resp.status} ${what}` : `GitHub returned ${resp.status}`;
  const head =
    throttle.kind === "primary"
      ? "GitHub's hourly limit for anonymous requests is used up"
      : "GitHub is temporarily limiting requests";
  const op = what ? ` (${what})` : "";
  const when = throttle.retryAt
    ? `try again after ${clock(throttle.retryAt)}`
    : throttle.kind === "primary"
      ? "try again later"
      : "try again in a few minutes";
  return `${head}${op} — ${when}`;
}
