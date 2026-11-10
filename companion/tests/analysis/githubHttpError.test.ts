import { describe, expect, it } from "vitest";
import { classifyGithubThrottle, githubErrorMessage } from "../../src/analysis/githubHttpError.js";
import { downloadSigmaRelease, latestSigmaRelease } from "../../src/analysis/sigmaReleaseClient.js";
import { latestSigmaMainCommit } from "../../src/analysis/sigmaMainBranchClient.js";
import { performUpdateCheck } from "../../src/analysis/updateCheckRun.js";
import type { UpdateResult } from "../../src/analysis/updateCheck.js";
import type { UpdateCheckStore } from "../../src/analysis/updateCheckStore.js";

// Explain GitHub rate-limit failures (#2520): a bare "GitHub returned 403" told the analyst nothing.
// The anonymous limit (60/h per IP) is primary; GitHub's short-term throttling is secondary.

const NOW = new Date("2026-11-10T05:00:00Z");
const res = (status: number, headers: Record<string, string> = {}) => new Response(null, { status, headers });
const epoch = (d: Date) => String(Math.floor(d.getTime() / 1000));

describe("classifyGithubThrottle", () => {
  it("a 403 with no remaining requests is the primary limit, resetting at x-ratelimit-reset", () => {
    const reset = new Date("2026-11-10T05:57:00Z");
    const t = classifyGithubThrottle(
      res(403, { "x-ratelimit-remaining": "0", "x-ratelimit-reset": epoch(reset) }),
      NOW,
    );
    expect(t).toEqual({ kind: "primary", retryAt: reset });
  });

  it("a 429 with no headers is still throttling", () => {
    expect(classifyGithubThrottle(res(429), NOW)).toEqual({ kind: "secondary" });
  });

  it("retry-after marks secondary throttling and sets the retry time", () => {
    const t = classifyGithubThrottle(res(403, { "retry-after": "120", "x-ratelimit-remaining": "40" }), NOW);
    expect(t).toEqual({ kind: "secondary", retryAt: new Date(NOW.getTime() + 120_000) });
  });

  it("with both signals, an exhausted quota wins and uses the quota reset", () => {
    const reset = new Date("2026-11-10T05:30:00Z");
    const t = classifyGithubThrottle(
      res(403, { "x-ratelimit-remaining": "0", "x-ratelimit-reset": epoch(reset), "retry-after": "60" }),
      NOW,
    );
    expect(t).toEqual({ kind: "primary", retryAt: reset });
  });

  it("ignores a malformed, expired or far-future reset", () => {
    const bad = [
      "",
      "soon",
      "-5",
      "1e400",
      epoch(new Date("2026-11-10T04:00:00Z")),
      epoch(new Date("2026-11-20T00:00:00Z")),
    ];
    for (const value of bad) {
      const r = res(403, { "x-ratelimit-remaining": "0", "x-ratelimit-reset": value });
      expect(classifyGithubThrottle(r, NOW)).toEqual({ kind: "primary" });
    }
    expect(classifyGithubThrottle(res(429, { "retry-after": "abc" }), NOW)).toEqual({ kind: "secondary" });
  });

  it("a plain 403, a 404 and an OK response are not throttling", () => {
    expect(classifyGithubThrottle(res(403), NOW)).toBeUndefined();
    expect(classifyGithubThrottle(res(403, { "x-ratelimit-remaining": "12" }), NOW)).toBeUndefined();
    expect(classifyGithubThrottle(res(404, { "x-ratelimit-remaining": "0" }), NOW)).toBeUndefined();
    expect(classifyGithubThrottle(res(200, { "x-ratelimit-remaining": "0" }), NOW)).toBeUndefined();
  });

  it("tolerates a response-like object without headers", () => {
    expect(classifyGithubThrottle({ status: 429 } as Response, NOW)).toEqual({ kind: "secondary" });
    expect(classifyGithubThrottle({ status: 403 } as Response, NOW)).toBeUndefined();
  });
});

describe("githubErrorMessage", () => {
  // #2525: the message is stored and shown later, so the time is UTC with its date — the same on
  // every host, whatever its locale or timezone.
  const primary = (reset: Date) =>
    githubErrorMessage(
      res(403, { "x-ratelimit-remaining": "0", "x-ratelimit-reset": epoch(reset) }),
      "listing SigmaHQ releases",
      NOW,
    );

  it("names the hourly limit and an absolute UTC time with its date", () => {
    expect(primary(new Date("2026-11-10T05:57:00Z"))).toBe(
      "GitHub's hourly limit for anonymous requests is used up (listing SigmaHQ releases) — try again after 2026-11-10 05:57 UTC",
    );
  });

  it("prints the same UTC time whatever the host's timezone", () => {
    const saved = process.env.TZ;
    try {
      process.env.TZ = "America/New_York";
      expect(primary(new Date("2026-11-10T05:57:00Z"))).toMatch(/try again after 2026-11-10 05:57 UTC$/);
    } finally {
      if (saved === undefined) delete process.env.TZ;
      else process.env.TZ = saved;
    }
  });

  it("carries the next day's date when the retry time crosses midnight", () => {
    const late = new Date("2026-11-10T23:50:00Z");
    expect(githubErrorMessage(res(429, { "retry-after": "1200" }), "x", late)).toBe(
      "GitHub is temporarily limiting requests (x) — try again after 2026-11-11 00:10 UTC",
    );
  });

  it("gives the secondary limit's retry-after as a UTC time", () => {
    expect(githubErrorMessage(res(429, { "retry-after": "120" }), "x", NOW)).toBe(
      "GitHub is temporarily limiting requests (x) — try again after 2026-11-10 05:02 UTC",
    );
  });

  it("says GitHub is temporarily limiting requests for secondary throttling", () => {
    expect(githubErrorMessage(res(429), "comparing SigmaHQ commits", NOW)).toBe(
      "GitHub is temporarily limiting requests (comparing SigmaHQ commits) — try again in a few minutes",
    );
  });

  it("falls back to 'try again later' when the reset is unknown", () => {
    expect(
      githubErrorMessage(res(403, { "x-ratelimit-remaining": "0" }), "listing rule pack releases", NOW),
    ).toBe(
      "GitHub's hourly limit for anonymous requests is used up (listing rule pack releases) — try again later",
    );
  });

  it("keeps the generic message for other failures, with or without an operation", () => {
    expect(githubErrorMessage(res(404), "listing SigmaHQ releases", NOW)).toBe(
      "GitHub returned 404 listing SigmaHQ releases",
    );
    expect(githubErrorMessage(res(403), undefined, NOW)).toBe("GitHub returned 403");
    expect(githubErrorMessage(res(429), undefined, NOW)).toBe(
      "GitHub is temporarily limiting requests — try again in a few minutes",
    );
  });
});

describe("the GitHub callers carry the rate-limit explanation", () => {
  const limited = () =>
    new Response("{}", {
      status: 403,
      headers: { "x-ratelimit-remaining": "0", "x-ratelimit-reset": "9999999999" },
    });
  const fetchLimited = (async () => limited()) as unknown as typeof fetch;
  const HOURLY = /hourly limit for anonymous requests is used up/;

  it("listing SigmaHQ releases", async () => {
    await expect(latestSigmaRelease(fetchLimited)).rejects.toThrow(HOURLY);
  });

  it("reading SigmaHQ's main branch", async () => {
    await expect(latestSigmaMainCommit(fetchLimited)).rejects.toThrow(/\(listing SigmaHQ commits\)/);
  });

  it("downloading a release asset, still releasing the response", async () => {
    let disposed = false;
    const fetchAsset = async () => ({
      response: limited(),
      url: new URL("https://github.com/SigmaHQ/sigma/releases/download/r1/sigma_all_rules.zip"),
      dispose: async () => {
        disposed = true;
      },
    });
    await expect(
      downloadSigmaRelease(
        {
          tag: "r1",
          url: "https://github.com/SigmaHQ/sigma/releases/download/r1/sigma_all_rules.zip",
          sha256: "0".repeat(64),
        },
        fetchAsset,
      ),
    ).rejects.toThrow(/\(downloading the Sigma release\)/);
    expect(disposed).toBe(true);
  });

  it("the companion update check keeps the last known version", async () => {
    let rec: { result?: UpdateResult } = {
      result: { latestVersion: "1.0.0", latestTag: "v1.0.0", htmlUrl: "https://x", checkedAt: 1 },
    };
    const store = {
      load: async () => rec,
      setResult: async (result: UpdateResult) => {
        rec = { result };
      },
    } as unknown as UpdateCheckStore;
    const r = await performUpdateCheck({ store, repo: "a/b", fetchFn: fetchLimited, now: 9 });
    expect(r.latestVersion).toBe("1.0.0");
    expect(r.error).toMatch(/^GitHub's hourly limit for anonymous requests is used up — try again/);
  });
});
