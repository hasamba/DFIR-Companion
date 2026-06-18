// companion/src/analysis/updateCheckRun.ts
import type { UpdateCheckStore } from "./updateCheckStore.js";
import { githubLatestUrl, parseLatestRelease, type UpdateResult } from "./updateCheck.js";

export type FetchLike = typeof fetch;

// Fetch the latest release from GitHub and cache it. Best-effort: on any failure we still write
// a result (stamped with the error) that PRESERVES the last known-good latestVersion, so a
// transient offline blip doesn't erase a "newer version available" banner. Never throws.
export async function performUpdateCheck(opts: {
  store: UpdateCheckStore;
  repo: string;
  fetchFn: FetchLike;
  now: number;
  timeoutMs?: number;
}): Promise<UpdateResult> {
  const { store, repo, fetchFn, now, timeoutMs = 5000 } = opts;
  const prev = (await store.load()).result;
  try {
    const resp = await fetchFn(githubLatestUrl(repo), {
      headers: { Accept: "application/vnd.github+json", "User-Agent": "dfir-companion" },
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!resp.ok) throw new Error(`GitHub returned ${resp.status}`);
    const parsed = parseLatestRelease(await resp.json());
    if (!parsed) throw new Error("could not parse the latest release");
    const result: UpdateResult = {
      latestVersion: parsed.version,
      latestTag: parsed.tag,
      htmlUrl: parsed.htmlUrl || `https://github.com/${repo}/releases`,
      publishedAt: parsed.publishedAt,
      checkedAt: now,
    };
    try { await store.setResult(result); } catch { /* best-effort: persistence failure must not break the caller */ }
    return result;
  } catch (err) {
    const result: UpdateResult = {
      latestVersion: prev?.latestVersion ?? "",
      latestTag: prev?.latestTag ?? "",
      htmlUrl: prev?.htmlUrl ?? `https://github.com/${repo}/releases`,
      publishedAt: prev?.publishedAt,
      checkedAt: now,
      error: err instanceof Error ? err.message : String(err),
    };
    try { await store.setResult(result); } catch { /* best-effort */ }
    return result;
  }
}
