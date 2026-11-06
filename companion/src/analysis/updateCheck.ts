// companion/src/analysis/updateCheck.ts
// Pure logic for the opt-in "newer release available" notice (issue #127). No I/O, no network,
// no new dependency — hand-rolled semver compare, in the style of the project's other
// hand-rolled utilities. The runner (network + persistence) lives in updateCheckRun.ts.

export const DEFAULT_UPDATE_REPO = "hasamba/DFIR-Companion";
export const UPDATE_CHECK_THROTTLE_MS = 24 * 60 * 60 * 1000;

export function githubLatestUrl(repo: string): string {
  return `https://api.github.com/repos/${repo}/releases/latest`;
}

// The app notice LISTS releases instead of reading /releases/latest (#2349). The same repository
// also publishes detection-rule packs as `rules-YYYY.MM.DD` releases; if one were ever marked
// "latest", /releases/latest would hand back a rules tag, which parses as version 0 and silences
// the "new version available" notice for everyone until the next app release.
export function githubReleasesUrl(repo: string): string {
  return `https://api.github.com/repos/${repo}/releases?per_page=30`;
}

/** An app release tag: `v` followed by a digit. `rules-*` packs and anything else are not. */
export function isAppReleaseTag(tag: string): boolean {
  return /^v\d/i.test(tag.trim());
}

function parseVersion(v: string): { core: number[]; pre: string } {
  const cleaned = (v ?? "").trim().replace(/^v/i, "");
  const [main, ...preParts] = cleaned.split("-");
  const core = main.split(".").map((n) => parseInt(n, 10) || 0);
  return { core, pre: preParts.join("-") };
}

// -1 if a<b, 0 if equal, 1 if a>b. A release (no prerelease) outranks an equal-core prerelease.
export function compareVersions(a: string, b: string): -1 | 0 | 1 {
  const pa = parseVersion(a),
    pb = parseVersion(b);
  const len = Math.max(pa.core.length, pb.core.length);
  for (let i = 0; i < len; i++) {
    const x = pa.core[i] ?? 0,
      y = pb.core[i] ?? 0;
    if (x > y) return 1;
    if (x < y) return -1;
  }
  if (pa.pre === pb.pre) return 0;
  if (pa.pre === "") return 1;
  if (pb.pre === "") return -1;
  // Both prerelease: lexical compare. Acceptable because this project's GitHub releases use
  // plain SemVer tags (no numeric rc/beta suffixes), so e.g. "rc.2" vs "rc.10" ordering never arises.
  return pa.pre > pb.pre ? 1 : -1;
}

export function isNewer(latest: string, current: string): boolean {
  if (!current || current === "unknown" || !latest) return false;
  return compareVersions(latest, current) === 1;
}

export interface LatestRelease {
  tag: string;
  version: string;
  htmlUrl: string;
  publishedAt?: string;
}

// Tolerant parse of ONE GitHub release body. A tag that is not an app release (a `rules-*` pack,
// #2349) is not an answer to "is there a newer app": null.
export function parseLatestRelease(json: unknown): LatestRelease | null {
  if (!json || typeof json !== "object" || Array.isArray(json)) return null;
  const o = json as Record<string, unknown>;
  const tag = typeof o.tag_name === "string" ? o.tag_name.trim() : "";
  if (!tag || !isAppReleaseTag(tag)) return null;
  return {
    tag,
    version: tag.replace(/^v/i, ""),
    htmlUrl: typeof o.html_url === "string" && o.html_url.startsWith("https://") ? o.html_url : "",
    publishedAt: typeof o.published_at === "string" ? o.published_at : undefined,
  };
}

/**
 * The newest app release in a GitHub answer: the release list (drafts, prereleases and every
 * non-`v` tag skipped, newest by version), or a single release object (accepted when it is an app
 * release). Null when there is none.
 */
export function pickLatestAppRelease(json: unknown): LatestRelease | null {
  if (!Array.isArray(json)) return parseLatestRelease(json);
  let best: LatestRelease | null = null;
  for (const item of json) {
    if (!item || typeof item !== "object") continue;
    const o = item as Record<string, unknown>;
    if (o.draft === true || o.prerelease === true) continue;
    const parsed = parseLatestRelease(o);
    if (parsed && (!best || compareVersions(parsed.version, best.version) === 1)) best = parsed;
  }
  return best;
}

export interface UpdateMode {
  enabled: boolean;
  locked: boolean;
}

// Env DFIR_UPDATE_CHECK: 0/false/off/no → locked off; 1/true/on/yes → default on; unset/other → default off.
// The persisted Settings toggle (storedEnabled) wins unless locked.
export function resolveUpdateMode(env: string | undefined, storedEnabled: boolean | undefined): UpdateMode {
  const e = (env ?? "").trim().toLowerCase();
  if (e === "0" || e === "false" || e === "off" || e === "no") return { enabled: false, locked: true };
  if (e === "1" || e === "true" || e === "on" || e === "yes")
    return { enabled: storedEnabled ?? true, locked: false };
  return { enabled: storedEnabled ?? false, locked: false };
}

export interface UpdateResult {
  latestVersion: string;
  latestTag: string;
  htmlUrl: string;
  publishedAt?: string;
  checkedAt: number;
  error?: string;
}

export interface UpdateStatus {
  enabled: boolean;
  locked: boolean;
  current: string;
  latest: string | null;
  latestTag: string | null;
  htmlUrl: string | null;
  isNewer: boolean;
  checkedAt: number | null;
  error: string | null;
}

export function buildUpdateStatus(
  mode: UpdateMode,
  current: string,
  result: UpdateResult | undefined,
): UpdateStatus {
  const latest = result?.latestVersion || null;
  return {
    enabled: mode.enabled,
    locked: mode.locked,
    current,
    latest,
    latestTag: result?.latestTag || null,
    htmlUrl: result?.htmlUrl || null,
    isNewer: latest ? isNewer(latest, current) : false,
    checkedAt: result?.checkedAt ?? null,
    error: result?.error ?? null,
  };
}
