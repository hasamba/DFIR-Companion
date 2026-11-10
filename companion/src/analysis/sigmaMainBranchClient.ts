// SigmaHQ's main branch for the Sigma rule updater (#2518). SigmaHQ cuts a release every one to three
// months, while new rules and fixes land on `master` almost daily. This client:
//   - says how many newer main-branch changes touch the folders the Companion grades, so the check
//     never says "up to date" while months of unreleased rules exist; and
//   - downloads one pinned main-branch commit as an opt-in, analyst-reviewed install.
//
// Verification (GitHub publishes no checksum for a branch): the commit is pinned by its SHA, each rule
// folder's listing and every file's git blob SHA-1 come from GitHub's tree API at that commit, and
// every rule taken from the commit's zip archive must hash to its listed blob SHA. Only the rule
// folders are unpacked. The result is a release-shaped zip the existing preview / install / roll back
// path reads, with the commit recorded in version.txt.

import { readCappedBody, type ReleaseAssetFetch } from "./githubReleaseDownload.js";
import { SIGMA_RELEASE_MAX_ENTRIES, SIGMA_RELEASE_MAX_ZIP_BYTES } from "./sigmaReleaseArchive.js";
import { SIGMA_RULE_DIRS } from "./sigmaRuleSet.js";
import { gitBlobSha } from "./suzakuReleaseClient.js";
import { createZip, readZip } from "./zipArchive.js";
import { githubErrorMessage } from "./githubHttpError.js";

const API = "https://api.github.com/repos/SigmaHQ/sigma";
const BRANCH = "master";
const HEADERS = { Accept: "application/vnd.github+json", "User-Agent": "dfir-companion" };
const SHA = /^[0-9a-f]{40}$/;
const ARCHIVE_HOSTS = new Set(["api.github.com", "codeload.github.com"]);
const MAX_RULE_BYTES = 1024 * 1024;
const MAX_TOTAL_INFLATED = 128 * 1024 * 1024;
const ARCHIVE_TIMEOUT_MS = 120_000;

/** The SigmaHQ folders the Companion grades at import — the bundle's own folders (data/sigma). */
export const SIGMA_GRADED_PATHS = [
  "rules/cloud/aws/cloudtrail",
  "rules/cloud/azure/signin_logs",
  "rules/cloud/azure/audit_logs",
  "rules/cloud/gcp/audit",
  "rules/web/webserver_generic",
  "rules/web/proxy_generic",
] as const;

export interface SigmaMainCommit {
  sha: string;
  /** YYYY-MM-DD */
  date: string;
}

/** The main branch as the check reports it. */
export interface SigmaMainSummary {
  commit: string;
  date: string;
  /** Main-branch commits since the installed rules that touch a graded folder (up to 100 per folder). */
  gradedChanges: number;
  /** The release name an install of this commit gets. */
  label: string;
  /** The installed commit the count was made against: a different one makes the count stale. */
  installedCommit: string;
}

async function getJson(fetchFn: typeof fetch, url: string, what: string): Promise<unknown> {
  const resp = await fetchFn(url, { headers: HEADERS, signal: AbortSignal.timeout(15_000) });
  if (!resp.ok) throw new Error(githubErrorMessage(resp, what));
  return resp.json();
}

const commitOf = (raw: unknown): SigmaMainCommit | undefined => {
  const c = raw as { sha?: unknown; commit?: { committer?: { date?: unknown } } } | undefined;
  const sha = typeof c?.sha === "string" ? c.sha.toLowerCase() : "";
  const date = typeof c?.commit?.committer?.date === "string" ? c.commit.committer.date : "";
  return SHA.test(sha) && /^\d{4}-\d{2}-\d{2}/.test(date) ? { sha, date: date.slice(0, 10) } : undefined;
};

/** The newest commit on SigmaHQ's main branch. */
export async function latestSigmaMainCommit(fetchFn: typeof fetch): Promise<SigmaMainCommit> {
  const json = await getJson(fetchFn, `${API}/commits?sha=${BRANCH}&per_page=1`, "listing SigmaHQ commits");
  const c = commitOf(Array.isArray(json) ? json[0] : undefined);
  if (!c) throw new Error("could not read SigmaHQ's newest main-branch commit from GitHub");
  return c;
}

/** The release name a main-branch install gets: it says "unreleased" wherever the release is named. */
export const sigmaMainLabel = (c: SigmaMainCommit): string =>
  `main-${c.date}-${c.sha.slice(0, 7)}-unreleased`;

/**
 * The main branch against the installed rules: newest commit, and how many main-branch commits since
 * the installed commit's date touch a graded folder (a commit touching two folders counts once).
 */
export async function sigmaMainSummary(
  fetchFn: typeof fetch,
  installedCommit: string,
): Promise<SigmaMainSummary> {
  const latest = await latestSigmaMainCommit(fetchFn);
  const installed = SHA.test(installedCommit)
    ? commitOf(
        await getJson(fetchFn, `${API}/commits/${installedCommit}`, "reading the installed SigmaHQ commit"),
      )
    : undefined;
  const since = installed ? `&since=${installed.date}T00:00:00Z` : "";
  const shas = new Set<string>();
  for (const path of SIGMA_GRADED_PATHS) {
    const list = await getJson(
      fetchFn,
      `${API}/commits?sha=${BRANCH}&path=${encodeURIComponent(path)}&per_page=100${since}`,
      "listing SigmaHQ changes",
    );
    for (const raw of Array.isArray(list) ? list : []) {
      const c = commitOf(raw);
      if (c) shas.add(c.sha);
    }
  }
  if (installed) shas.delete(installed.sha);
  // A same-day commit already in the installed rules is not "newer": keep only commits the checked tip
  // has and the installed commit does not (Codex review). GitHub lists at most 250 of them; past that
  // the date filter above is the best answer available.
  const ahead = installed ? await commitsAhead(fetchFn, installed.sha, latest.sha) : undefined;
  const newer = ahead ? [...shas].filter((s) => ahead.has(s)) : [...shas];
  return {
    commit: latest.sha,
    date: latest.date,
    gradedChanges: newer.length,
    label: sigmaMainLabel(latest),
    installedCommit,
  };
}

/** Commits reachable from `head` but not from `base`, or undefined when GitHub listed only some. */
async function commitsAhead(
  fetchFn: typeof fetch,
  base: string,
  head: string,
): Promise<Set<string> | undefined> {
  if (base === head) return new Set();
  const json = (await getJson(fetchFn, `${API}/compare/${base}...${head}`, "comparing SigmaHQ commits")) as {
    total_commits?: unknown;
    commits?: unknown;
  };
  const list = Array.isArray(json.commits) ? json.commits : [];
  if (typeof json.total_commits !== "number" || json.total_commits > list.length) return undefined;
  return new Set(
    list.flatMap((c) =>
      typeof (c as { sha?: unknown }).sha === "string" ? [(c as { sha: string }).sha] : [],
    ),
  );
}

type TreeEntry = { path?: unknown; type?: unknown; sha?: unknown; mode?: unknown };

async function tree(fetchFn: typeof fetch, sha: string, recursive: boolean): Promise<TreeEntry[]> {
  const json = (await getJson(
    fetchFn,
    `${API}/git/trees/${sha}${recursive ? "?recursive=1" : ""}`,
    "listing SigmaHQ rule folders",
  )) as { tree?: unknown; truncated?: unknown };
  if (json.truncated === true || !Array.isArray(json.tree))
    throw new Error("GitHub returned an incomplete listing of the SigmaHQ rule folders");
  return json.tree as TreeEntry[];
}

/** Every rule file under the rule folders at `sha`: repo path → git blob SHA. */
export async function listSigmaMainRules(fetchFn: typeof fetch, sha: string): Promise<Map<string, string>> {
  const root = await tree(fetchFn, sha, false);
  const out = new Map<string, string>();
  for (const dir of SIGMA_RULE_DIRS) {
    const folder = root.find((e) => e.path === dir && e.type === "tree");
    if (typeof folder?.sha !== "string" || !SHA.test(folder.sha)) continue;
    for (const e of await tree(fetchFn, folder.sha, true)) {
      if (e.type !== "blob" || typeof e.path !== "string" || !/\.ya?ml$/i.test(e.path)) continue;
      if (e.mode !== "100644" || typeof e.sha !== "string" || !SHA.test(e.sha)) continue;
      if (e.path.split("/").some((part) => part === ".." || part === "")) continue;
      out.set(`${dir}/${e.path}`, e.sha);
    }
  }
  if (![...out.keys()].some((p) => p.startsWith("rules/")))
    throw new Error("the SigmaHQ commit has no rules folder");
  if (out.size > SIGMA_RELEASE_MAX_ENTRIES)
    throw new Error(`the SigmaHQ commit holds more than ${SIGMA_RELEASE_MAX_ENTRIES} rules`);
  return out;
}

const allowedArchiveUrl = (raw: string): boolean => {
  try {
    const u = new URL(raw);
    return u.protocol === "https:" && !u.port && !u.username && !u.password && ARCHIVE_HOSTS.has(u.hostname);
  } catch {
    return false;
  }
};

async function fetchArchive(sha: string, fetchAsset: ReleaseAssetFetch): Promise<Buffer> {
  const fetched = await fetchAsset(`${API}/zipball/${sha}`, ARCHIVE_TIMEOUT_MS);
  try {
    if (!allowedArchiveUrl(fetched.url.href)) {
      await fetched.response.body?.cancel().catch(() => {});
      throw new Error("the SigmaHQ archive came from a host other than GitHub; nothing was installed");
    }
    if (!fetched.response.ok || !fetched.response.body)
      throw new Error(githubErrorMessage(fetched.response, "downloading SigmaHQ's main branch"));
    return await readCappedBody(
      fetched.response.body,
      SIGMA_RELEASE_MAX_ZIP_BYTES,
      "SigmaHQ main-branch archive",
    );
  } finally {
    await fetched.dispose();
  }
}

/**
 * Download `commit`, verify every rule against GitHub's listing, and return a release-shaped zip
 * (rule folders + version.txt naming the commit) for the store's preview. Throws a plain sentence.
 */
export async function downloadSigmaMain(
  commit: SigmaMainCommit,
  fetchFn: typeof fetch,
  fetchAsset: ReleaseAssetFetch,
): Promise<Buffer> {
  if (!SHA.test(commit.sha)) throw new Error("not a SigmaHQ commit");
  const listed = await listSigmaMainRules(fetchFn, commit.sha);
  const archive = await fetchArchive(commit.sha, fetchAsset);
  // GitHub wraps the archive in one owner-repo-shortsha folder; only rule-folder entries are unpacked.
  const ruleEntry = (path: string): boolean => {
    const rest = path.slice(path.indexOf("/") + 1);
    return SIGMA_RULE_DIRS.some((d) => rest.startsWith(`${d}/`)) && /\.ya?ml$/i.test(rest);
  };
  const entries = readZip(archive, {
    include: ruleEntry,
    maxEntryBytes: MAX_RULE_BYTES,
    maxTotalBytes: MAX_TOTAL_INFLATED,
  });
  if (new Set(entries.map((e) => e.path.split("/")[0])).size > 1)
    throw new Error("the SigmaHQ archive does not have the layout GitHub produces");
  const found = new Map<string, Buffer>();
  for (const e of entries) {
    const path = e.path.slice(e.path.indexOf("/") + 1);
    const want = listed.get(path);
    if (!want) continue;
    if (found.has(path)) throw new Error(`the SigmaHQ archive holds ${path} twice; nothing was installed`);
    if (gitBlobSha(e.data) !== want)
      throw new Error(`the SigmaHQ rule ${path} does not match GitHub's listing; nothing was installed`);
    found.set(path, e.data);
  }
  const missing = [...listed.keys()].filter((p) => !found.has(p));
  if (missing.length)
    throw new Error(
      `the SigmaHQ archive is missing ${missing.length} listed rule(s), e.g. ${missing[0]}; nothing was installed`,
    );
  const version = `Label: ${sigmaMainLabel(commit)}\nCommit-Hash: ${commit.sha}\nRelease Date: ${commit.date}\n`;
  return createZip([
    ...[...found].map(([path, data]) => ({ path, data })),
    { path: "version.txt", data: Buffer.from(version) },
  ]);
}
