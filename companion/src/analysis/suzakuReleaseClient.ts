// The Suzaku rule updater's GitHub client (#2508). Suzaku publishes no releases, so the unit is the
// newest commit touching suzaku/aws/cloudtrail in Yamato-Security/suzaku-rules.
//
// Verification (GitHub publishes no checksum for a folder): the commit is pinned by its SHA, the
// folder's file list and each file's git blob SHA-1 come from GitHub's tree API at that commit, and
// every file taken from the commit's zip archive must hash to its listed blob SHA. A missing or
// mismatched file fails the whole download — nothing is half-installed.
//
// The network calls are injected (the route passes fetch for the API and the SSRF-guarded
// fetchOutbound for the archive), so this file never decides how a connection is made. Only the
// Suzaku CloudTrail folder is taken; the repo's daily SigmaHQ mirror (sigma/) is never read.

import { createHash } from "node:crypto";
import { readCappedBody, type ReleaseAssetFetch } from "./githubReleaseDownload.js";
import { readZip } from "./zipArchive.js";

export const SUZAKU_REPO = "Yamato-Security/suzaku-rules";
export const SUZAKU_WATCH_PATH = "suzaku/aws/cloudtrail";
const API = `https://api.github.com/repos/${SUZAKU_REPO}`;
const HEADERS = { Accept: "application/vnd.github+json", "User-Agent": "dfir-companion" };
/** Compressed archive cap: the zip is the whole repo, SigmaHQ mirror included. */
export const SUZAKU_MAX_ZIP_BYTES = 32 * 1024 * 1024;
const MAX_ENTRY_INFLATED = 8 * 1024 * 1024;
const MAX_TOTAL_INFLATED = 128 * 1024 * 1024;
/** The loader's own per-file cap (sigmaSuzakuRules.ts): a bigger file would load as empty text. */
export const SUZAKU_MAX_RULE_BYTES = 128 * 1024;
export const SUZAKU_MAX_RULE_FILES = 5_000;
const ARCHIVE_TIMEOUT_MS = 120_000;
const RULE_NAME = /^[A-Za-z0-9._-]+\.ya?ml$/;
const SHA = /^[0-9a-f]{40}$/;
const ARCHIVE_HOSTS = new Set(["api.github.com", "codeload.github.com"]);

export interface SuzakuCommit {
  sha: string;
  /** YYYY-MM-DD of the commit. */
  date: string;
}

export interface SuzakuDownload {
  commit: SuzakuCommit;
  /** File name (no folder) → text, every one verified against its git blob SHA. */
  files: { name: string; text: string }[];
}

async function getJson(
  fetchFn: typeof fetch,
  url: string,
  what: string,
  timeoutMs = 15_000,
): Promise<unknown> {
  const resp = await fetchFn(url, { headers: HEADERS, signal: AbortSignal.timeout(timeoutMs) });
  if (!resp.ok) throw new Error(`GitHub returned ${resp.status} ${what}`);
  return resp.json();
}

/** The newest commit touching the Suzaku CloudTrail folder. */
export async function latestSuzakuCommit(fetchFn: typeof fetch): Promise<SuzakuCommit> {
  const url = `${API}/commits?path=${encodeURIComponent(SUZAKU_WATCH_PATH)}&per_page=1`;
  const json = await getJson(fetchFn, url, "listing Suzaku rule commits");
  const first = Array.isArray(json) ? (json[0] as Record<string, unknown> | undefined) : undefined;
  const sha = typeof first?.sha === "string" ? first.sha.toLowerCase() : "";
  const commit = first?.commit as { committer?: { date?: unknown } } | undefined;
  const rawDate = typeof commit?.committer?.date === "string" ? commit.committer.date : "";
  if (!SHA.test(sha) || !/^\d{4}-\d{2}-\d{2}/.test(rawDate))
    throw new Error("could not read the newest Suzaku rule commit from GitHub");
  return { sha, date: rawDate.slice(0, 10) };
}

type TreeEntry = { path?: unknown; type?: unknown; sha?: unknown; mode?: unknown };

async function tree(fetchFn: typeof fetch, sha: string): Promise<TreeEntry[]> {
  const json = (await getJson(fetchFn, `${API}/git/trees/${sha}`, "listing the Suzaku rule folder")) as {
    tree?: unknown;
    truncated?: unknown;
  };
  if (json.truncated === true || !Array.isArray(json.tree))
    throw new Error("GitHub returned an incomplete listing of the Suzaku rule folder");
  return json.tree as TreeEntry[];
}

/** The CloudTrail folder at `sha`: file name → git blob SHA. Walked one level at a time. */
export async function listSuzakuRules(fetchFn: typeof fetch, sha: string): Promise<Map<string, string>> {
  let at = sha;
  for (const part of SUZAKU_WATCH_PATH.split("/")) {
    const next = (await tree(fetchFn, at)).find((e) => e.path === part && e.type === "tree");
    if (typeof next?.sha !== "string" || !SHA.test(next.sha))
      throw new Error(`the Suzaku commit has no ${SUZAKU_WATCH_PATH} folder`);
    at = next.sha;
  }
  const out = new Map<string, string>();
  for (const e of await tree(fetchFn, at)) {
    if (e.type !== "blob" || typeof e.path !== "string" || !RULE_NAME.test(e.path)) continue;
    if (e.mode !== "100644" || typeof e.sha !== "string" || !SHA.test(e.sha))
      throw new Error(`the Suzaku rule ${e.path} is not a plain file`);
    out.set(e.path, e.sha);
  }
  if (out.size === 0) throw new Error("the Suzaku rule folder holds no rules at that commit");
  if (out.size > SUZAKU_MAX_RULE_FILES)
    throw new Error(`the Suzaku rule folder holds more than ${SUZAKU_MAX_RULE_FILES} rules`);
  return out;
}

/** git's blob SHA-1: sha1("blob <length>\0" + bytes). */
export const gitBlobSha = (bytes: Buffer): string =>
  createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex");

const allowedArchiveUrl = (raw: string): boolean => {
  try {
    const u = new URL(raw);
    return u.protocol === "https:" && !u.port && !u.username && !u.password && ARCHIVE_HOSTS.has(u.hostname);
  } catch {
    return false;
  }
};

async function fetchArchive(sha: string, fetchAsset: ReleaseAssetFetch): Promise<Buffer> {
  const url = `${API}/zipball/${sha}`;
  const fetched = await fetchAsset(url, ARCHIVE_TIMEOUT_MS);
  try {
    if (!allowedArchiveUrl(fetched.url.href)) {
      await fetched.response.body?.cancel().catch(() => {});
      throw new Error("the Suzaku archive came from a host other than GitHub; nothing was installed");
    }
    if (!fetched.response.ok || !fetched.response.body)
      throw new Error(`GitHub returned ${fetched.response.status} downloading the Suzaku rules`);
    return await readCappedBody(fetched.response.body, SUZAKU_MAX_ZIP_BYTES, "Suzaku rules archive");
  } finally {
    await fetched.dispose();
  }
}

/** The one top-level folder GitHub wraps a commit archive in (owner-repo-shortsha). */
function wrapperOf(paths: readonly string[]): string {
  const tops = new Set(paths.map((p) => p.split("/")[0]));
  if (tops.size !== 1) throw new Error("the Suzaku archive does not have the layout GitHub produces");
  return [...tops][0];
}

/** Download and verify the CloudTrail rules at `commit`. Throws a plain sentence on any failure. */
export async function downloadSuzakuRules(
  commit: SuzakuCommit,
  fetchFn: typeof fetch,
  fetchAsset: ReleaseAssetFetch,
): Promise<SuzakuDownload> {
  if (!SHA.test(commit.sha)) throw new Error("not a Suzaku commit");
  const listed = await listSuzakuRules(fetchFn, commit.sha);
  const entries = readZip(await fetchArchive(commit.sha, fetchAsset), {
    maxEntryBytes: MAX_ENTRY_INFLATED,
    maxTotalBytes: MAX_TOTAL_INFLATED,
  });
  const prefix = `${wrapperOf(entries.map((e) => e.path))}/${SUZAKU_WATCH_PATH}/`;
  const found = new Map<string, Buffer>();
  for (const e of entries) {
    if (!e.path.startsWith(prefix)) continue;
    const name = e.path.slice(prefix.length);
    if (!listed.has(name)) continue; // sub-folders, non-rule files: not part of the listing
    if (found.has(name)) throw new Error(`the Suzaku archive holds ${name} twice; nothing was installed`);
    if (gitBlobSha(e.data) !== listed.get(name))
      throw new Error(`the Suzaku rule ${name} does not match GitHub's listing; nothing was installed`);
    if (e.data.length > SUZAKU_MAX_RULE_BYTES)
      throw new Error(`the Suzaku rule ${name} is larger than 128 KB; nothing was installed`);
    found.set(name, e.data);
  }
  const missing = [...listed.keys()].filter((n) => !found.has(n));
  if (missing.length)
    throw new Error(
      `the Suzaku archive is missing ${missing.length} listed rule(s), e.g. ${missing[0]}; nothing was installed`,
    );
  return {
    commit,
    files: [...found]
      .sort(([a], [b]) => (a < b ? -1 : 1))
      .map(([name, data]) => ({ name, text: data.toString("utf8") })),
  };
}
