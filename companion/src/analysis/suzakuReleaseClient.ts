// The Suzaku rule updater's GitHub client (#2508). Suzaku publishes no releases, so the unit is a
// commit of Yamato-Security/suzaku-rules: the head of its main branch, taken as ONE snapshot of the
// watched rule folders (#2500 — CloudTrail, Microsoft 365, Azure Activity). The folders' git tree
// SHAs at that commit are its identity, so a change confined to any one folder is seen, and the
// repo's daily SigmaHQ mirror commits (outside every watched folder) are not an update.
//
// Verification (GitHub publishes no checksum for a folder): the commit is pinned by its SHA, the
// folder's file list and each file's git blob SHA-1 come from GitHub's tree API at that commit, and
// every file taken from the commit's zip archive must hash to its listed blob SHA. A missing or
// mismatched file fails the whole download — nothing is half-installed.
//
// The network calls are injected (the route passes fetch for the API and the SSRF-guarded
// fetchOutbound for the archive), so this file never decides how a connection is made. Only the
// watched folders are taken; the repo's daily SigmaHQ mirror (sigma/) is never read.

import { createHash } from "node:crypto";
import { readCappedBody, type ReleaseAssetFetch } from "./githubReleaseDownload.js";
import { readZip } from "./zipArchive.js";
import { githubErrorMessage } from "./githubHttpError.js";

export const SUZAKU_REPO = "Yamato-Security/suzaku-rules";
/** The rule folders taken from the repo, each read one level deep (its sub-folders are not rules). */
export const SUZAKU_WATCH_PATHS = [
  "suzaku/aws/cloudtrail",
  "suzaku/m365",
  "suzaku/azure/activity_logs",
] as const;
const BRANCH = "main";
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
  /** Watched folder → its git tree SHA at this commit: the snapshot's identity. */
  folders?: Record<string, string>;
}

export interface SuzakuDownload {
  commit: SuzakuCommit;
  /** Path under suzaku/ (aws/cloudtrail/x.yml) → text, every one verified against its git blob SHA. */
  files: { path: string; text: string }[];
}

/** True when two snapshots hold the same watched folders; unknown (missing) never counts as equal. */
export function sameSuzakuFolders(a?: Record<string, string>, b?: Record<string, string>): boolean {
  if (!a || !b) return false;
  return SUZAKU_WATCH_PATHS.every((p) => !!a[p] && a[p] === b[p]);
}

async function getJson(
  fetchFn: typeof fetch,
  url: string,
  what: string,
  timeoutMs = 15_000,
): Promise<unknown> {
  const resp = await fetchFn(url, { headers: HEADERS, signal: AbortSignal.timeout(timeoutMs) });
  if (!resp.ok) throw new Error(githubErrorMessage(resp, what));
  return resp.json();
}

/** The head of the main branch, with the watched folders' tree SHAs at it (two API calls). */
export async function latestSuzakuCommit(fetchFn: typeof fetch): Promise<SuzakuCommit> {
  const url = `${API}/commits?sha=${BRANCH}&per_page=1`;
  const json = await getJson(fetchFn, url, "listing Suzaku rule commits");
  const first = Array.isArray(json) ? (json[0] as Record<string, unknown> | undefined) : undefined;
  const sha = typeof first?.sha === "string" ? first.sha.toLowerCase() : "";
  const commit = first?.commit as { committer?: { date?: unknown } } | undefined;
  const rawDate = typeof commit?.committer?.date === "string" ? commit.committer.date : "";
  if (!SHA.test(sha) || !/^\d{4}-\d{2}-\d{2}/.test(rawDate))
    throw new Error("could not read the newest Suzaku rule commit from GitHub");
  const snap = await snapshotSuzaku(fetchFn, sha);
  return { sha, date: rawDate.slice(0, 10), folders: snap.folders };
}

type TreeEntry = { path?: unknown; type?: unknown; sha?: unknown; mode?: unknown };

async function tree(
  fetchFn: typeof fetch,
  sha: string,
  recursive = false,
): Promise<{ entries: TreeEntry[]; truncated: boolean }> {
  const url = `${API}/git/trees/${sha}${recursive ? "?recursive=1" : ""}`;
  const json = (await getJson(fetchFn, url, "listing the Suzaku rule folders")) as {
    tree?: unknown;
    truncated?: unknown;
  };
  if (!Array.isArray(json.tree))
    throw new Error("GitHub returned an unreadable listing of the Suzaku rule folders");
  return { entries: json.tree as TreeEntry[], truncated: json.truncated === true };
}

interface SuzakuSnapshot {
  folders: Record<string, string>;
  /** Path under suzaku/ → git blob SHA. */
  files: Map<string, string>;
}

/** One rule file of `folder` (a direct child), checked: a plain file with a real blob SHA. */
function addRule(out: Map<string, string>, folder: string, e: TreeEntry, name: string): void {
  if (e.type !== "blob" || !RULE_NAME.test(name)) return;
  if (e.mode !== "100644" || typeof e.sha !== "string" || !SHA.test(e.sha))
    throw new Error(`the Suzaku rule ${folder}/${name} is not a plain file`);
  out.set(`${folder.slice(SUZAKU_PREFIX.length)}/${name}`, e.sha);
}

const SUZAKU_PREFIX = "suzaku/";

/** Every watched folder's tree SHA and rule files at `sha`. One recursive listing; when GitHub
 * truncates it, each folder is walked one level at a time instead. */
async function snapshotSuzaku(fetchFn: typeof fetch, sha: string): Promise<SuzakuSnapshot> {
  const folders: Record<string, string> = {};
  const files = new Map<string, string>();
  const whole = await tree(fetchFn, sha, true);
  if (!whole.truncated) {
    const watched = new Set<string>(SUZAKU_WATCH_PATHS);
    for (const e of whole.entries) {
      if (typeof e.path !== "string") continue;
      if (e.type === "tree" && watched.has(e.path) && typeof e.sha === "string" && SHA.test(e.sha))
        folders[e.path] = e.sha;
      const cut = e.path.lastIndexOf("/");
      if (cut > 0 && watched.has(e.path.slice(0, cut)))
        addRule(files, e.path.slice(0, cut), e, e.path.slice(cut + 1));
    }
  } else {
    for (const folder of SUZAKU_WATCH_PATHS) {
      let at = sha;
      for (const part of folder.split("/")) {
        const next = (await tree(fetchFn, at)).entries.find((e) => e.path === part && e.type === "tree");
        if (typeof next?.sha !== "string" || !SHA.test(next.sha))
          throw new Error(`the Suzaku commit has no ${folder} folder`);
        at = next.sha;
      }
      folders[folder] = at;
      for (const e of (await tree(fetchFn, at)).entries)
        if (typeof e.path === "string") addRule(files, folder, e, e.path);
    }
  }
  const missing = SUZAKU_WATCH_PATHS.find((f) => !folders[f]);
  if (missing) throw new Error(`the Suzaku commit has no ${missing} folder`);
  if (files.size === 0) throw new Error("the Suzaku rule folders hold no rules at that commit");
  if (files.size > SUZAKU_MAX_RULE_FILES)
    throw new Error(`the Suzaku rule folders hold more than ${SUZAKU_MAX_RULE_FILES} rules`);
  return { folders, files };
}

/** The watched folders' rules at `sha`: path under suzaku/ → git blob SHA. */
export async function listSuzakuRules(fetchFn: typeof fetch, sha: string): Promise<Map<string, string>> {
  return (await snapshotSuzaku(fetchFn, sha)).files;
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
      throw new Error(githubErrorMessage(fetched.response, "downloading the Suzaku rules"));
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

/** Download and verify the watched folders' rules at `commit`. Throws a plain sentence on any failure. */
export async function downloadSuzakuRules(
  commit: SuzakuCommit,
  fetchFn: typeof fetch,
  fetchAsset: ReleaseAssetFetch,
): Promise<SuzakuDownload> {
  if (!SHA.test(commit.sha)) throw new Error("not a Suzaku commit");
  const snap = await snapshotSuzaku(fetchFn, commit.sha);
  const listed = snap.files;
  const entries = readZip(await fetchArchive(commit.sha, fetchAsset), {
    maxEntryBytes: MAX_ENTRY_INFLATED,
    maxTotalBytes: MAX_TOTAL_INFLATED,
  });
  const prefix = `${wrapperOf(entries.map((e) => e.path))}/${SUZAKU_PREFIX}`;
  const found = new Map<string, Buffer>();
  for (const e of entries) {
    if (!e.path.startsWith(prefix)) continue;
    const path = e.path.slice(prefix.length);
    if (!listed.has(path)) continue; // other folders, sub-folders, non-rule files: not listed
    if (found.has(path)) throw new Error(`the Suzaku archive holds ${path} twice; nothing was installed`);
    if (gitBlobSha(e.data) !== listed.get(path))
      throw new Error(`the Suzaku rule ${path} does not match GitHub's listing; nothing was installed`);
    if (e.data.length > SUZAKU_MAX_RULE_BYTES)
      throw new Error(`the Suzaku rule ${path} is larger than 128 KB; nothing was installed`);
    found.set(path, e.data);
  }
  const missing = [...listed.keys()].filter((n) => !found.has(n));
  if (missing.length)
    throw new Error(
      `the Suzaku archive is missing ${missing.length} listed rule(s), e.g. ${missing[0]}; nothing was installed`,
    );
  return {
    commit: { ...commit, folders: snap.folders },
    files: [...found]
      .sort(([a], [b]) => (a < b ? -1 : 1))
      .map(([path, data]) => ({ path, text: data.toString("utf8") })),
  };
}
