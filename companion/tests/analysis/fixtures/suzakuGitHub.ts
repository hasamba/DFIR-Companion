// A fake GitHub for the Suzaku rule updater (#2508): the commits, tree and zipball endpoints the
// client calls, built from a list of rule files. Synthetic data only.
import { createHash } from "node:crypto";
import { createZip } from "../../../src/analysis/zipArchive.js";
import { gitBlobSha, SUZAKU_WATCH_PATHS } from "../../../src/analysis/suzakuReleaseClient.js";
import type { ReleaseAssetFetch } from "../../../src/analysis/githubReleaseDownload.js";

export const SHA_A = "a".repeat(40);
export const SHA_B = "b".repeat(40);
const T = (c: string) => c.repeat(40);

export const ruleText = (id: string, title: string, level = "high", status = "experimental") =>
  `title: ${title}\nid: ${id}\nstatus: ${status}\nauthor: Example Author\nlogsource:\n  product: aws\n  service: cloudtrail\ndetection:\n  sel:\n    eventName: ${title.replace(/\W/g, "")}\n  condition: sel\nlevel: ${level}\n`;

export interface FakeRepo {
  sha: string;
  date: string;
  /** Rule files: a bare name sits in suzaku/aws/cloudtrail; a path (m365/x.yml) is under suzaku/. */
  files: Record<string, string>;
  /** Override what the archive holds (tampering tests), keyed the same way. */
  archive?: Record<string, string>;
  archiveHost?: string;
  /** Extra files outside the watched folders (the SigmaHQ mirror). */
  others?: Record<string, string>;
  /** Make the recursive listing truncated, so the client walks the folders instead. */
  truncated?: boolean;
}

export const WATCHED: readonly string[] = SUZAKU_WATCH_PATHS;

/** A file key as its full repo path. */
const repoPath = (key: string): string =>
  key.includes("/") ? `suzaku/${key}` : `suzaku/aws/cloudtrail/${key}`;

/** A stable fake tree SHA for a folder, changing whenever its files change. */
const folderSha = (folder: string, files: Record<string, string>): string =>
  createHash("sha1")
    .update(folder)
    .update(
      Object.entries(files)
        .filter(([k]) => repoPath(k).startsWith(`${folder}/`))
        .map(([k, t]) => `${k}\0${t}`)
        .sort()
        .join("\n"),
    )
    .digest("hex");

/** The folder identities a FakeRepo answers with (what a check would report). */
export const fakeFolders = (files: Record<string, string>): Record<string, string> =>
  Object.fromEntries(WATCHED.map((f) => [f, folderSha(f, files)]));

export function fakeGitHub(repo: FakeRepo): {
  fetchFn: typeof fetch;
  fetchAsset: ReleaseAssetFetch;
  calls: string[];
} {
  const calls: string[] = [];
  const json = (body: unknown, status = 200) =>
    new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  const blob = (path: string, text: string) => ({
    path,
    type: "blob",
    mode: "100644",
    sha: gitBlobSha(Buffer.from(text)),
  });
  const folders = fakeFolders(repo.files);
  const inFolder = (folder: string) =>
    Object.entries(repo.files)
      .filter(([k]) => repoPath(k).startsWith(`${folder}/`))
      .map(([k, t]) => blob(repoPath(k).slice(folder.length + 1), t));
  // Per-level trees for the walk: root → suzaku → aws/m365/azure/gws → cloudtrail/activity_logs/<app>.
  const trees: Record<string, unknown[]> = {
    [repo.sha]: [
      { path: "suzaku", type: "tree", sha: T("1") },
      { path: "README.md", type: "blob", mode: "100644", sha: T("9") },
    ],
    [T("1")]: [
      { path: "aws", type: "tree", sha: T("2") },
      { path: "m365", type: "tree", sha: folders["suzaku/m365"] },
      { path: "azure", type: "tree", sha: T("4") },
      { path: "gws", type: "tree", sha: T("5") },
    ],
    [T("2")]: [{ path: "cloudtrail", type: "tree", sha: folders["suzaku/aws/cloudtrail"] }],
    [T("4")]: [{ path: "activity_logs", type: "tree", sha: folders["suzaku/azure/activity_logs"] }],
    [T("5")]: ["admin", "calendar", "drive", "login"].map((app) => ({
      path: app,
      type: "tree",
      sha: folders[`suzaku/gws/${app}`],
    })),
    ...Object.fromEntries(WATCHED.map((f) => [folders[f], inFolder(f)])),
  };
  const recursive = [
    { path: "suzaku", type: "tree", sha: T("1") },
    ...WATCHED.map((f) => ({ path: f, type: "tree", sha: folders[f] })),
    ...Object.entries(repo.files).map(([k, t]) => blob(repoPath(k), t)),
    ...Object.entries(repo.others ?? {}).map(([p, t]) => blob(p, t)),
  ];
  const fetchFn = (async (input: string | URL) => {
    const url = String(input);
    calls.push(url);
    if (url.includes("/commits?"))
      return json([{ sha: repo.sha, commit: { committer: { date: `${repo.date}T09:00:00Z` } } }]);
    const r = /\/git\/trees\/([0-9a-f]{40})\?recursive=1$/.exec(url);
    if (r && r[1] === repo.sha) return json({ sha: r[1], tree: recursive, truncated: !!repo.truncated });
    const m = /\/git\/trees\/([0-9a-f]{40})$/.exec(url);
    if (m && trees[m[1]]) return json({ sha: m[1], tree: trees[m[1]], truncated: false });
    return json({ message: "Not Found" }, 404);
  }) as typeof fetch;
  const fetchAsset: ReleaseAssetFetch = async (url) => {
    calls.push(url);
    const wrap = `Yamato-Security-suzaku-rules-${repo.sha.slice(0, 7)}`;
    const content = repo.archive ?? repo.files;
    const entries = [
      ...Object.entries(content).map(([k, t]) => ({ path: `${wrap}/${repoPath(k)}`, data: Buffer.from(t) })),
      ...Object.entries(repo.others ?? {}).map(([p, t]) => ({ path: `${wrap}/${p}`, data: Buffer.from(t) })),
    ];
    return {
      response: new Response(new Uint8Array(createZip(entries))),
      url: new URL(`https://${repo.archiveHost ?? "codeload.github.com"}/x/zip/${repo.sha}`),
      dispose: async () => {},
    };
  };
  return { fetchFn, fetchAsset, calls };
}
