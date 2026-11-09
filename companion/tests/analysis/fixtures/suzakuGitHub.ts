// A fake GitHub for the Suzaku rule updater (#2508): the commits, tree and zipball endpoints the
// client calls, built from a list of rule files. Synthetic data only.
import { createZip } from "../../../src/analysis/zipArchive.js";
import { gitBlobSha } from "../../../src/analysis/suzakuReleaseClient.js";
import type { ReleaseAssetFetch } from "../../../src/analysis/githubReleaseDownload.js";

export const SHA_A = "a".repeat(40);
export const SHA_B = "b".repeat(40);
const T = (c: string) => c.repeat(40);

export const ruleText = (id: string, title: string, level = "high", status = "experimental") =>
  `title: ${title}\nid: ${id}\nstatus: ${status}\nauthor: Example Author\nlogsource:\n  product: aws\n  service: cloudtrail\ndetection:\n  sel:\n    eventName: ${title.replace(/\W/g, "")}\n  condition: sel\nlevel: ${level}\n`;

export interface FakeRepo {
  sha: string;
  date: string;
  files: Record<string, string>;
  /** Override what the archive holds (tampering tests). */
  archive?: Record<string, string>;
  archiveHost?: string;
  /** Extra files outside the CloudTrail folder (the SigmaHQ mirror). */
  others?: Record<string, string>;
}

export function fakeGitHub(repo: FakeRepo): {
  fetchFn: typeof fetch;
  fetchAsset: ReleaseAssetFetch;
  calls: string[];
} {
  const calls: string[] = [];
  const json = (body: unknown, status = 200) =>
    new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  const leaf = Object.entries(repo.files).map(([path, text]) => ({
    path,
    type: "blob",
    mode: "100644",
    sha: gitBlobSha(Buffer.from(text)),
  }));
  const trees: Record<string, unknown[]> = {
    [repo.sha]: [
      { path: "suzaku", type: "tree", sha: T("1") },
      { path: "README.md", type: "blob", mode: "100644", sha: T("9") },
    ],
    [T("1")]: [{ path: "aws", type: "tree", sha: T("2") }],
    [T("2")]: [{ path: "cloudtrail", type: "tree", sha: T("3") }],
    [T("3")]: leaf,
  };
  const fetchFn = (async (input: string | URL) => {
    const url = String(input);
    calls.push(url);
    if (url.includes("/commits?"))
      return json([{ sha: repo.sha, commit: { committer: { date: `${repo.date}T09:00:00Z` } } }]);
    const m = /\/git\/trees\/([0-9a-f]{40})$/.exec(url);
    if (m && trees[m[1]]) return json({ sha: m[1], tree: trees[m[1]], truncated: false });
    return json({ message: "Not Found" }, 404);
  }) as typeof fetch;
  const fetchAsset: ReleaseAssetFetch = async (url) => {
    calls.push(url);
    const wrap = `Yamato-Security-suzaku-rules-${repo.sha.slice(0, 7)}`;
    const content = repo.archive ?? repo.files;
    const entries = [
      ...Object.entries(content).map(([n, t]) => ({
        path: `${wrap}/suzaku/aws/cloudtrail/${n}`,
        data: Buffer.from(t),
      })),
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
