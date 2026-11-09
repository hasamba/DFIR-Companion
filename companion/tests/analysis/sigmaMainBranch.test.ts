import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { bundledSigmaDir } from "../../src/analysis/sigmaBundledRules.js";
import {
  downloadSigmaMain,
  sigmaMainLabel,
  sigmaMainSummary,
} from "../../src/analysis/sigmaMainBranchClient.js";
import { readSigmaReleaseZip } from "../../src/analysis/sigmaReleaseArchive.js";
import { SigmaRuleStore } from "../../src/analysis/sigmaRuleStore.js";
import { releaseIsUpdate, sigmaCheckAsOfNow } from "../../src/analysis/sigmaUpdateCheck.js";
import { gitBlobSha } from "../../src/analysis/suzakuReleaseClient.js";
import { createZip, readZip } from "../../src/analysis/zipArchive.js";
import type { ReleaseAssetFetch } from "../../src/analysis/githubReleaseDownload.js";

// #2518: SigmaHQ's main branch — the honest "unreleased changes" count and the opt-in, verified
// main-branch install. GitHub is faked; rules are synthetic.

const MAIN = "c".repeat(40);
const INSTALLED = "552f3fee420ef232a8e5790c4fae591847e32347";
const T = (ch: string) => ch.repeat(40);
const RULE = `title: Main Only Rule\nid: 00000000-0000-0000-0000-00000000c001\nstatus: test\nlogsource:\n  product: aws\n  service: cloudtrail\ndetection:\n  sel:\n    eventName: MainOnlyCall\n  condition: sel\nlevel: high\n`;
const FILES: Record<string, string> = {
  "rules/cloud/aws/cloudtrail/main_only.yml": RULE,
  "rules-emerging-threats/2026/x.yml": RULE.replace("c001", "c002").replace("Main Only Rule", "ET Rule"),
};

function fakeSigmaHQ(
  opts: { archive?: Record<string, string>; others?: Record<string, string>; ahead?: string[] } = {},
) {
  const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status });
  const commit = (sha: string, date: string) => ({
    sha,
    commit: { committer: { date: `${date}T10:00:00Z` } },
  });
  const sub = (dir: string) =>
    Object.entries(FILES)
      .filter(([p]) => p.startsWith(`${dir}/`))
      .map(([p, t]) => ({
        path: p.slice(dir.length + 1),
        type: "blob",
        mode: "100644",
        sha: gitBlobSha(Buffer.from(t)),
      }));
  const fetchFn = (async (input: string | URL) => {
    const url = String(input);
    if (url.includes(`/commits/${INSTALLED}`)) return json(commit(INSTALLED, "2026-07-01"));
    if (url.includes(`/compare/${INSTALLED}...${MAIN}`)) {
      const ahead = opts.ahead ?? [MAIN, T("d"), T("e")];
      return json({ total_commits: ahead.length, commits: ahead.map((sha) => ({ sha })) });
    }
    if (url.includes("/commits?sha=master&per_page=1")) return json([commit(MAIN, "2026-11-07")]);
    if (url.includes("path=rules%2Fcloud%2Faws"))
      return json([commit(MAIN, "2026-11-07"), commit(T("d"), "2026-10-21")]);
    if (url.includes("path=rules%2Fcloud%2Fazure%2Fsignin"))
      return json([commit(T("d"), "2026-10-21"), commit(T("e"), "2026-09-03")]);
    if (url.includes("/commits?sha=master&path=")) return json([]);
    if (url.endsWith(`/git/trees/${MAIN}`))
      return json({
        tree: [
          { path: "rules", type: "tree", sha: T("1") },
          { path: "rules-emerging-threats", type: "tree", sha: T("2") },
          { path: "tests", type: "tree", sha: T("3") },
        ],
        truncated: false,
      });
    if (url.endsWith(`/git/trees/${T("1")}?recursive=1`))
      return json({ tree: sub("rules"), truncated: false });
    if (url.endsWith(`/git/trees/${T("2")}?recursive=1`))
      return json({ tree: sub("rules-emerging-threats"), truncated: false });
    return json({ message: "Not Found" }, 404);
  }) as typeof fetch;
  const fetchAsset: ReleaseAssetFetch = async () => {
    const wrap = "SigmaHQ-sigma-ccccccc";
    const content = { ...(opts.archive ?? FILES), ...(opts.others ?? {}) };
    const zip = createZip(
      Object.entries(content).map(([p, t]) => ({ path: `${wrap}/${p}`, data: Buffer.from(t) })),
    );
    return {
      response: new Response(new Uint8Array(zip)),
      url: new URL(`https://codeload.github.com/x/${MAIN}`),
      dispose: async () => {},
    };
  };
  return { fetchFn, fetchAsset };
}

describe("the main-branch summary", () => {
  it("counts each newer commit that touches a graded folder once", async () => {
    const { fetchFn } = fakeSigmaHQ();
    expect(await sigmaMainSummary(fetchFn, INSTALLED)).toEqual({
      commit: MAIN,
      date: "2026-11-07",
      gradedChanges: 3,
      label: `main-2026-11-07-ccccccc-unreleased`,
      installedCommit: INSTALLED,
    });
  });

  it("does not count a same-day commit the installed rules already contain", async () => {
    // T("e") is listed by the date query but is an ancestor of the installed commit.
    const { fetchFn } = fakeSigmaHQ({ ahead: [MAIN, T("d")] });
    expect((await sigmaMainSummary(fetchFn, INSTALLED)).gradedChanges).toBe(2);
  });

  it("marks the count stale once other rules are installed or rolled back to", () => {
    const check = {
      checkedAt: "x",
      latest: "r2026-07-01",
      publishedAt: "2026-07-09T00:00:00Z",
      installed: "r2026-07-01",
      updateAvailable: false,
      main: { commit: MAIN, date: "2026-11-07", gradedChanges: 0, label: "l", installedCommit: MAIN },
    };
    expect(sigmaCheckAsOfNow(check, "r2026-07-01", INSTALLED).main).toEqual({ stale: true });
    expect(sigmaCheckAsOfNow(check, "main-2026-11-07-ccccccc-unreleased", MAIN).main).toMatchObject({
      gradedChanges: 0,
    });
  });
});

describe("downloadSigmaMain", () => {
  it("returns a release-shaped zip of the verified rule folders, naming the commit", async () => {
    const { fetchFn, fetchAsset } = fakeSigmaHQ({
      others: { "tests/huge.bin": "x".repeat(2 * 1024 * 1024) },
    });
    const zip = await downloadSigmaMain({ sha: MAIN, date: "2026-11-07" }, fetchFn, fetchAsset);
    const contents = readSigmaReleaseZip(zip);
    expect(contents.files.map((f) => f.path).sort()).toEqual(Object.keys(FILES).sort());
    expect(contents.commit).toBe(MAIN);
    expect(contents.versionLabel).toBe(sigmaMainLabel({ sha: MAIN, date: "2026-11-07" }));
  });

  it("fails when a rule does not match GitHub's listing", async () => {
    const tampered = { ...FILES, "rules/cloud/aws/cloudtrail/main_only.yml": `${RULE}# changed\n` };
    const { fetchFn, fetchAsset } = fakeSigmaHQ({ archive: tampered });
    await expect(downloadSigmaMain({ sha: MAIN, date: "2026-11-07" }, fetchFn, fetchAsset)).rejects.toThrow(
      /does not match GitHub's listing; nothing was installed/,
    );
  });

  it("fails when a listed rule is missing", async () => {
    const { fetchFn, fetchAsset } = fakeSigmaHQ({
      archive: { "rules-emerging-threats/2026/x.yml": FILES["rules-emerging-threats/2026/x.yml"] },
    });
    await expect(downloadSigmaMain({ sha: MAIN, date: "2026-11-07" }, fetchFn, fetchAsset)).rejects.toThrow(
      /missing 1 listed rule/,
    );
  });
});

describe("a main-branch install through the store", () => {
  it("previews as an unreleased release and installs", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-sigma-main-"));
    const store = new SigmaRuleStore(root, bundledSigmaDir(), {});
    await store.init();
    const { fetchFn, fetchAsset } = fakeSigmaHQ();
    const p = await store.previewMain(fetchFn, fetchAsset);
    expect(p.release.release).toBe("main-2026-11-07-ccccccc-unreleased");
    expect(p.usable).toBe(true);
    const active = await store.install(p.token);
    expect(active).toMatchObject({ release: "main-2026-11-07-ccccccc-unreleased", commit: MAIN });
  });
});

describe("whether the latest release is an update", () => {
  it("compares tags for a release install", () => {
    expect(releaseIsUpdate("r2026-10-01", "2026-10-05T00:00:00Z", "r2026-07-01")).toBe(true);
    expect(releaseIsUpdate("r2026-07-01", "2026-07-09T00:00:00Z", "r2026-07-01")).toBe(false);
  });

  it("over a main-branch install, only a release published after that commit counts", () => {
    const installed = "main-2026-11-07-ccccccc-unreleased";
    expect(releaseIsUpdate("r2026-07-01", "2026-07-09T00:00:00Z", installed)).toBe(false);
    expect(releaseIsUpdate("r2027-01-01", "2027-01-20T00:00:00Z", installed)).toBe(true);
    const check = {
      checkedAt: "x",
      latest: "r2026-07-01",
      publishedAt: "2026-07-09T00:00:00Z",
      installed: "r2026-07-01",
      updateAvailable: false,
    };
    expect(sigmaCheckAsOfNow(check, installed).updateAvailable).toBe(false);
  });
});

describe("readZip include filter", () => {
  it("reads only the entries the filter accepts and never inflates the rest", () => {
    const zip = createZip([
      { path: "a/keep.yml", data: Buffer.from("k") },
      { path: "a/big.bin", data: Buffer.alloc(4 * 1024 * 1024) },
    ]);
    const out = readZip(zip, { include: (p) => p.endsWith(".yml"), maxEntryBytes: 1024 });
    expect(out.map((e) => e.path)).toEqual(["a/keep.yml"]);
  });
});
