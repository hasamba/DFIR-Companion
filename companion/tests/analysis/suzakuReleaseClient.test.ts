import { describe, expect, it } from "vitest";
import {
  downloadSuzakuRules,
  gitBlobSha,
  latestSuzakuCommit,
  sameSuzakuFolders,
} from "../../src/analysis/suzakuReleaseClient.js";
import { fakeFolders, fakeGitHub, ruleText, SHA_A } from "./fixtures/suzakuGitHub.js";

// #2508: the Suzaku rule updater's GitHub client — newest commit, folder listing, archive download,
// and per-file verification against git blob SHAs. #2500: one snapshot of three watched folders.

const FILES = {
  "aws_one.yml": ruleText("00000000-0000-0000-0000-000000000001", "One"),
  "aws_two.yml": ruleText("00000000-0000-0000-0000-000000000002", "Two"),
};
const repo = { sha: SHA_A, date: "2026-11-20", files: FILES };

describe("latestSuzakuCommit", () => {
  it("reads the head of main and the watched folders' identities in two calls", async () => {
    const gh = fakeGitHub(repo);
    expect(await latestSuzakuCommit(gh.fetchFn)).toEqual({
      sha: SHA_A,
      date: "2026-11-20",
      folders: fakeFolders(FILES),
    });
    expect(gh.calls).toHaveLength(2);
    expect(gh.calls[0]).toContain("/commits?sha=main&per_page=1");
    expect(gh.calls[1]).toMatch(/\/git\/trees\/a{40}\?recursive=1$/);
  });

  it("walks the folders one level at a time when GitHub truncates the listing", async () => {
    const gh = fakeGitHub({ ...repo, truncated: true });
    expect((await latestSuzakuCommit(gh.fetchFn)).folders).toEqual(fakeFolders(FILES));
  });

  it("a change to one folder alone changes the identity; a commit outside them does not", () => {
    const m365 = { ...FILES, "m365/m365_x.yml": ruleText("00000000-0000-0000-0000-000000000003", "X") };
    const a = fakeFolders(FILES);
    const b = fakeFolders(m365);
    expect(b["suzaku/m365"]).not.toBe(a["suzaku/m365"]);
    expect(b["suzaku/aws/cloudtrail"]).toBe(a["suzaku/aws/cloudtrail"]);
    expect(sameSuzakuFolders(a, fakeFolders({ ...FILES }))).toBe(true);
    expect(sameSuzakuFolders(a, b)).toBe(false);
    expect(sameSuzakuFolders(a, undefined)).toBe(false);
  });

  it("refuses an answer without a commit SHA", async () => {
    const bad = (async () => new Response(JSON.stringify([{ sha: "nope" }]))) as unknown as typeof fetch;
    await expect(latestSuzakuCommit(bad)).rejects.toThrow(/could not read the newest Suzaku rule commit/);
  });
});

describe("downloadSuzakuRules", () => {
  it("returns every listed rule, verified, and never reads the SigmaHQ mirror", async () => {
    const gh = fakeGitHub({ ...repo, others: { "sigma/aws/x.yml": "title: mirror" } });
    const d = await downloadSuzakuRules({ sha: SHA_A, date: "2026-11-20" }, gh.fetchFn, gh.fetchAsset);
    expect(d.files.map((f) => f.path)).toEqual(["aws/cloudtrail/aws_one.yml", "aws/cloudtrail/aws_two.yml"]);
    expect(d.commit.folders).toEqual(fakeFolders(FILES));
    expect(d.files[0].text).toBe(FILES["aws_one.yml"]);
    expect(gh.calls.some((u) => u.endsWith(`/zipball/${SHA_A}`))).toBe(true);
  });

  it("takes every watched folder, keeping two files of the same name apart", async () => {
    const same = ruleText("00000000-0000-0000-0000-000000000004", "Same");
    const files = { ...FILES, "m365/same.yml": same, "azure/activity_logs/same.yml": `${same}# other\n` };
    const gh = fakeGitHub({ ...repo, files });
    const d = await downloadSuzakuRules(repo, gh.fetchFn, gh.fetchAsset);
    expect(d.files.map((f) => f.path)).toEqual([
      "aws/cloudtrail/aws_one.yml",
      "aws/cloudtrail/aws_two.yml",
      "azure/activity_logs/same.yml",
      "m365/same.yml",
    ]);
  });

  it("takes each Google Workspace application folder, and nothing in gws/ outside them (#2522)", async () => {
    const files = {
      ...FILES,
      "gws/admin/a.yml": ruleText("00000000-0000-0000-0000-000000000006", "A"),
      "gws/login/l.yml": ruleText("00000000-0000-0000-0000-000000000007", "L"),
      "gws/drive/d.yml": ruleText("00000000-0000-0000-0000-000000000008", "D"),
      "gws/calendar/c.yml": ruleText("00000000-0000-0000-0000-000000000009", "C"),
      "gws/stray.yml": ruleText("00000000-0000-0000-0000-00000000000a", "Stray"),
    };
    for (const truncated of [false, true]) {
      const gh = fakeGitHub({ ...repo, files, truncated });
      const d = await downloadSuzakuRules(repo, gh.fetchFn, gh.fetchAsset);
      expect(d.files.map((f) => f.path).filter((p) => p.startsWith("gws/"))).toEqual([
        "gws/admin/a.yml",
        "gws/calendar/c.yml",
        "gws/drive/d.yml",
        "gws/login/l.yml",
      ]);
    }
  });

  it("ignores a file in a sub-folder of a watched folder", async () => {
    const files = { ...FILES, "m365/old/x.yml": ruleText("00000000-0000-0000-0000-000000000005", "Old") };
    const gh = fakeGitHub({ ...repo, files });
    const d = await downloadSuzakuRules(repo, gh.fetchFn, gh.fetchAsset);
    expect(d.files.map((f) => f.path)).not.toContain("m365/old/x.yml");
  });

  it("fails when a file does not match GitHub's listing", async () => {
    const gh = fakeGitHub({
      ...repo,
      archive: { ...FILES, "aws_two.yml": `${FILES["aws_two.yml"]}# tampered\n` },
    });
    await expect(downloadSuzakuRules(repo, gh.fetchFn, gh.fetchAsset)).rejects.toThrow(
      /aws_two\.yml does not match GitHub's listing; nothing was installed/,
    );
  });

  it("fails when a listed file is missing from the archive", async () => {
    const gh = fakeGitHub({ ...repo, archive: { "aws_one.yml": FILES["aws_one.yml"] } });
    await expect(downloadSuzakuRules(repo, gh.fetchFn, gh.fetchAsset)).rejects.toThrow(
      /missing 1 listed rule/,
    );
  });

  it("refuses an archive served from a host other than GitHub", async () => {
    const gh = fakeGitHub({ ...repo, archiveHost: "evil.example" });
    await expect(downloadSuzakuRules(repo, gh.fetchFn, gh.fetchAsset)).rejects.toThrow(
      /host other than GitHub/,
    );
  });

  it("refuses a rule bigger than the loader reads", async () => {
    const big = `${FILES["aws_one.yml"]}#${"x".repeat(130 * 1024)}\n`;
    const gh = fakeGitHub({ ...repo, files: { "aws_one.yml": big } });
    await expect(downloadSuzakuRules(repo, gh.fetchFn, gh.fetchAsset)).rejects.toThrow(/larger than 128 KB/);
  });

  it("computes git's blob SHA", () => {
    // `printf 'hello\n' | git hash-object --stdin`
    expect(gitBlobSha(Buffer.from("hello\n"))).toBe("ce013625030ba8dba906f756967f9e9ca394464a");
  });
});
