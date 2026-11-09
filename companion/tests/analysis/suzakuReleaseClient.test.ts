import { describe, expect, it } from "vitest";
import {
  downloadSuzakuRules,
  gitBlobSha,
  latestSuzakuCommit,
} from "../../src/analysis/suzakuReleaseClient.js";
import { fakeGitHub, ruleText, SHA_A } from "./fixtures/suzakuGitHub.js";

// #2508: the Suzaku rule updater's GitHub client — newest commit, folder listing, archive download,
// and per-file verification against git blob SHAs.

const FILES = {
  "aws_one.yml": ruleText("00000000-0000-0000-0000-000000000001", "One"),
  "aws_two.yml": ruleText("00000000-0000-0000-0000-000000000002", "Two"),
};
const repo = { sha: SHA_A, date: "2026-11-20", files: FILES };

describe("latestSuzakuCommit", () => {
  it("reads the newest commit touching the CloudTrail folder", async () => {
    const gh = fakeGitHub(repo);
    expect(await latestSuzakuCommit(gh.fetchFn)).toEqual({ sha: SHA_A, date: "2026-11-20" });
    expect(gh.calls[0]).toContain("path=suzaku%2Faws%2Fcloudtrail");
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
    expect(d.files.map((f) => f.name)).toEqual(["aws_one.yml", "aws_two.yml"]);
    expect(d.files[0].text).toBe(FILES["aws_one.yml"]);
    expect(gh.calls.some((u) => u.endsWith(`/zipball/${SHA_A}`))).toBe(true);
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
