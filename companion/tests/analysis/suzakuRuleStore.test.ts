import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { bundledSigmaDir } from "../../src/analysis/sigmaBundledRules.js";
import { SigmaRuleStore } from "../../src/analysis/sigmaRuleStore.js";
import { bundledSuzakuDir } from "../../src/analysis/sigmaSuzakuRules.js";
import { SuzakuRuleStore } from "../../src/analysis/suzakuRuleStore.js";
import { matchSigmaRecord } from "../../src/analysis/sigmaRuleSet.js";
import { sigmaProvenanceToken } from "../../src/analysis/sigmaImportGrade.js";
import { fakeGitHub, ruleText, SHA_A } from "./fixtures/suzakuGitHub.js";

// #2508: installing a newer Suzaku commit, grading with it, rolling back, and falling back when an
// install cannot be read. GitHub is faked; rule data is synthetic.

const SIGMA_DIR = bundledSigmaDir() as string;
const SUZAKU_DIR = bundledSuzakuDir() as string;
const FILES = {
  "aws_new.yml": ruleText("00000000-0000-0000-0000-00000000a001", "Brand New Call", "critical", "test"),
  "aws_quiet.yml": ruleText("00000000-0000-0000-0000-00000000a002", "Quiet Call", "medium", "experimental"),
};
const COMMIT = { sha: SHA_A, date: "2026-11-20" };

async function stores(env: NodeJS.ProcessEnv = {}) {
  const root = await mkdtemp(join(tmpdir(), "dfir-suzaku-store-"));
  const suzaku = new SuzakuRuleStore(root, SUZAKU_DIR);
  await suzaku.init();
  const sigma = new SigmaRuleStore(root, SIGMA_DIR, env, suzaku);
  await sigma.init();
  const gh = fakeGitHub({ ...COMMIT, files: FILES });
  const measure = (f: Parameters<SigmaRuleStore["measureSuzaku"]>[0]) => sigma.measureSuzaku(f);
  return { root, suzaku, sigma, gh, measure };
}

const suzakuTitles = (sigma: SigmaRuleStore, eventName: string) =>
  matchSigmaRecord(sigma.activeRuleSet(), "aws-cloudtrail", { eventName })
    .matches.filter((m) => m.ref.origin === "Suzaku")
    .map((m) => m.ref);

describe("Suzaku rule updates", () => {
  it("starts on the bundled copy", async () => {
    const { suzaku } = await stores();
    expect(suzaku.active()).toMatchObject({ id: "bundled", release: "suzaku-2026-11-01", source: "bundled" });
    expect(suzaku.previous()).toBeNull();
  });

  it("checks GitHub and reports a newer commit", async () => {
    const { suzaku, gh } = await stores();
    const c = await suzaku.checkLatest(gh.fetchFn);
    expect(c).toMatchObject({
      updateAvailable: true,
      latest: "suzaku-2026-11-20-aaaaaaa",
      latestCommit: SHA_A,
    });
  });

  it("previews against the current settings, installs, grades with the new commit, and rolls back", async () => {
    const { suzaku, sigma, gh, measure } = await stores();
    const before = sigmaProvenanceToken(sigma.activeRuleSet(), "high");
    const p = await suzaku.preview(COMMIT, gh.fetchFn, gh.fetchAsset, measure);
    expect(p.usable).toBe(true);
    // Both rules load (statuses default to all three); only the critical one can raise severity.
    expect(p.measure).toEqual({ loads: 2, raises: 1 });
    expect(p.diff.added.length).toBe(2);
    expect(p.diff.removed.length).toBeGreaterThan(700);

    const active = await suzaku.install(p.token, measure);
    expect(active).toMatchObject({ release: "suzaku-2026-11-20-aaaaaaa", commit: SHA_A, source: "github" });
    const [ref] = suzakuTitles(sigma, "BrandNewCall");
    expect(ref.url).toBe(
      `https://github.com/Yamato-Security/suzaku-rules/blob/${SHA_A}/suzaku/aws/cloudtrail/aws_new.yml`,
    );
    expect(ref.release).toBe("suzaku-2026-11-20-aaaaaaa");
    expect(sigmaProvenanceToken(sigma.activeRuleSet(), "high")).not.toBe(before);
    expect(suzaku.checkAsOfNow()).toBeUndefined();

    expect(suzaku.previous()).toMatchObject({ id: "bundled" });
    await suzaku.rollback();
    expect(suzaku.active().id).toBe("bundled");
    expect(suzakuTitles(sigma, "BrandNewCall")).toEqual([]);
  });

  it("says no update is available once the checked commit is installed", async () => {
    const { suzaku, gh, measure } = await stores();
    await suzaku.checkLatest(gh.fetchFn);
    const p = await suzaku.preview(COMMIT, gh.fetchFn, gh.fetchAsset, measure);
    await suzaku.install(p.token, measure);
    expect(suzaku.checkAsOfNow()).toMatchObject({ updateAvailable: false, installedCommit: SHA_A });
  });

  it("re-measures at install and refuses when no rule would load now", async () => {
    const { root, suzaku, gh, measure } = await stores();
    const p = await suzaku.preview(COMMIT, gh.fetchFn, gh.fetchAsset, measure);
    const strict = new SigmaRuleStore(root, SIGMA_DIR, { DFIR_SIGMA_SUZAKU_STATUSES: "stable" }, suzaku);
    await expect(suzaku.install(p.token, (f) => strict.measureSuzaku(f))).rejects.toThrow(
      /none of these Suzaku rules would load/,
    );
    expect(suzaku.active().id).toBe("bundled");
  });

  it("refuses an unknown or stale preview token", async () => {
    const { suzaku, gh, measure } = await stores();
    await expect(suzaku.install("nope", measure)).rejects.toThrow(/preview is gone/);
    const p = await suzaku.preview(COMMIT, gh.fetchFn, gh.fetchAsset, measure);
    const q = await suzaku.preview(COMMIT, gh.fetchFn, gh.fetchAsset, measure);
    await expect(suzaku.install(p.token, measure)).rejects.toThrow(/preview is gone/);
    await expect(suzaku.install(q.token, measure)).resolves.toMatchObject({ commit: SHA_A });
  });

  it("falls back to the bundled copy — and says so everywhere — when the install cannot be read", async () => {
    const { root, suzaku, sigma, gh, measure } = await stores();
    const p = await suzaku.preview(COMMIT, gh.fetchFn, gh.fetchAsset, measure);
    const installed = await suzaku.install(p.token, measure);
    await rm(join(root, "sigma", "suzaku", "installs", installed.id, "rules"), { recursive: true });
    // A restart reads the manifest again.
    const fresh = new SuzakuRuleStore(root, SUZAKU_DIR);
    fresh.load();
    expect(fresh.active()).toMatchObject({ id: "bundled", release: "suzaku-2026-11-01" });
    const after = new SigmaRuleStore(root, SIGMA_DIR, {}, fresh).activeRuleSet();
    expect(after.problems.join(" ")).toMatch(/could not be read — using the bundled Suzaku rules/);
    expect(after.origins[0]).toMatchObject({ release: "suzaku-2026-11-01" });
    // Installing after a fallback records the bundled copy, not the broken install, as previous.
    const q = await fresh.preview(COMMIT, gh.fetchFn, gh.fetchAsset, (f) => sigma.measureSuzaku(f));
    await fresh.install(q.token, (f) => sigma.measureSuzaku(f));
    expect(fresh.previous()).toMatchObject({ id: "bundled" });
  });

  it("ignores a manifest naming a folder with corrupt metadata", async () => {
    const { root } = await stores();
    await mkdir(join(root, "sigma", "suzaku"), { recursive: true });
    await writeFile(
      join(root, "sigma", "suzaku", "active.json"),
      JSON.stringify({ active: "ghost", generation: 3 }),
    );
    const s = new SuzakuRuleStore(root, SUZAKU_DIR);
    s.load();
    expect(s.active().id).toBe("bundled");
    expect(s.activeSource().problems[0]).toMatch(/ghost could not be read/);
  });

  it("refuses to roll back with no previous version", async () => {
    const { suzaku } = await stores();
    await expect(suzaku.rollback()).rejects.toThrow(/no previous Suzaku version/);
  });
});
