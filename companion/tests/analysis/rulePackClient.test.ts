import { describe, expect, it } from "vitest";
import { findLatestRulePack, listRulePackReleases } from "../../src/analysis/rulePackClient.js";
import { comparePackVersions, packFit, parseRulePackManifest } from "../../src/analysis/rulePackManifest.js";
import { RULES_V1, RULES_V2, fakeGitHub, manifestFor, sha } from "./rulePackFixtures.js";

// The detection-rule pack client (#2349): this project's rules-* releases only, GitHub hosts only,
// size-capped, SHA-256 against GitHub's digest AND the manifest, newer-app packs refused.

const v1 = { tag: "rules-2026.11.01", rules: RULES_V1, manifest: manifestFor(RULES_V1, "rules-2026.11.01") };
const v2 = { tag: "rules-2026.11.05", rules: RULES_V2, manifest: manifestFor(RULES_V2, "rules-2026.11.05") };

describe("rule pack manifest", () => {
  it("orders pack versions by date then .N", () => {
    expect(comparePackVersions("rules-2026.11.05", "rules-2026.11.01")).toBe(1);
    expect(comparePackVersions("rules-2026.11.05.2", "rules-2026.11.05")).toBe(1);
    expect(comparePackVersions("rules-2026.11.05", "rules-2026.11.05")).toBe(0);
  });
  it("fits only packs built at this app version", () => {
    expect(packFit("0.45.0", "0.45.0")).toBe("ok");
    expect(packFit("0.46.0", "0.45.0")).toBe("needs-newer-app");
    expect(packFit("0.44.0", "0.45.0")).toBe("superseded");
  });
  it("rejects a malformed manifest with a sentence", () => {
    expect(() => parseRulePackManifest("{")).toThrow(/not valid JSON/);
    expect(() => parseRulePackManifest(JSON.stringify({ schema: 1 }))).toThrow(/not valid/);
  });
});

describe("rule pack client", () => {
  it("keeps only rules-* releases, newest first", async () => {
    const gh = fakeGitHub(
      [v1, v2],
      [
        { tag_name: "v0.45.0", assets: [] },
        { tag_name: "rules-2026.11.09", draft: true, assets: [] },
      ],
    );
    const refs = await listRulePackReleases(gh.fetchFn);
    expect(refs.map((r) => r.tag)).toEqual(["rules-2026.11.05", "rules-2026.11.01"]);
  });

  it("downloads the newest loadable pack, verified", async () => {
    const gh = fakeGitHub([v1, v2]);
    const out = await findLatestRulePack({ ...gh, appVersion: "0.45.0" });
    expect(out.status).toBe("found");
    expect(out.pack?.tag).toBe("rules-2026.11.05");
    expect(out.pack?.rulesSha256).toBe(sha(RULES_V2));
  });

  it("refuses a pack that needs a newer app, naming it, and falls back to an older loadable one", async () => {
    const newer = {
      tag: "rules-2026.11.07",
      rules: RULES_V2,
      manifest: manifestFor(RULES_V2, "rules-2026.11.07", "0.46.0"),
    };
    const gh = fakeGitHub([v1, newer]);
    const out = await findLatestRulePack({ ...gh, appVersion: "0.45.0" });
    expect(out.newerNeedsApp?.message).toMatch(/needs DFIR Companion 0\.46\.0 or newer \(this is 0\.45\.0\)/);
    expect(out.pack?.tag).toBe("rules-2026.11.01");
    const only = await findLatestRulePack({ ...fakeGitHub([newer]), appVersion: "0.45.0" });
    expect(only.status).toBe("none");
    expect(only.newerNeedsApp?.tag).toBe("rules-2026.11.07");
  });

  it("calls a pack built for an older app superseded", async () => {
    const old = {
      tag: "rules-2026.10.01",
      rules: RULES_V1,
      manifest: manifestFor(RULES_V1, "rules-2026.10.01", "0.44.0"),
    };
    const out = await findLatestRulePack({ ...fakeGitHub([old]), appVersion: "0.45.0" });
    expect(out.status).toBe("superseded");
    expect(out.pack).toBeUndefined();
  });

  it("refuses bytes that do not match GitHub's digest", async () => {
    const bad = { ...v2, rulesDigest: "0".repeat(64) };
    await expect(findLatestRulePack({ ...fakeGitHub([bad]), appVersion: "0.45.0" })).rejects.toThrow(
      /does not match GitHub's published SHA-256/,
    );
  });

  it("refuses a rules file that does not match the manifest, even when GitHub's digest matches", async () => {
    const lying = { ...v2, manifest: manifestFor(RULES_V1, v2.tag) };
    await expect(findLatestRulePack({ ...fakeGitHub([lying]), appVersion: "0.45.0" })).rejects.toThrow(
      /does not match the SHA-256 in the rule pack manifest/,
    );
  });

  it("refuses an asset from a host that is not GitHub's", async () => {
    const evil = { ...v2, rulesUrl: "https://evil.example/tags.yaml" };
    await expect(findLatestRulePack({ ...fakeGitHub([evil]), appVersion: "0.45.0" })).rejects.toThrow(
      /unexpected host/,
    );
  });

  it("refuses a rules file over the size cap", async () => {
    const huge = "x".repeat(4 * 1024 * 1024 + 10);
    const big = { tag: "rules-2026.11.06", rules: huge, manifest: manifestFor(huge, "rules-2026.11.06") };
    await expect(findLatestRulePack({ ...fakeGitHub([big]), appVersion: "0.45.0" })).rejects.toThrow(
      /larger than/,
    );
  });

  it("refuses a manifest whose version is not its release tag", async () => {
    const swapped = { ...v2, manifest: manifestFor(RULES_V2, "rules-2026.11.01") };
    await expect(findLatestRulePack({ ...fakeGitHub([swapped]), appVersion: "0.45.0" })).rejects.toThrow(
      /names version/,
    );
  });
});
