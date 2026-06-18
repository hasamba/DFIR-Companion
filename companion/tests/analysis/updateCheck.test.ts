// companion/tests/analysis/updateCheck.test.ts
import { describe, it, expect } from "vitest";
import {
  compareVersions, isNewer, parseLatestRelease, resolveUpdateMode,
  buildUpdateStatus, githubLatestUrl, DEFAULT_UPDATE_REPO,
} from "../../src/analysis/updateCheck.js";

describe("compareVersions", () => {
  it("orders numeric cores and ignores a leading v", () => {
    expect(compareVersions("v1.2.0", "1.1.9")).toBe(1);
    expect(compareVersions("1.0.0", "1.0.0")).toBe(0);
    expect(compareVersions("0.23.0", "0.23.1")).toBe(-1);
  });
  it("treats a release as newer than its prerelease", () => {
    expect(compareVersions("1.2.3", "1.2.3-rc.1")).toBe(1);
    expect(compareVersions("1.2.3-rc.1", "1.2.3")).toBe(-1);
  });
  it("handles unequal segment counts", () => {
    expect(compareVersions("1.2", "1.2.0")).toBe(0);
    expect(compareVersions("1.2.1", "1.2")).toBe(1);
  });
});

describe("isNewer", () => {
  it("is false when current is unknown", () => {
    expect(isNewer("9.9.9", "unknown")).toBe(false);
    expect(isNewer("9.9.9", "")).toBe(false);
  });
  it("is true only when latest > current", () => {
    expect(isNewer("0.24.0", "0.23.0")).toBe(true);
    expect(isNewer("0.23.0", "0.23.0")).toBe(false);
  });
});

describe("parseLatestRelease", () => {
  it("reads tag_name / html_url / published_at", () => {
    const r = parseLatestRelease({ tag_name: "v0.24.0", html_url: "https://x/y", published_at: "2026-06-18T00:00:00Z" });
    expect(r).toEqual({ tag: "v0.24.0", version: "0.24.0", htmlUrl: "https://x/y", publishedAt: "2026-06-18T00:00:00Z" });
  });
  it("returns null on junk or a missing tag", () => {
    expect(parseLatestRelease(null)).toBeNull();
    expect(parseLatestRelease({})).toBeNull();
    expect(parseLatestRelease("nope")).toBeNull();
  });
  it("drops a non-https html_url (defense-in-depth against javascript: URLs)", () => {
    const r = parseLatestRelease({ tag_name: "v1.0.0", html_url: "javascript:alert(1)" });
    expect(r?.htmlUrl).toBe("");
  });
});

describe("resolveUpdateMode", () => {
  it("locks off when env is 0/false/off", () => {
    expect(resolveUpdateMode("0", true)).toEqual({ enabled: false, locked: true });
    expect(resolveUpdateMode("false", undefined)).toEqual({ enabled: false, locked: true });
  });
  it("defaults on when env is 1/true, stored wins", () => {
    expect(resolveUpdateMode("1", undefined)).toEqual({ enabled: true, locked: false });
    expect(resolveUpdateMode("true", false)).toEqual({ enabled: false, locked: false });
  });
  it("defaults off when env unset, stored wins", () => {
    expect(resolveUpdateMode(undefined, undefined)).toEqual({ enabled: false, locked: false });
    expect(resolveUpdateMode(undefined, true)).toEqual({ enabled: true, locked: false });
  });
});

describe("buildUpdateStatus", () => {
  it("computes isNewer from the cached result vs current", () => {
    const s = buildUpdateStatus({ enabled: true, locked: false }, "0.23.0", {
      latestVersion: "0.24.0", latestTag: "v0.24.0", htmlUrl: "https://x", checkedAt: 1000,
    });
    expect(s.isNewer).toBe(true);
    expect(s.latest).toBe("0.24.0");
    expect(s.current).toBe("0.23.0");
    expect(s.checkedAt).toBe(1000);
  });
  it("is safe with no cached result", () => {
    const s = buildUpdateStatus({ enabled: false, locked: false }, "0.23.0", undefined);
    expect(s.isNewer).toBe(false);
    expect(s.latest).toBeNull();
  });
});

describe("githubLatestUrl", () => {
  it("builds the releases/latest API url", () => {
    expect(githubLatestUrl(DEFAULT_UPDATE_REPO)).toBe("https://api.github.com/repos/hasamba/DFIR-Companion/releases/latest");
  });
});
