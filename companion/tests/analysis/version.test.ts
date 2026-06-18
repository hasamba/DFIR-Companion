// companion/tests/analysis/version.test.ts
import { describe, it, expect, afterEach } from "vitest";
import { getAppVersion } from "../../src/version.js";

const SAVED = { baked: process.env.DFIR_BUILD_VERSION, npm: process.env.npm_package_version };
afterEach(() => {
  if (SAVED.baked === undefined) delete process.env.DFIR_BUILD_VERSION;
  else process.env.DFIR_BUILD_VERSION = SAVED.baked;
  if (SAVED.npm === undefined) delete process.env.npm_package_version;
  else process.env.npm_package_version = SAVED.npm;
});

describe("getAppVersion", () => {
  it("prefers the baked DFIR_BUILD_VERSION", () => {
    process.env.DFIR_BUILD_VERSION = "9.9.9";
    process.env.npm_package_version = "1.1.1";
    expect(getAppVersion()).toBe("9.9.9");
  });

  it("falls back to npm_package_version", () => {
    delete process.env.DFIR_BUILD_VERSION;
    process.env.npm_package_version = "1.2.3";
    expect(getAppVersion()).toBe("1.2.3");
  });

  it("falls back to reading package.json when no env is set", () => {
    delete process.env.DFIR_BUILD_VERSION;
    delete process.env.npm_package_version;
    const v = getAppVersion();
    expect(v).not.toBe("unknown");
    expect(v).toMatch(/^\d+\.\d+\.\d+/);
  });
});
