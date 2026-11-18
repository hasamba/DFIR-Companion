import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { rootCertificates } from "node:tls";
import { describe, expect, it } from "vitest";
import {
  checkFalconBaseUrl,
  ngsiemCredentialsFromEnv,
  ngsiemSettingsError,
} from "../../src/integrations/crowdstrike/ngsiemConfig.js";
import {
  currentNgsiemAgentForTest,
  NgsiemCaError,
  ngsiemFetchFor,
} from "../../src/integrations/crowdstrike/ngsiemTransport.js";

// #2685: the base URL is validated when it is read, and DFIR_CROWDSTRIKE_SIEM_CA is a PEM bundle.

describe("checkFalconBaseUrl", () => {
  it("accepts an https API host, trimming trailing slashes, keeping a port and a path prefix", () => {
    expect(checkFalconBaseUrl("https://api.us-2.crowdstrike.com/")).toEqual({
      ok: true,
      base: "https://api.us-2.crowdstrike.com",
    });
    expect(checkFalconBaseUrl("https://falcon.test:8443/prefix/")).toEqual({
      ok: true,
      base: "https://falcon.test:8443/prefix",
    });
  });

  it.each([
    ["api.crowdstrike.com", /not a valid URL/],
    ["http://api.crowdstrike.com", /https:\/\//],
    ["https://user:pw@api.crowdstrike.com", /user name or password/],
    ["https://api.crowdstrike.com/?x=1", /query or fragment/],
    ["https://api.crowdstrike.com/?", /query or fragment/],
    ["https://api.crowdstrike.com/#", /query or fragment/],
    ["https://falcon.crowdstrike.com/", /console/],
    ["https://falcon.us-2.crowdstrike.com/investigate", /console/],
  ])("refuses %s with a Settings sentence", (raw, why) => {
    const r = checkFalconBaseUrl(raw);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.error).toMatch(why);
      expect(r.error).toContain("DFIR_CROWDSTRIKE_SIEM_BASE_URL");
      expect(r.error).not.toContain("pw@");
    }
  });
});

describe("ngsiemSettingsError / credentials", () => {
  const on = { DFIR_CROWDSTRIKE_SIEM_CLIENT_ID: "id", DFIR_CROWDSTRIKE_SIEM_CLIENT_SECRET: "sec" };
  it("is null when the feature is off or the settings are fine", () => {
    expect(ngsiemSettingsError({})).toBeNull();
    expect(ngsiemSettingsError(on)).toBeNull();
  });
  it("names a bad base URL", () => {
    expect(ngsiemSettingsError({ ...on, DFIR_CROWDSTRIKE_SIEM_BASE_URL: "falcon.crowdstrike.com" })).toMatch(
      /BASE_URL/,
    );
  });
  it("names an unreadable CA bundle before any call", () => {
    expect(ngsiemSettingsError({ ...on, DFIR_CROWDSTRIKE_SIEM_CA: "/nonexistent/dfir/ca.pem" })).toMatch(
      /DFIR_CROWDSTRIKE_SIEM_CA could not be read/,
    );
  });
  it("reads the CA bundle path", () => {
    expect(ngsiemCredentialsFromEnv({ ...on, DFIR_CROWDSTRIKE_SIEM_CA: " /x/ca.pem " })?.ca).toBe(
      "/x/ca.pem",
    );
    expect(ngsiemCredentialsFromEnv(on)?.ca).toBeUndefined();
  });
});

describe("ngsiemFetchFor", () => {
  const dir = mkdtempSync(join(tmpdir(), "dfir-ngsiem-ca-"));
  it("no bundle: the default fetch", () => {
    expect(ngsiemFetchFor(undefined)).toBe(fetch);
  });
  it("a missing file or a file with no certificate is a Settings error naming the path", () => {
    expect(() => ngsiemFetchFor(join(dir, "missing.pem"))).toThrow(NgsiemCaError);
    expect(() => ngsiemFetchFor(join(dir, "missing.pem"))).toThrow(
      /DFIR_CROWDSTRIKE_SIEM_CA could not be read/,
    );
    const junk = join(dir, "junk.pem");
    writeFileSync(junk, "not a certificate");
    expect(() => ngsiemFetchFor(junk)).toThrow(/holds no PEM certificate/);
  });
  it("a PEM bundle builds one cached fetch, rebuilt when the file changes", () => {
    const pem = join(dir, "ca.pem");
    writeFileSync(pem, rootCertificates[0]);
    const a = ngsiemFetchFor(pem);
    expect(a).not.toBe(fetch);
    expect(ngsiemFetchFor(pem)).toBe(a);
    writeFileSync(pem, `${rootCertificates[0]}\n${rootCertificates[1]}`);
    expect(ngsiemFetchFor(pem)).not.toBe(a);
  });

  it("a rotated bundle leaves the old Agent open for a search still using it (review finding)", () => {
    const pem = join(dir, "rotate.pem");
    writeFileSync(pem, rootCertificates[0]);
    ngsiemFetchFor(pem);
    const old = currentNgsiemAgentForTest();
    writeFileSync(pem, `${rootCertificates[0]}\n${rootCertificates[2]}\n`);
    ngsiemFetchFor(pem);
    expect(currentNgsiemAgentForTest()).not.toBe(old);
    expect(old?.closed).toBe(false);
    expect(old?.destroyed).toBe(false);
  });
});
