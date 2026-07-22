import { describe, it, expect } from "vitest";
import { repairIocValue, isWellFormedIocValue } from "../../src/analysis/iocValue.js";

describe("repairIocValue", () => {
  describe("annotation stripping (#177)", () => {
    it("moves a trailing host label out of an IP value and into `note`", () => {
      expect(repairIocValue({ type: "ip", value: "10.10.20.15 (DC01)" }))
        .toEqual({ value: "10.10.20.15", note: "DC01" });
    });

    it("handles the reversed form, where the parenthesised half is the indicator", () => {
      expect(repairIocValue({ type: "ip", value: "FS01 (10.10.20.30)" }))
        .toEqual({ value: "10.10.20.30", note: "FS01" });
    });

    it("strips a descriptive annotation from a url value", () => {
      expect(repairIocValue({ type: "url", value: "northlakeportal.com (wdi-svc.exe download URL)" }))
        .toEqual({ value: "northlakeportal.com", note: "wdi-svc.exe download URL" });
    });

    it("strips an annotation from a domain value, keeping the casing it was seen with", () => {
      expect(repairIocValue({ type: "domain", value: "Evil.Example.COM (C2 domain)" }))
        .toEqual({ value: "Evil.Example.COM", note: "C2 domain" });
    });

    it("keeps parentheses that are part of the indicator itself (no space before the paren)", () => {
      const url = "https://en.wikipedia.org/wiki/Foo_(bar)";
      expect(repairIocValue({ type: "url", value: url })).toEqual({ value: url });
    });

    it("never splits on parentheses for path-like types — a filename may legitimately contain them", () => {
      const path = "C:\\Users\\jsmith\\Downloads\\invoice (1).xlsm";
      expect(repairIocValue({ type: "file", value: path })).toEqual({ value: path });
    });

    it("drops an annotation that adds nothing (same text as the indicator)", () => {
      expect(repairIocValue({ type: "ip", value: "10.0.0.5 (10.0.0.5)" })).toEqual({ value: "10.0.0.5" });
    });
  });

  describe("per-type canonicalization", () => {
    it("unwraps an IPv4-mapped IPv6 address", () => {
      expect(repairIocValue({ type: "ip", value: "::ffff:10.0.0.1" })).toEqual({ value: "10.0.0.1" });
    });

    it("splits a trailing port off an IPv4 value", () => {
      expect(repairIocValue({ type: "ip", value: "185.220.101.47:443" }))
        .toEqual({ value: "185.220.101.47", note: "port 443" });
    });

    it("validates a hash case-insensitively but keeps the casing it was seen with", () => {
      const sha = "3B4A5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9C0D1E2F3A4B";
      expect(repairIocValue({ type: "hash", value: sha })).toEqual({ value: sha });
    });

    it("strips a trailing dot from a fully-qualified domain", () => {
      expect(repairIocValue({ type: "domain", value: "evil.example.com." })).toEqual({ value: "evil.example.com" });
    });

    it("trims surrounding whitespace on every type", () => {
      expect(repairIocValue({ type: "process", value: "  svchost32.exe \n" })).toEqual({ value: "svchost32.exe" });
    });
  });

  describe("rejecting unusable values", () => {
    it("rejects an empty / whitespace-only value", () => {
      expect(repairIocValue({ type: "ip", value: "   " })).toBeNull();
    });

    it("rejects a multi-line blob stored as an indicator", () => {
      const blob = "nd any 'Group Membership'\nsection data is processed if present.\n.PARAMETER Identity\n";
      expect(repairIocValue({ type: "ip", value: blob })).toBeNull();
    });

    it("rejects a value far longer than any real indicator of that type", () => {
      expect(repairIocValue({ type: "ip", value: "1".repeat(200) })).toBeNull();
      expect(repairIocValue({ type: "domain", value: `${"a".repeat(300)}.com` })).toBeNull();
    });

    it("keeps a single-line value it cannot validate, rather than dropping evidence", () => {
      // 66 hex chars — not a real hash length, but it is a plausible analyst-entered token.
      // Export layers reject it explicitly; ingest must not silently discard it.
      const odd = "cafe0001002003004005006007008009000a000b000c000d000e000f0010001100";
      expect(repairIocValue({ type: "hash", value: odd })).toEqual({ value: odd });
    });

    it("keeps an unknown IOC type verbatim (types outside the union exist in older cases)", () => {
      expect(repairIocValue({ type: "vulnerability", value: "CVE-2021-44228" }))
        .toEqual({ value: "CVE-2021-44228" });
    });
  });
});

describe("isWellFormedIocValue", () => {
  it("accepts bare indicators", () => {
    expect(isWellFormedIocValue("ip", "10.10.20.15")).toBe(true);
    expect(isWellFormedIocValue("ip", "2001:db8::1")).toBe(true);
    expect(isWellFormedIocValue("domain", "evil.example.com")).toBe(true);
    expect(isWellFormedIocValue("domain", "dc01")).toBe(true);
    expect(isWellFormedIocValue("url", "http://evil.example/a.ps1")).toBe(true);
    expect(isWellFormedIocValue("hash", "d41d8cd98f00b204e9800998ecf8427e")).toBe(true);
  });

  it("rejects the annotated forms that strict consumers (MISP) refuse", () => {
    expect(isWellFormedIocValue("ip", "10.10.20.15 (DC01)")).toBe(false);
    expect(isWellFormedIocValue("domain", "evil.example.com (C2)")).toBe(false);
    expect(isWellFormedIocValue("url", "evil.example (download)")).toBe(false);
  });

  it("rejects a hash that is not a recognised digest length", () => {
    expect(isWellFormedIocValue("hash", "cafe0001002003004005006007008009000a000b000c000d000e000f0010001100")).toBe(false);
    expect(isWellFormedIocValue("hash", "deadbeef")).toBe(false);
  });

  it("has no opinion on free-form types — they are always well formed once trimmed", () => {
    expect(isWellFormedIocValue("file", "C:\\Windows\\Temp\\svchost32.exe")).toBe(true);
    expect(isWellFormedIocValue("other", "jsmith@globaltech.com")).toBe(true);
  });
});
