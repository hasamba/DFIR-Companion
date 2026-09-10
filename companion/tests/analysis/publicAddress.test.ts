import { describe, it, expect } from "vitest";
import { addressReach, ipv6Groups, reachPhrase } from "../../src/analysis/publicAddress.js";

describe("addressReach — IPv4", () => {
  it("calls a routable address public", () => {
    for (const ip of ["203.0.113.9", "198.51.100.4", "8.8.8.8", "172.32.0.1", "100.128.0.1"]) {
      expect(addressReach(ip), ip).toBe("public");
    }
  });

  // Kept in lockstep with iocValue.ts and internalIp.ts. CGNAT and link-local are the rows that drift.
  it("calls every private, loopback, link-local and CGNAT range private", () => {
    for (const ip of [
      "10.0.1.5",
      "172.16.0.4",
      "172.31.255.254",
      "192.168.1.10",
      "127.0.0.1",
      "0.0.0.0",
      "169.254.169.254",
      "100.64.0.1",
      "100.127.255.255",
    ]) {
      expect(addressReach(ip), ip).toBe("private");
    }
  });

  it("refuses to read a malformed address rather than calling it public", () => {
    for (const ip of ["999.1.1.1", "1.2.3.4.5", "1.2.3", "not-an-address", "", "   "]) {
      expect(addressReach(ip), ip).toBe("unreadable");
    }
  });
});

describe("addressReach — IPv6", () => {
  // The first version had no IPv6 handling at all, so every one of these came back "not public"
  // and the caller then printed "the source was inside the network".
  it("calls a global address public", () => {
    for (const ip of ["2001:db8::1", "2606:4700:4700::1111", "[2001:db8::1]", "::ffff:203.0.113.9"]) {
      expect(addressReach(ip), ip).toBe("public");
    }
  });

  it("calls loopback, unique-local, link-local and mapped-private addresses private", () => {
    for (const ip of [
      "::1",
      "::",
      "fc00::1",
      "fd12:3456::1",
      "fe80::1",
      "febf::1",
      "::ffff:10.0.0.1",
      "::10.0.0.1",
    ]) {
      expect(addressReach(ip), ip).toBe("private");
    }
  });

  it("refuses to read a malformed IPv6 address", () => {
    for (const ip of ["2001:db8::1::2", "gggg::1", "2001:db8:1"]) {
      expect(addressReach(ip), ip).toBe("unreadable");
    }
  });

  it("expands the compressed form", () => {
    expect(ipv6Groups("::1")).toEqual([0, 0, 0, 0, 0, 0, 0, 1]);
    expect(ipv6Groups("2001:db8::1")).toEqual([0x2001, 0x0db8, 0, 0, 0, 0, 0, 1]);
    expect(ipv6Groups("::ffff:203.0.113.9")).toEqual([0, 0, 0, 0, 0, 0xffff, 0xcb00, 0x7109]);
    expect(ipv6Groups("1:2:3:4:5:6:7:8")).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
    expect(ipv6Groups("1:2:3:4:5:6:7")).toBeNull();
  });
});

describe("reachPhrase — an unreadable address never reads as an internal one", () => {
  it("says what it means in each case", () => {
    expect(reachPhrase("203.0.113.9", "public")).toContain("outside the network");
    expect(reachPhrase("10.0.0.1", "private")).toContain("an internal address");
    expect(reachPhrase("garbage", "unreadable")).toContain("could not be read");
    expect(reachPhrase("", "unreadable")).toContain("did not record");
  });
});
