import { describe, it, expect } from "vitest";
import { isInternalIpv4 } from "../../src/analysis/internalIp.js";

// Direct unit spec of the ONE shared range table (TC2-1). Every importer that keeps only public
// IPs as IOCs, plus siemImport's logon-risk grading, routes through this — before this file its
// range boundaries were pinned only indirectly, via one emailImport Received-walk test.
describe("isInternalIpv4 — the shared internal-range table", () => {
  it("classifies every internal range as internal", () => {
    expect(isInternalIpv4("10.0.0.1")).toBe(true); // RFC1918 10/8
    expect(isInternalIpv4("127.0.0.1")).toBe(true); // loopback
    expect(isInternalIpv4("0.1.2.3")).toBe(true); // 0.0.0.0/8 "this network"
    expect(isInternalIpv4("192.168.1.1")).toBe(true); // RFC1918 192.168/16
    expect(isInternalIpv4("172.16.0.1")).toBe(true); // RFC1918 172.16/12 lower edge
    expect(isInternalIpv4("172.31.255.255")).toBe(true); // RFC1918 172.16/12 upper edge
    expect(isInternalIpv4("169.254.10.10")).toBe(true); // link-local
    expect(isInternalIpv4("100.64.0.1")).toBe(true); // CGNAT 100.64/10 lower edge
    expect(isInternalIpv4("100.127.255.255")).toBe(true); // CGNAT 100.64/10 upper edge
  });

  it("leaves the boundary neighbours of each range public", () => {
    expect(isInternalIpv4("172.15.255.255")).toBe(false); // below 172.16/12
    expect(isInternalIpv4("172.32.0.1")).toBe(false); // above 172.16/12
    expect(isInternalIpv4("100.63.255.255")).toBe(false); // below CGNAT
    expect(isInternalIpv4("100.128.0.1")).toBe(false); // above CGNAT
    expect(isInternalIpv4("192.169.0.1")).toBe(false); // beside 192.168/16
  });

  // False here means "not internal IPv4", NOT "public": a caller that needs "public IPv4" must
  // also require the IPv4 shape (see siemImport's isPublicIpv4 and its comment) — a plain
  // negation would call blank and IPv6 sources public.
  it("returns false for non-IPv4 shapes — blank, placeholder, IPv6, truncated", () => {
    expect(isInternalIpv4("")).toBe(false);
    expect(isInternalIpv4("-")).toBe(false);
    expect(isInternalIpv4("::1")).toBe(false);
    expect(isInternalIpv4("2001:db8::5")).toBe(false);
    expect(isInternalIpv4("10.0.0")).toBe(false);
  });
});
