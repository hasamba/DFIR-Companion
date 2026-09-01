import { describe, it, expect } from "vitest";
import { isGloballyRoutable, ipv4ToBytes, ipv6ToBytes } from "../../src/routes/publicAddress.js";

// ── The address test is an allowlist ─────────────────────────────────────────
// A denylist permits by default, so every range nobody thought to name is reachable. These are the
// ranges isInternalTarget() does NOT classify as internal — each one was permitted before the test
// was inverted to "must be globally routable unicast".
describe("isGloballyRoutable", () => {
  it.each([
    ["93.184.216.34", "ordinary public IPv4"],
    ["8.8.8.8", "public resolver"],
    ["2606:4700::1111", "public IPv6"],
  ])("allows %s (%s)", (address) => {
    expect(isGloballyRoutable(address)).toBe(true);
  });

  it.each([
    ["240.0.0.1", "240/4 reserved — permitted by the old denylist"],
    ["255.255.255.255", "broadcast"],
    ["224.0.0.1", "multicast"],
    ["198.18.0.1", "198.18/15 benchmarking"],
    ["192.0.0.1", "192.0.0/24 IETF protocol assignments"],
    ["192.88.99.1", "6to4 relay anycast"],
    ["192.0.2.1", "TEST-NET-1"],
    ["198.51.100.1", "TEST-NET-2"],
    ["203.0.113.1", "TEST-NET-3"],
  ])("refuses %s (%s)", (address) => {
    expect(isGloballyRoutable(address)).toBe(false);
  });

  it.each([
    ["10.0.0.1", "RFC1918"],
    ["172.16.0.1", "RFC1918"],
    ["192.168.1.1", "RFC1918"],
    ["127.0.0.1", "loopback"],
    ["169.254.169.254", "cloud metadata"],
    ["100.64.0.1", "CGNAT"],
    ["0.0.0.0", "this network"],
  ])("still refuses %s (%s)", (address) => {
    expect(isGloballyRoutable(address)).toBe(false);
  });

  it.each([
    ["::1", "loopback"],
    ["fd00::1", "unique-local"],
    ["fe80::1", "link-local"],
    ["ff02::1", "multicast"],
    ["2001:db8::1", "documentation"],
    ["::ffff:169.254.169.254", "IPv4-mapped metadata"],
  ])("refuses IPv6 %s (%s)", (address) => {
    expect(isGloballyRoutable(address)).toBe(false);
  });

  // NAT64 carries an IPv4 address inside an IPv6 one. 64:ff9b:: was delegated to nobody, so the
  // allowlist refuses it without needing to know what NAT64 is — which is the point of an
  // allowlist: it does not have to recognise the trick to stop it.
  it("refuses a NAT64 address carrying the metadata service", () => {
    expect(isGloballyRoutable("64:ff9b::a9fe:a9fe")).toBe(false);
  });

  // 6to4 is deprecated (RFC 7526) and was never delegated to an RIR, so the allowlist refuses all
  // of 2002::/16 without unwrapping the IPv4 address inside it. The unwrap used to be a special
  // case, and a special case is only ever correct for the payloads someone thought to check.
  it("refuses 6to4 whatever address it tunnels to", () => {
    expect(isGloballyRoutable("2002:a9fe:a9fe::1")).toBe(false); // 169.254.169.254
    expect(isGloballyRoutable("2002:0a00:0001::1")).toBe(false); // 10.0.0.1
    expect(isGloballyRoutable("2002:5db8:d822::1")).toBe(false); // 93.184.216.34 — refused too
  });

  it("refuses Teredo, which tunnels IPv4 too", () => {
    expect(isGloballyRoutable("2001:0:53aa:64c::1")).toBe(false);
  });

  it("refuses anything it cannot parse rather than guessing", () => {
    expect(isGloballyRoutable("")).toBe(false);
    expect(isGloballyRoutable("not-an-address")).toBe(false);
    expect(isGloballyRoutable("999.1.1.1")).toBe(false);
  });
});

// "Top three bits are 001" is necessary but not sufficient. IANA carves special-purpose blocks out
// of global unicast, so each of these sits INSIDE 2000::/3 and was permitted by the first version
// of the allowlist.
describe("isGloballyRoutable — non-global blocks inside 2000::/3", () => {
  it.each([
    ["3fff::1", "documentation, RFC 9637 — inside 2000::/3 and easy to miss"],
    ["3fff:0fff:ffff::1", "top of the 3fff::/20 documentation block"],
    ["2001:2::1", "benchmarking, 2001:2::/48"],
    ["2001:20::1", "ORCHIDv2, 2001:20::/28"],
    ["2001:10::1", "deprecated ORCHID, 2001:10::/28"],
    ["2001:30::1", "drone remote ID, 2001:30::/28"],
    ["2001:4:112::1", "AMT, 2001:4:112::/48"],
    ["2001:1::1", "port control protocol anycast"],
    ["2001:1::2", "TURN server anycast"],
    ["2001:1::3", "DNS-SD service registration anycast"],
    ["2001::1", "Teredo, 2001::/32"],
    ["2001:db8::1", "documentation, RFC 3849"],
    ["2620:4f:8000::1", "AS112 direct delegation"],
  ])("refuses %s (%s)", (address) => {
    expect(isGloballyRoutable(address)).toBe(false);
  });

  // The boundaries of the parent 2001:0000::/23 block, so the prefix arithmetic is pinned rather
  // than assumed: 2001:01ff:: is the last address in it, 2001:0200:: the first one outside.
  it("refuses the whole IETF protocol-assignment block, and stops at its edge", () => {
    expect(isGloballyRoutable("2001:0:0:0:0:0:0:1")).toBe(false);
    expect(isGloballyRoutable("2001:1ff::1")).toBe(false);
    expect(isGloballyRoutable("2001:200::1")).toBe(true); // real global unicast begins here
  });

  it("still allows ordinary global unicast next to the carve-outs", () => {
    expect(isGloballyRoutable("2606:4700::1111")).toBe(true); // ARIN 2600::/12
    expect(isGloballyRoutable("2620:4f:7fff::1")).toBe(true); // just below the AS112 block
    expect(isGloballyRoutable("2a00:1450:4001::1")).toBe(true); // RIPE NCC 2a00::/12
    expect(isGloballyRoutable("2001:4860:4860::8888")).toBe(true); // ARIN 2001:4800::/23
  });

  // Returned 6bone space: inside 2000::/3, delegated to nobody. It was permitted for as long as
  // "top three bits are 001" was the rule, and an earlier version of this test asserted so.
  it("refuses the returned 6bone range", () => {
    expect(isGloballyRoutable("3ffe::1")).toBe(false);
    expect(isGloballyRoutable("3ffe:ffff::1")).toBe(false);
  });

  // The blocks that made "2000::/3 minus exceptions" the wrong shape: all reserved, all inside it.
  it.each([
    ["3000::1", "3000::/4 reserved by IETF"],
    ["3fff:ffff::1", "top of the reserved 3000::/4"],
    ["2e00::1", "2e00::/7 reserved"],
    ["2d00::1", "2d00::/8 reserved"],
    ["2004::1", "unallocated inside 2000::/12"],
    ["2100::1", "unallocated"],
    ["2200::1", "unallocated"],
  ])("refuses %s (%s)", (address) => {
    expect(isGloballyRoutable(address)).toBe(false);
  });

  it("refuses an address carrying a zone index rather than parsing past it", () => {
    expect(isGloballyRoutable("fe80::1%eth0")).toBe(false);
    expect(isGloballyRoutable("2606:4700::1111%eth0")).toBe(false);
  });
});

// The parser is the part a table-driven classifier rests on: a CIDR that parses wrong is a hole
// that no range test would notice, so it is pinned directly.
describe("address parsing", () => {
  it("reads a dotted quad, and refuses one with an out-of-range octet", () => {
    expect(ipv4ToBytes("93.184.216.34")).toEqual([93, 184, 216, 34]);
    expect(ipv4ToBytes("256.1.1.1")).toBeNull();
    expect(ipv4ToBytes("1.2.3")).toBeNull();
    expect(ipv4ToBytes("")).toBeNull();
  });

  it("expands :: to the right number of zero groups", () => {
    expect(ipv6ToBytes("::1")).toEqual([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    expect(ipv6ToBytes("2001:db8::1")?.slice(0, 4)).toEqual([0x20, 0x01, 0x0d, 0xb8]);
    expect(ipv6ToBytes("::")).toEqual(new Array(16).fill(0));
  });

  it("reads a fully written address with no ::", () => {
    expect(ipv6ToBytes("2001:0db8:0000:0000:0000:0000:0000:0001")?.length).toBe(16);
    expect(ipv6ToBytes("2001:db8:0:0:0:0:0:1")?.[15]).toBe(1);
  });

  // The trailing dotted-quad forms are valid IPv6 text, so they have to be READ and then judged —
  // an unparseable-therefore-refused shortcut would refuse 2606:4700::93.184.216.34 too.
  it("reads the trailing dotted-quad forms", () => {
    expect(ipv6ToBytes("::ffff:169.254.169.254")?.slice(10)).toEqual([0xff, 0xff, 169, 254, 169, 254]);
    expect(ipv6ToBytes("2001:db8::192.0.2.1")?.slice(12)).toEqual([192, 0, 2, 1]);
  });

  it("refuses text that is not an address", () => {
    expect(ipv6ToBytes("2001:db8::1::2")).toBeNull(); // two ::
    expect(ipv6ToBytes("2001:zzzz::1")).toBeNull();
    expect(ipv6ToBytes("2001:db8:1")).toBeNull(); // too short, no ::
    expect(ipv6ToBytes("fe80::1%eth0")).toBeNull(); // zone index
    expect(ipv6ToBytes("1.2.3.4::1")).toBeNull(); // dotted quad not last
    expect(ipv6ToBytes("")).toBeNull();
  });
});

// Every entry in the two tables has to parse, or the guard has a hole where a typo is. parseCidr
// throws at load, so importing the module at all is most of this test; the rest pins that the
// boundaries of a few awkward prefixes land where they should.
describe("CIDR boundaries", () => {
  it.each([
    ["100.63.255.255", true], // just below CGNAT
    ["100.64.0.0", false], // first CGNAT
    ["100.127.255.255", false], // last CGNAT
    ["100.128.0.0", true], // just above
    ["198.17.255.255", true], // just below benchmarking
    ["198.18.0.0", false],
    ["198.19.255.255", false], // /15 spans two octets
    ["198.20.0.0", true],
    ["223.255.255.255", true], // just below multicast
    ["224.0.0.0", false],
    ["239.255.255.255", false],
    ["240.0.0.0", false],
    ["255.255.255.255", false], // broadcast, inside 240/4
  ])("puts %s on the right side of its boundary", (address, routable) => {
    expect(isGloballyRoutable(address)).toBe(routable);
  });

  it("reads an address in brackets, as a URL host carries it", () => {
    expect(isGloballyRoutable("[2606:4700::1111]")).toBe(true);
    expect(isGloballyRoutable("[::1]")).toBe(false);
  });
});

// The failure mode of an allowlist is the opposite of a denylist's: a missing row refuses a real
// customer rather than admitting an attacker. Writing the table from memory dropped 2410::/12 and
// 2a10::/12 — an entire APNIC and an entire RIPE NCC delegation — so every delegated block gets a
// probe, and the reserved blocks between them get one too.
describe("delegated IPv6 space is not refused", () => {
  it.each([
    ["2001:200::1", "APNIC"],
    ["2001:400::1", "ARIN"],
    ["2001:600::1", "RIPE NCC"],
    ["2001:800::1", "RIPE NCC /22"],
    ["2001:bff:ffff::1", "top of RIPE NCC 2001:800::/22"],
    ["2001:c00::1", "APNIC"],
    ["2001:e00::1", "APNIC"],
    ["2001:1200::1", "LACNIC"],
    ["2001:1400::1", "RIPE NCC /22"],
    ["2001:17ff:ffff::1", "top of RIPE NCC 2001:1400::/22"],
    ["2001:1800::1", "ARIN"],
    ["2001:1a00::1", "RIPE NCC"],
    ["2001:1c00::1", "RIPE NCC"],
    ["2001:2000::1", "RIPE NCC /19"],
    ["2001:3fff:ffff::1", "top of RIPE NCC 2001:2000::/19"],
    ["2001:4000::1", "RIPE NCC"],
    ["2001:4200::1", "AFRINIC"],
    ["2001:4400::1", "APNIC"],
    ["2001:4600::1", "RIPE NCC"],
    ["2001:4800::1", "ARIN"],
    ["2001:4a00::1", "RIPE NCC"],
    ["2001:4c00::1", "RIPE NCC"],
    ["2001:5000::1", "RIPE NCC"],
    ["2001:8000::1", "APNIC"],
    ["2001:a000::1", "APNIC"],
    ["2001:b000::1", "APNIC"],
    ["2003::1", "RIPE NCC"],
    ["2400::1", "APNIC"],
    ["2410::1", "APNIC — omitted when this table was written from memory"],
    ["2600::1", "ARIN"],
    ["2610::1", "ARIN"],
    ["2620::1", "ARIN"],
    ["2630::1", "ARIN"],
    ["2800::1", "LACNIC"],
    ["2a00::1", "RIPE NCC"],
    ["2a10::1", "RIPE NCC — omitted when this table was written from memory"],
    ["2c00::1", "AFRINIC"],
  ])("allows %s (%s)", (address) => {
    expect(isGloballyRoutable(address)).toBe(true);
  });

  // The two that were missing, at both ends of their /12 rather than just the first address.
  it("allows the whole of the two blocks that were missing", () => {
    expect(isGloballyRoutable("2410:0:0:0:0:0:0:1")).toBe(true);
    expect(isGloballyRoutable("241f:ffff:ffff::1")).toBe(true);
    expect(isGloballyRoutable("2a10::1")).toBe(true);
    expect(isGloballyRoutable("2a1f:ffff:ffff::1")).toBe(true);
    // And the reserved space either side of them stays refused.
    expect(isGloballyRoutable("2420::1")).toBe(false);
    expect(isGloballyRoutable("2a20::1")).toBe(false);
  });
});
