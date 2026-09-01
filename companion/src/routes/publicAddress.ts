// Is this IP address one the public internet routes to? (issue #760)
//
// WHY THIS IS A TABLE AND NOT A CHAIN OF IFs. This classifier was written twice as hand-rolled
// conditions and was wrong both times, in the same way each time: a range nobody happened to think
// of. First 240.0.0.0/4, 198.18.0.0/15, multicast and NAT64; then, once IPv6 was reduced to "top
// three bits are 001", the blocks IANA carves out INSIDE that range — 3fff::/20 documentation
// (RFC 9637, 2024) among them. The lesson is not "think harder", it is that a rule you have to
// re-derive by eye has no edge you can check. So the ranges are DATA, taken from the IANA
// special-purpose address registries, parsed once at load, and matched by one CIDR routine that is
// tested on its boundaries. Adding a range is a line in a list, not a new branch.
//
// THE BIAS IS TOWARDS REFUSING. This decides where a server may open a socket on a caller's say-so.
// Refusing an address that turns out to be reachable costs an operator one clear error message;
// permitting one that turns out to be internal costs them their cloud credentials. So anything not
// recognisably ordinary global unicast is refused, including infrastructure anycast that IANA marks
// globally reachable (AS112, AMT, PCP/TURN). Nothing anyone hosts a threat-intel feed on lives
// there, and the asymmetry is not close.
//
// SEPARATE FROM isInternalTarget() ON PURPOSE. That function answers "is this one of the ranges we
// call internal", which is the right question for enrichment and IOC display, and it stays the
// first check the guard runs on a URL literal because its wording gives the operator a better
// message. This answers a different and stricter question, so it gets its own table rather than
// bending that one.

interface Cidr {
  bytes: number[];
  bits: number;
}

/** Dotted-quad to 4 bytes. Null for anything that is not exactly that. */
export function ipv4ToBytes(ip: string): number[] | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip.trim());
  if (!m) return null;
  const bytes = m.slice(1, 5).map(Number);
  if (bytes.some((n) => n > 255)) return null;
  return bytes;
}

/**
 * IPv6 text to 16 bytes, including the trailing dotted-quad forms (::ffff:1.2.3.4). Null for
 * anything that does not parse — a zone index, a truncated address, junk — because the caller's
 * only safe response to "I could not read this" is to refuse it.
 */
export function ipv6ToBytes(ip: string): number[] | null {
  const text = ip.trim();
  if (!text || text.includes("%")) return null; // zone index: refuse rather than guess
  const halves = text.split("::");
  if (halves.length > 2) return null;

  // `endsAddress` is what makes the dotted-quad rule correct. Checking only "last piece of this
  // half" accepts 1.2.3.4::1, where the quad is last in the HEAD but not last in the address.
  const parsePart = (part: string, endsAddress: boolean): number[] | null => {
    if (!part) return [];
    const out: number[] = [];
    const pieces = part.split(":");
    for (let i = 0; i < pieces.length; i += 1) {
      const piece = pieces[i];
      if (piece.includes(".")) {
        if (!endsAddress || i !== pieces.length - 1) return null; // only ever the final group
        const v4 = ipv4ToBytes(piece);
        if (!v4) return null;
        out.push(...v4);
        continue;
      }
      if (!/^[0-9a-f]{1,4}$/i.test(piece)) return null;
      const value = Number.parseInt(piece, 16);
      out.push((value >> 8) & 0xff, value & 0xff);
    }
    return out;
  };

  const head = parsePart(halves[0], halves.length === 1);
  if (head === null) return null;
  if (halves.length === 1) return head.length === 16 ? head : null;
  const tail = parsePart(halves[1], true);
  if (tail === null) return null;
  const fill = 16 - head.length - tail.length;
  if (fill < 0) return null;
  return [...head, ...(new Array(fill).fill(0) as number[]), ...tail];
}

function parseCidr(cidr: string): Cidr {
  const [addr, len] = cidr.split("/");
  const bytes = addr.includes(":") ? ipv6ToBytes(addr) : ipv4ToBytes(addr);
  const bits = Number(len);
  // A typo in the tables below is a hole in the guard. Fail at load, not silently at request time.
  if (!bytes || !Number.isInteger(bits) || bits < 0 || bits > bytes.length * 8) {
    throw new Error(`outbound address guard: malformed CIDR "${cidr}"`);
  }
  return { bytes, bits };
}

function inCidr(bytes: number[], net: Cidr): boolean {
  if (bytes.length !== net.bytes.length) return false;
  const whole = net.bits >> 3;
  for (let i = 0; i < whole; i += 1) if (bytes[i] !== net.bytes[i]) return false;
  const rest = net.bits & 7;
  if (rest === 0) return true;
  const mask = (0xff << (8 - rest)) & 0xff;
  return (bytes[whole] & mask) === (net.bytes[whole] & mask);
}

// IANA IPv4 Special-Purpose Address Registry, plus multicast and the reserved top of the space.
const NON_GLOBAL_IPV4 = [
  "0.0.0.0/8", // this network
  "10.0.0.0/8", // private
  "100.64.0.0/10", // CGNAT
  "127.0.0.0/8", // loopback
  "169.254.0.0/16", // link-local — the cloud metadata service
  "172.16.0.0/12", // private
  "192.0.0.0/24", // IETF protocol assignments
  "192.0.2.0/24", // TEST-NET-1
  "192.31.196.0/24", // AS112-v4
  "192.52.193.0/24", // AMT
  "192.88.99.0/24", // 6to4 relay anycast (deprecated)
  "192.168.0.0/16", // private
  "192.175.48.0/24", // AS112 direct delegation
  "198.18.0.0/15", // benchmarking
  "198.51.100.0/24", // TEST-NET-2
  "203.0.113.0/24", // TEST-NET-3
  "224.0.0.0/4", // multicast
  "240.0.0.0/4", // reserved, and 255.255.255.255 broadcast with it
].map(parseCidr);

// IPv6 IS AN ALLOWLIST OF WHAT IANA HAS ACTUALLY DELEGATED — not "2000::/3 minus exceptions".
//
// 2000::/3 is the ARCHITECTURAL definition of global unicast, and using it as the permitted range
// was the mistake behind three separate rounds of this: most of 2000::/3 has never been delegated
// to anyone. 3000::/4, 2e00::/7, 2d00::/8 and the returned 6bone space 3ffe::/16 are all IANA
// reserved, all inside 2000::/3, and all were permitted. Naming each one as it was noticed is the
// losing game — the list of things nobody has thought of yet is not enumerable.
//
// So the question is inverted one final time: an address is permitted only if it falls inside a
// block IANA has delegated to an RIR. Unallocated space is refused because it is not in the list,
// which is the same reason a range invented tomorrow is refused. These blocks are large and change
// on a timescale of years; if IANA delegates a new one, this table gets a line and the failure in
// the meantime is a clear refusal rather than a silent hole.
//
// TRANSCRIBED FROM THE REGISTRY, NOT FROM MEMORY. Every RIR-delegated row of
// https://www.iana.org/assignments/ipv6-unicast-address-assignments/ — the IANA, 6to4 and
// Documentation rows are the ones deliberately left out. Writing this list from recall dropped
// 2410::/12 and 2a10::/12, which would have refused APNIC and RIPE customers outright, so re-check
// it against that page rather than reasoning about which blocks "look right" when updating.
const DELEGATED_IPV6 = [
  "2001:200::/23", // APNIC
  "2001:400::/23", // ARIN
  "2001:600::/23", // RIPE NCC
  "2001:800::/22", // RIPE NCC
  "2001:c00::/23", // APNIC
  "2001:e00::/23", // APNIC
  "2001:1200::/23", // LACNIC
  "2001:1400::/22", // RIPE NCC
  "2001:1800::/23", // ARIN
  "2001:1a00::/23", // RIPE NCC
  "2001:1c00::/22", // RIPE NCC
  "2001:2000::/19", // RIPE NCC
  "2001:4000::/23", // RIPE NCC
  "2001:4200::/23", // AFRINIC
  "2001:4400::/23", // APNIC
  "2001:4600::/23", // RIPE NCC
  "2001:4800::/23", // ARIN
  "2001:4a00::/23", // RIPE NCC
  "2001:4c00::/23", // RIPE NCC
  "2001:5000::/20", // RIPE NCC
  "2001:8000::/19", // APNIC
  "2001:a000::/20", // APNIC
  "2001:b000::/20", // APNIC
  "2003::/18", // RIPE NCC
  "2400::/12", // APNIC
  "2410::/12", // APNIC
  "2600::/12", // ARIN
  "2610::/23", // ARIN
  "2620::/23", // ARIN
  "2630::/12", // ARIN
  "2800::/12", // LACNIC
  "2a00::/12", // RIPE NCC
  "2a10::/12", // RIPE NCC
  "2c00::/12", // AFRINIC
].map(parseCidr);

// Special-purpose blocks that sit INSIDE a delegated range, so the allowlist alone would admit
// them. Everything else in the IPv6 special-purpose registry — ::1, fc00::/7, fe80::/10, ff00::/8,
// NAT64, Teredo, ORCHID, 3fff::/20, 5f00::/16, 2002::/16 6to4 — is outside every delegated block
// and is refused by not being in the list at all. 6to4 in particular no longer needs unwrapping:
// it is deprecated (RFC 7526) and simply not delegated space.
const RESERVED_WITHIN_DELEGATED_IPV6 = [
  "2001:db8::/32", // documentation (RFC 3849) — sits inside APNIC's 2001:0c00::/23
  "2620:4f:8000::/48", // AS112 direct delegation — sits inside ARIN's 2620::/23
].map(parseCidr);

/**
 * True only for an address the public internet routes to. Everything else — private, reserved,
 * unallocated, loopback, link-local, multicast, documentation, or unparseable — is false.
 */
export function isGloballyRoutable(address: string): boolean {
  const value = address.trim().replace(/^\[|\]$/g, "");
  if (!value) return false;

  if (!value.includes(":")) {
    const bytes = ipv4ToBytes(value);
    if (!bytes) return false;
    return !NON_GLOBAL_IPV4.some((net) => inCidr(bytes, net));
  }

  const bytes = ipv6ToBytes(value);
  if (!bytes) return false;
  if (!DELEGATED_IPV6.some((net) => inCidr(bytes, net))) return false;
  return !RESERVED_WITHIN_DELEGATED_IPV6.some((net) => inCidr(bytes, net));
}
