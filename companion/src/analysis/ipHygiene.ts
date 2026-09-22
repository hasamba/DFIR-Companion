// Address hygiene for the IOC list (#1530): which destination addresses are indicators at all.
//
// Scoring INC-2026-001 put twelve Microsoft, Akamai and CDN addresses in the case IOC list as type
// `ip` with nothing beside them, next to the six real C2 addresses, and the attack graph then
// offered all eighteen as candidate C2. Two of the twelve were not addresses at all: `1.0.0.0`,
// read out of `$script:ModuleVersion = '1.0.0.0'` in a compiled PowerShell module, and
// `0:0:0:0:0:0:0:1`, which is loopback written the long way.
//
// ──────────────────────────── WHAT COUNTS AS "NOT AN INDICATOR" ────────────────────────────
//
// SINGLE-TENANT vendor service space only. An address inside Microsoft's own service edges serves
// Microsoft's own services; nobody can rent a host there, so an address in it cannot be an
// intruder's.
//
// Cloud COMPUTE space is deliberately NOT here — 13.64/11, 20.33/11, 40.74/15 and 172.179/16 are
// Azure ranges where anyone with a credit card can stand up a VM, so a C2 server in them is
// ordinary. Neither is any CDN. Akamai was in the single-tenant tier for one draft, on the argument
// that its customers sign contracts; the code review was right to refuse it (#1530). An edge that
// fronts other people's origins can front a compromised one, and retyping the whole allocation
// would have taken every Akamai-delivered payload out of the IP indicator list, out of enrichment
// and out of a MISP push — for every case, not just the updater rows this fix is about. Akamai and
// Cloudflare are `open-cdn`: the analyst is told whose edge it is, and the address stays a full
// indicator.
//
// So `vendorForIp` answers two different questions with one table, and the caller must respect the
// difference: `tier: "single-tenant"` means the address is not an indicator; `tier: "open-cdn"`
// means the address is an indicator whose owner is worth naming.
//
// PURE — no I/O, no imports above `shared` (publicAddress.ts is shared too).

import { ipv6Groups } from "./publicAddress.js";

export type VendorTier = "single-tenant" | "open-cdn";

export interface VendorRange {
  /** The owner as the analyst should read it. */
  vendor: string;
  /** Whether an address here can be an intruder's. See the header. */
  tier: VendorTier;
  /** Dotted-quad network + prefix length. */
  cidr: string;
}

// Each range is a published vendor block, checked against RDAP rather than copied from a blog.
// Keep the list short and verifiable: a range nobody can point at an RDAP record for does not
// belong here, because every entry lowers what the analyst is shown.
export const VENDOR_RANGES: readonly VendorRange[] = [
  // Microsoft first-party service edges (Microsoft 365, OneDrive, Teams, Bing, update fronts).
  { vendor: "Microsoft", tier: "single-tenant", cidr: "13.107.0.0/16" },
  { vendor: "Microsoft", tier: "single-tenant", cidr: "52.96.0.0/12" },
  { vendor: "Microsoft", tier: "single-tenant", cidr: "52.112.0.0/14" },
  { vendor: "Microsoft", tier: "single-tenant", cidr: "52.120.0.0/14" },
  { vendor: "Microsoft", tier: "single-tenant", cidr: "150.171.0.0/16" },
  { vendor: "Microsoft", tier: "single-tenant", cidr: "204.79.197.0/24" },
  // Akamai edge. Microsoft ships OneDrive and Windows Update content through it, so an updater's
  // connection lands here as often as in Microsoft's own space — but so does a payload from a
  // compromised Akamai-fronted origin. Named, never excused.
  { vendor: "Akamai", tier: "open-cdn", cidr: "23.0.0.0/12" },
  { vendor: "Akamai", tier: "open-cdn", cidr: "23.192.0.0/11" },
  { vendor: "Akamai", tier: "open-cdn", cidr: "2.16.0.0/13" },
  { vendor: "Akamai", tier: "open-cdn", cidr: "96.16.0.0/15" },
  { vendor: "Akamai", tier: "open-cdn", cidr: "104.64.0.0/10" },
  { vendor: "Akamai", tier: "open-cdn", cidr: "184.24.0.0/13" },
  // Cloudflare edge — the same, and its free tier makes it the routine C2 front. See the header.
  { vendor: "Cloudflare", tier: "open-cdn", cidr: "104.16.0.0/13" },
  { vendor: "Cloudflare", tier: "open-cdn", cidr: "172.64.0.0/13" },
  { vendor: "Cloudflare", tier: "open-cdn", cidr: "162.158.0.0/15" },
  { vendor: "Cloudflare", tier: "open-cdn", cidr: "173.245.48.0/20" },
  { vendor: "Cloudflare", tier: "open-cdn", cidr: "103.21.244.0/22" },
  { vendor: "Cloudflare", tier: "open-cdn", cidr: "141.101.64.0/18" },
  { vendor: "Cloudflare", tier: "open-cdn", cidr: "108.162.192.0/18" },
  { vendor: "Cloudflare", tier: "open-cdn", cidr: "190.93.240.0/20" },
  { vendor: "Cloudflare", tier: "open-cdn", cidr: "188.114.96.0/20" },
  { vendor: "Cloudflare", tier: "open-cdn", cidr: "197.234.240.0/22" },
  { vendor: "Cloudflare", tier: "open-cdn", cidr: "198.41.128.0/17" },
  { vendor: "Cloudflare", tier: "open-cdn", cidr: "131.0.72.0/22" },
];

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

/** Dotted quad → its 32-bit value, or null when any octet is not an octet. */
function ipv4ToInt(ip: string): number | null {
  const m = IPV4_RE.exec(ip.trim());
  if (!m) return null;
  let n = 0;
  for (let i = 1; i <= 4; i++) {
    const o = Number(m[i]);
    if (o > 255) return null;
    n = (n << 8) | o;
  }
  return n >>> 0;
}

interface ParsedRange extends VendorRange {
  base: number;
  mask: number;
}

// Parsed once. A malformed entry is dropped rather than throwing at import time — a bad row in the
// table must not take the server down — and the table test asserts every row parses.
const PARSED: ParsedRange[] = VENDOR_RANGES.flatMap((r) => {
  const [net, bitsRaw] = r.cidr.split("/");
  const base = ipv4ToInt(net);
  const bits = Number(bitsRaw);
  if (base === null || !Number.isInteger(bits) || bits < 1 || bits > 32) return [];
  const mask = bits === 32 ? 0xffffffff : (0xffffffff << (32 - bits)) >>> 0;
  return [{ ...r, base: (base & mask) >>> 0, mask }];
});

export interface VendorMatch {
  vendor: string;
  tier: VendorTier;
}

/**
 * The vendor whose published range holds this address, or null. IPv4 only: the case evidence and
 * every published edge range above are v4, and guessing at a v6 block would widen the silence.
 * An IPv4-mapped IPv6 address is read through to its embedded v4.
 */
export function vendorForIp(address: string): VendorMatch | null {
  const v4 = embeddedIpv4(address) ?? address;
  const n = ipv4ToInt(v4);
  if (n === null) return null;
  for (const r of PARSED) if ((n & r.mask) >>> 0 === r.base) return { vendor: r.vendor, tier: r.tier };
  return null;
}

/** True for a vendor range no intruder can be inside — the only tier that changes an IOC's type. */
export function isNonIndicatorVendorIp(address: string): boolean {
  return vendorForIp(address)?.tier === "single-tenant";
}

/** The analyst-facing note an IOC in a vendor range carries. "" when the address is in none. */
export function vendorNote(address: string): string {
  const m = vendorForIp(address);
  if (!m) return "";
  return m.tier === "single-tenant"
    ? `vendor: ${m.vendor} (published service range — not an indicator on its own)`
    : `vendor: ${m.vendor} (shared CDN edge — the edge is not the origin)`;
}

/** The dotted-quad inside an IPv4-mapped or IPv4-compatible IPv6 address, else null. */
function embeddedIpv4(address: string): string | null {
  const groups = ipv6Groups(address.trim().replace(/^\[|\]$/g, ""));
  if (!groups) return null;
  const [g0, g1, g2, g3, g4, g5, g6, g7] = groups;
  const leading = g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0;
  if (!leading || (g5 !== 0xffff && g5 !== 0)) return null;
  if (g5 === 0 && g6 === 0 && g7 <= 1) return null; // :: and ::1 are not addresses of a host
  return [(g6 >> 8) & 0xff, g6 & 0xff, (g7 >> 8) & 0xff, g7 & 0xff].join(".");
}

/**
 * Loopback, the unspecified address, or "-" — in EVERY spelling, read with a parser rather than
 * matched against a list of strings. `0:0:0:0:0:0:0:1` is how Sysmon writes ::1, and the list the
 * importer used to check held only the compressed form, so every WinRM-to-itself row minted an
 * indicator (#1530).
 */
export function isNonIndicatorAddress(address: string): boolean {
  const v = (address ?? "").trim().replace(/^\[|\]$/g, "");
  if (!v || v === "-") return true;
  const n4 = ipv4ToInt(v);
  if (n4 !== null) {
    const first = (n4 >>> 24) & 0xff;
    return first === 127 || n4 === 0; // loopback, 0.0.0.0
  }
  const groups = ipv6Groups(v);
  if (!groups) return false;
  if (groups.every((g) => g === 0)) return true; // ::
  const leading = groups.slice(0, 5).every((g) => g === 0);
  if (leading && groups[5] === 0 && groups[6] === 0 && groups[7] === 1) return true; // ::1
  // ::ffff:127.0.0.1 and ::127.0.0.1 — loopback wearing a v6 spelling.
  const mapped = embeddedIpv4(v);
  return mapped !== null && isNonIndicatorAddress(mapped);
}

// A dotted quad written right after a version marker is a version string, not an address:
// `$script:ModuleVersion = '1.0.0.0'`, `choco install openssh --version 8.0.0.1`. Octet bounds
// cannot tell these apart — every octet is ≤ 255 — so the ~14 characters before the match decide.
// Lives here rather than in one scraper because BOTH free-text scrapers need it: veloTextIocs.ts
// had it and siemImport.ts's textIocs did not, which is how `1.0.0.0` reached the case IOC list
// from a hundred compiled-module script blocks.
const VERSION_PREFIX_RE = /version\s*['"=:\s]*$/;
const VERSION_LOOKBEHIND = 14;

/** Is the dotted quad at `index` in `text` the tail of a version string rather than an address? */
export function looksLikeVersionString(text: string, index: number): boolean {
  const at = Math.max(0, index);
  return VERSION_PREFIX_RE.test(text.slice(Math.max(0, at - VERSION_LOOKBEHIND), at).toLowerCase());
}
