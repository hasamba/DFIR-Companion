import { embeddedIpv4, expandIpv6Groups } from "./iocValue.js";

// Cloud-metadata and link-local targets (issue #2146).
//
// Outbound channels the admin configures (notification webhooks, the SMTP host, and — #2147 —
// audit-export destinations) may legitimately point at the LAN or at this machine: a self-hosted
// Mattermost, a local syslog forwarder. What they must never reach is the cloud instance-metadata
// service, because on a cloud-hosted companion that answers with the instance's credentials, and
// link-local space generally, which no chat server or collector lives on.
//
// This is the SYNCHRONOUS half of the rule: a classification of a host string, with no DNS. It is
// what the save-time parsers in analysis/ can call (they are synchronous, and the domain layer may
// not import the delivery-layer guard). The send-time half — resolve, check every address with this
// same predicate, pin the connection to the checked address — lives in
// routes/outboundTargetPolicy.ts. Both halves use this one predicate so they cannot drift.
//
// Why a list and not a range: two well-known metadata addresses sit INSIDE space that is otherwise
// fine to reach. AWS's IPv6 IMDS (fd00:ec2::254) is in unique-local fc00::/7, and Alibaba's
// 100.100.100.200 is in CGNAT 100.64.0.0/10. A "private is fine" rule lets both through, so they
// are named explicitly.

/** Metadata service hostnames. Compared after lower-casing and dropping a trailing dot. */
const METADATA_HOSTNAMES = new Set([
  "metadata", // GCP short name, resolvable from inside a GCE VM
  "metadata.google.internal",
  "metadata.goog",
  "instance-data", // AWS alias for 169.254.169.254
  "instance-data.ec2.internal",
  "metadata.tencentyun.com",
]);

/** Metadata addresses outside link-local space. */
const METADATA_IPV4 = new Set(["100.100.100.200"]);
/** fd00:ec2::254 — AWS IMDS over IPv6 — as expanded groups. */
const AWS_IMDS_V6 = [0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254];

const DOTTED_IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;
// Anything the WHATWG URL parser might read as an IPv4 number: decimal, octal, hex, short forms.
const NUMERIC_HOST = /^(?:0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+)){0,3}$/i;

function isBlockedIpv4(ip: string): boolean {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return false;
  if (parts[0] === 169 && parts[1] === 254) return true; // 169.254.0.0/16 link-local
  return METADATA_IPV4.has(ip);
}

/** Canonical dotted IPv4 for any spelling the URL parser accepts (2852039166, 0xa9fea9fe, octal). */
function canonicalIpv4(host: string): string | null {
  // Always through the URL parser, never Number(): "0251.0376.0251.0376" is octal to the parser
  // (and to inet_aton, which a socket connect uses), so a decimal read would misclassify it.
  if (!NUMERIC_HOST.test(host)) return null;
  try {
    const parsed = new URL(`http://${host}/`).hostname;
    return DOTTED_IPV4.test(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

/** Canonical hex IPv6 (the URL parser folds a dotted tail into hex), or null when not IPv6. */
function canonicalIpv6(host: string): string | null {
  if (!host.includes(":")) return null;
  const withoutZone = host.replace(/%.*$/, "");
  try {
    return new URL(`http://[${withoutZone}]/`).hostname.replace(/^\[|\]$/g, "");
  } catch {
    return null;
  }
}

function isBlockedIpv6(ip: string): boolean {
  const groups = expandIpv6Groups(ip);
  if (!groups) return false;
  if ((groups[0] & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
  if (groups.every((g, i) => g === AWS_IMDS_V6[i])) return true;
  const embedded = embeddedIpv4(ip);
  if (embedded && isBlockedIpv4(embedded)) return true;
  // NAT64 well-known prefix 64:ff9b::/96 carries an IPv4 address in its last 32 bits.
  const isNat64 = groups[0] === 0x64 && groups[1] === 0xff9b && groups.slice(2, 6).every((g) => g === 0);
  if (isNat64) {
    const v4 = [groups[6] >> 8, groups[6] & 0xff, groups[7] >> 8, groups[7] & 0xff].join(".");
    return isBlockedIpv4(v4);
  }
  return false;
}

/**
 * True when `host` — an IP literal in any common spelling (bracketed or not, IPv4-mapped,
 * decimal/hex/octal IPv4) or a hostname — is a cloud-metadata or link-local target. Hostnames are
 * matched against the known metadata names only; whatever a name RESOLVES to is the send-time
 * check's job.
 */
export function isMetadataOrLinkLocalHost(rawHost: string): boolean {
  const host = rawHost
    .trim()
    .replace(/^\[|\]$/g, "")
    .replace(/\.+$/, "")
    .toLowerCase();
  if (!host) return false;
  const v6 = canonicalIpv6(host);
  if (v6 !== null) return isBlockedIpv6(v6);
  const v4 = canonicalIpv4(host);
  if (v4 !== null) return isBlockedIpv4(v4);
  return METADATA_HOSTNAMES.has(host);
}

/** The host of `url` is a cloud-metadata or link-local target. False for an unparsable URL. */
export function urlHostIsMetadataOrLinkLocal(url: string): boolean {
  try {
    return isMetadataOrLinkLocalHost(new URL(url).hostname);
  } catch {
    return false;
  }
}

/** The plain-language refusal an admin sees. Names only what they typed. */
export function metadataTargetError(host: string): string {
  return `the address "${host}" is blocked because it is a cloud-metadata or link-local address`;
}
