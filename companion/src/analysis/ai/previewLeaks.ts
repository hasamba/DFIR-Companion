import { isIPv6 } from "node:net";
import {
  isInternalIp,
  isInternalIpv6,
  isMaskableIpv4,
  isMaskableIpv6,
  type AnonPolicy,
} from "../anonymize.js";

/**
 * "Possible leak" marks for the AI preview's masked pane (#2531): text that LOOKS LIKE an IP address,
 * an email address, a domain or a host name and was sent as it is. These are guesses from the text's
 * shape — the dialog words them that way ("looks like … — not masked") — never a claim that the
 * value is sensitive. Scans the masked text only, outside every token; linear in the text.
 */
export type LooksLike = "ip" | "email" | "domain" | "host";

export interface PreviewWarning {
  /** [start, end) in the masked text. */
  readonly m: readonly [number, number];
  readonly looksLike: LooksLike;
}

const TOKEN_SHAPE = /ANON_[A-Z]+_\d+|\[REDACTED_SECRET\]/g;
const IPV4 = /(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\.?\d)/g;
const IPV6 = /(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}(?:[0-9A-Fa-f]{1,4}|(?:\d{1,3}\.){3}\d{1,3})?(?![\w:])/g;
const EMAIL = /(?<![\w.%+-])[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}(?![\w-])/g;
const DOMAIN =
  /(?<![\w.@\\-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+([A-Za-z]{2,24})(?![\w-]|\.[A-Za-z0-9])/g;
const HOST = /(?<![\w.\\-])([A-Z][A-Z0-9]*)(?:-[A-Z0-9]+)+(?![\w.-])/g;

// Common generic and private-namespace TLDs. Two-letter country codes count too (minus file types).
const TLDS = new Set(
  (
    "com net org edu gov mil int info biz io co app dev cloud online site xyz top club tech store live me " +
    "tv cc ws name pro mobi asia tel travel jobs local localdomain internal intranet corp lan home arpa " +
    "onion test example invalid"
  ).split(" "),
);
// File types that would otherwise read as a TLD (cmd.exe, notes.md, run.sh …).
const FILE_TYPES = new Set(
  (
    "exe dll sys ps psm psd bat cmd vbs js ts py sh rb pl md cs vb db gz xz bz so ko go rs hs ml txt log " +
    "json xml csv tsv evtx etl lnk pf dat tmp ini cfg conf yaml yml zip rar tar msi png jpg jpeg gif bmp " +
    "pdf doc docx xls xlsx ppt pptx htm html php asp aspx jsp css hta jar class reg bak old db3 sqlite " +
    "plist ds ad"
  ).split(" "),
);
// First parts that make an ALL-CAPS hyphenated word an identifier, not a host (CVE-2021-1, SHA-256 …).
const NOT_HOST =
  /^(?:CVE|CWE|GHSA|CAPEC|UTF|SHA\d*|MD\d|AES|RC\d|DES|ISO|RFC|TLS|SSL|HTTPS?|KB\d*|MS\d*|TA\d*|T\d+|S|X|X\d+|IEC|PKCS|RSA|ECDSA|ECDH|DH|NTLM|APT\d*|ID|PID|TID|UID|GID|EID|EVT|IPV\d|V\d+)$/;

function ipLeak(ip: string, policy: Pick<AnonPolicy, "maskPublicIps">): boolean {
  if (ip === "0.0.0.0" || ip === "255.255.255.255" || ip.startsWith("127.")) return false;
  return isInternalIp(ip) || (policy.maskPublicIps && isMaskableIpv4(ip));
}

function ipv6Leak(ip: string, policy: Pick<AnonPolicy, "maskPublicIps">): boolean {
  if (!/[0-9a-f]/i.test(ip) || !isIPv6(ip) || ip === "::1") return false;
  return isInternalIpv6(ip) || (policy.maskPublicIps && isMaskableIpv6(ip));
}

function domainLeak(tld: string): boolean {
  const t = tld.toLowerCase();
  if (FILE_TYPES.has(t)) return false;
  return t.length === 2 || TLDS.has(t);
}

function hostLeak(word: string, first: string): boolean {
  return word.length <= 15 && /\d/.test(word) && !NOT_HOST.test(first);
}

interface Candidate extends PreviewWarning {
  readonly rank: number;
}

function collect(masked: string, policy: Pick<AnonPolicy, "maskPublicIps">): Candidate[] {
  const out: Candidate[] = [];
  const add = (re: RegExp, looksLike: LooksLike, rank: number, keep: (hit: RegExpExecArray) => boolean) => {
    for (const hit of masked.matchAll(re))
      if (keep(hit)) out.push({ m: [hit.index, hit.index + hit[0].length], looksLike, rank });
  };
  add(EMAIL, "email", 0, () => true);
  add(IPV6, "ip", 1, (h) => ipv6Leak(h[0], policy));
  add(IPV4, "ip", 1, (h) => ipLeak(h[0], policy));
  add(DOMAIN, "domain", 2, (h) => domainLeak(h[1]));
  add(HOST, "host", 3, (h) => hostLeak(h[0], h[1]));
  return out;
}

/** Possible leaks in the masked text, in text order, never overlapping each other or a token. */
export function possibleLeaks(masked: string, policy: Pick<AnonPolicy, "maskPublicIps">): PreviewWarning[] {
  const tokens = [...masked.matchAll(TOKEN_SHAPE)].map((t) => [t.index, t.index + t[0].length] as const);
  // Earliest first; at the same start, the stronger shape (email > IP > domain > host), then longer.
  const candidates = collect(masked, policy).sort(
    (a, b) => a.m[0] - b.m[0] || a.rank - b.rank || b.m[1] - a.m[1],
  );
  const out: PreviewWarning[] = [];
  let lastEnd = 0;
  let t = 0;
  for (const c of candidates) {
    if (c.m[0] < lastEnd) continue;
    while (t < tokens.length && tokens[t][1] <= c.m[0]) t++;
    if (t < tokens.length && tokens[t][0] < c.m[1]) continue; // touches a token
    out.push({ m: c.m, looksLike: c.looksLike });
    lastEnd = c.m[1];
  }
  return out;
}
