/**
 * The IPv6 detector the anonymizer sets addresses aside with, and the scan that walks it (#2953).
 *
 * IPV6_RE is a DETECTOR, not a validator: the caller grades every match. A match is consumed even
 * when the caller rejects it, so a false match that starts inside a word ("de12:fd00::1" out of
 * "node12:fd00::1") used to swallow the real address after it, and that address went to the AI in
 * clear. findIpv6Literals() retries inside such a match instead of giving up on its text.
 */

// Match full and compressed IPv6 addresses. Handles full (a:b:c:d:e:f:g:h), compressed (::),
// IPv4-mapped (::ffff:x.x.x.x), and a network prefix that ends in "::" (fd00:abcd::).
//
// The two "::ffff:…" (IPv4-mapped) branches are FIRST in the alternation on purpose. JS regex
// alternation is first-match, not longest-match: a generic branch like the bare "::" one further
// down can match a truncated prefix of a mapped address (e.g. just "::ffff:127" out of
// "::ffff:127.0.0.1", stopping at the first "." since "." isn't a hex digit) and the engine never
// backtracks to try the more specific, longer-matching branch below it. Putting the specific
// dotted/hex-group mapped forms first means they get first refusal at a "::ffff:" prefix, so the
// WHOLE address is consumed as one match before IPV4_RE (run second, see anonIps) ever gets
// a chance to tokenize the embedded dotted quad on its own and leave a dangling "::ffff:" behind.
//
// The two terminal-"::" branches are LAST for the same first-match reason: placed earlier they
// would cut "fd00:abcd::1" down to "fd00:abcd::". They need two groups, or one group of three or
// four hex digits, so a code namespace such as "fd::" or "fc::" never reads as an address, and
// they must not be followed by a letter, digit, "_" or ":" ("fd00::Method" is not an address).
export const IPV6_RE =
  /::ffff(?::\d{1,3}){3}|::ffff:\d{1,3}(?:\.\d{1,3}){3}|(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,7}:(?:[0-9a-f]{1,4}:){0,5}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,6}::(?:[0-9a-f]{1,4}:){0,5}[0-9a-f]{1,4}?|(?:[0-9a-f]{1,4}:){1,5}(?::[0-9a-f]{1,4}){1,3}|(?:[0-9a-f]{1,4}:){1,4}(?::[0-9a-f]{1,4}){1,4}|(?:[0-9a-f]{1,4}:){1,3}(?::[0-9a-f]{1,4}){1,5}|(?:[0-9a-f]{1,4}:){1,2}(?::[0-9a-f]{1,4}){1,6}|[0-9a-f]{1,4}:(?::[0-9a-f]{1,4}){1,7}|::(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){2,7}:(?![0-9a-z_:\u0080-￿])|[0-9a-f]{3,4}::(?![0-9a-z_:\u0080-￿])/gi;

/**
 * How the caller judges one detector match.
 * - "keep": take it as it stands, even glued to a word (an internal address fails CLOSED).
 * - "weak": take it, unless it starts inside a word and a "keep" address sits inside it.
 * - null: not an address the caller would hide.
 */
export type Ipv6Grade = "keep" | "weak" | null;

export interface Ipv6Span {
  start: number;
  end: number;
}

// A match that starts right after a letter, digit or "_" may have borrowed its first group from
// that word ("node12:" -> "de12:").
const WORD_CHAR = /[\p{L}\p{N}_]/u;
// A retried address must end the token: retrying must not mint new false positives in code-like
// text ("std::os::fd::AsRawFd") or inside a longer colon-separated byte run (a fingerprint).
const ENDS_TOKEN = /^(?![\p{L}\p{N}_:])/u;

function stickyAt(text: string, at: number): RegExpExecArray | null {
  const re = new RegExp(IPV6_RE.source, "iy");
  re.lastIndex = at;
  return re.exec(text);
}

// Re-run the detector at every group start inside the rejected match, on the FULL text (the real
// address can run past the rejected match's end). The first acceptable one is the longest.
function retryInside(
  text: string,
  m: Ipv6Span,
  accept: (g: Ipv6Grade) => boolean,
  grade: (ip: string) => Ipv6Grade,
): Ipv6Span | null {
  for (let p = m.start + 1; p < m.end; p++) {
    if (text[p - 1] !== ":" || text[p] === ":") continue;
    const hit = stickyAt(text, p);
    if (!hit) continue;
    const end = p + hit[0].length;
    if (ENDS_TOKEN.test(text.slice(end, end + 1)) && accept(grade(hit[0]))) return { start: p, end };
  }
  return null;
}

/**
 * The IPv6 spans to set aside, in text order, never overlapping.
 *
 * `splitUnknown`: also retry inside a rejected match that is not glued to a word but contains
 * "::" — "dc:fd00::1" is a valid literal in unallocated space, and the internal address after the
 * label must fail closed. A custom-range caller passes false: a complete address outside the
 * range ("2001:fd00::1") must never have part of it hidden.
 */
export function findIpv6Literals(
  text: string,
  grade: (ip: string) => Ipv6Grade,
  splitUnknown: boolean,
): Ipv6Span[] {
  const out: Ipv6Span[] = [];
  const re = new RegExp(IPV6_RE.source, "gi"); // local: no lastIndex shared with other callers
  for (let m = re.exec(text); m; m = re.exec(text)) {
    const start = m.index;
    const span = { start, end: start + m[0].length };
    const g = grade(m[0]);
    if (g === "keep") {
      out.push(span);
      continue;
    }
    const glued = start > 0 && WORD_CHAR.test(text[start - 1]);
    if (glued || (splitUnknown && g === null && m[0].includes("::"))) {
      // Glued "weak" match ("2019:fd00::1" out of "win2019:fd00::1"): only a "keep" address wins.
      const inner = retryInside(text, span, (x) => x === "keep" || (g === null && x !== null), grade);
      if (inner) {
        out.push(inner);
        re.lastIndex = inner.end; // the real address can run past the rejected match
        continue;
      }
    }
    if (g === "weak") out.push(span);
  }
  return out;
}
