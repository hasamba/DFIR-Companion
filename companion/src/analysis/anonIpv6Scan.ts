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
// they must not be followed by a letter or digit in any script, "_" or ":" ("fd00::Method" is
// not an address; a closing quote, a no-break space or a direction mark after one is fine). One
// closing colon is fine too (#2969): ":::" before a space, punctuation or the end reads as "::" plus
// a colon that closes the phrase ("route fe80::: down"); before a word character or another ":" it
// is still not an address.
export const IPV6_RE =
  /::ffff(?::\d{1,3}){3}|::ffff:\d{1,3}(?:\.\d{1,3}){3}|(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,7}:(?:[0-9a-f]{1,4}:){0,5}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,6}::(?:[0-9a-f]{1,4}:){0,5}[0-9a-f]{1,4}?|(?:[0-9a-f]{1,4}:){1,5}(?::[0-9a-f]{1,4}){1,3}|(?:[0-9a-f]{1,4}:){1,4}(?::[0-9a-f]{1,4}){1,4}|(?:[0-9a-f]{1,4}:){1,3}(?::[0-9a-f]{1,4}){1,5}|(?:[0-9a-f]{1,4}:){1,2}(?::[0-9a-f]{1,4}){1,6}|[0-9a-f]{1,4}:(?::[0-9a-f]{1,4}){1,7}|::(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){2,7}:(?![\p{L}\p{N}_]|:[\p{L}\p{N}_:])|[0-9a-f]{3,4}::(?![\p{L}\p{N}_]|:[\p{L}\p{N}_:])/giu;

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
  const re = new RegExp(IPV6_RE.source, "iuy");
  re.lastIndex = at;
  return re.exec(text);
}

// One colon that closes a phrase ("peer fd00::1: reset"): followed by a space, punctuation or the
// end, never by another ":" or a word character, so a colon run that goes on is not one (#2968).
const CLOSING_COLON = /^:(?![\p{L}\p{N}_:])/u;
const closingColonAt = (text: string, end: number) => CLOSING_COLON.test(text.slice(end, end + 2));

const endsToken = (text: string, end: number) =>
  ENDS_TOKEN.test(text.slice(end, end + 1)) || closingColonAt(text, end);

// A real unique-local (fc00::/7) or link-local (fe80::/10) address opens with a FOUR-digit group;
// a fingerprint or MAC byte run has two-digit groups, a code namespace like "fd::" too (#2956).
const WIDE_START = /^[0-9a-f]{4}:/i;
// A retried "keep" hit that may run into a word: a four-digit opening group, or a "::" opening
// ("node12:::1xyz", "node12:::ffff:10.0.0.5xyz") — the caller graded it internal (#2965).
const INTERNAL_OPENING = /^(?:[0-9a-f]{4}:|::)/i;
// The short first groups the old loose unique-local / link-local checks graded internal (#2959, #2966).
const SHORT_INTERNAL_LEAD = /^(?:f[cd][0-9a-f]?|fe[89ab]):/i;

interface RetryRules {
  // Only a hit that opens with a four-digit group counts (a "weak" match whose colon run goes on).
  wideOnly: boolean;
  // An internal address found inside need not end the token at all: it fails closed (#2959).
  keepRunsOn: boolean;
  // A "keep" hit that opens with a four-digit group may be followed by a word character, as an
  // unglued "fd00::1xyz" already is: "node12:fd00::1xyz" fails CLOSED too. Never by ":".
  wordAfter: boolean;
}

function hitEndsWell(text: string, end: number, hit: string, keep: boolean, rules: RetryRules): boolean {
  if (endsToken(text, end) || (keep && rules.keepRunsOn)) return true;
  return rules.wordAfter && keep && INTERNAL_OPENING.test(hit) && WORD_CHAR.test(text.slice(end, end + 1));
}

// Re-run the detector at every group start inside the rejected match, on the FULL text (the real
// address can run past the rejected match's end). The first acceptable one is the longest.
function retryInside(
  text: string,
  m: Ipv6Span,
  accept: (g: Ipv6Grade) => boolean,
  grade: (ip: string) => Ipv6Grade,
  rules: RetryRules,
): Ipv6Span | null {
  for (let p = m.start + 1; p < m.end; p++) {
    if (text[p - 1] !== ":") continue; // a group start, or the "::" of "node12:::1"
    const hit = stickyAt(text, p);
    if (!hit || (rules.wideOnly && !WIDE_START.test(hit[0]))) continue;
    const end = p + hit[0].length;
    const g = grade(hit[0]);
    if (accept(g) && hitEndsWell(text, end, hit[0], g === "keep", rules)) return { start: p, end };
  }
  return null;
}

// Why a rejected match is worth retrying, or null: it is glued to a word, or it is not an address
// the caller would hide (#2959's full-form retry covers "dc:fd00:1:2:3:4:5:6:7"), or its colon run
// goes on past it. Nine or more groups are never one address, so a "weak" first eight
// ("2019:fd00:1:2:3:4:5:6" out of "2019:fd00:1:2:3:4:5:6:7") is retried too, for a four-digit-opening
// internal address only (#2956). A custom-range caller retries a match that opens with a short
// group ("dc:fd00::1") or whose colon run goes on, for a four-digit-opening in-range address only:
// neither can be the front of a real address, which the range path must never split (#2965).
function retryRules(
  text: string,
  m: RegExpExecArray,
  g: Ipv6Grade,
  glued: boolean,
  opts: { splitUnknown: boolean; wholeToken: boolean },
): RetryRules | null {
  const unknown = opts.splitUnknown && g === null;
  // A range caller's grade is "keep" or null, never "weak", so a null run that goes on qualifies.
  // A closing colon does not go on: "2001:fd00::1: x" is one complete address (#2968).
  const end = m.index + m[0].length;
  const runGoesOn = text[end] === ":" && !closingColonAt(text, end);
  const shortLead = !opts.splitUnknown && g === null && !WIDE_START.test(m[0]);
  if (!glued && !unknown && !runGoesOn && !shortLead) return null;
  // A match that opens with a 2-3 digit "fd"/"fc" group was hidden whole before #2959, and one that
  // opens with a 3-digit "fe8"-"feb" group before #2966; an internal address inside it
  // ("fd:fd00::1Method", "fe8:fe80::1:x") must stay hidden even where it runs into a word.
  // The range path's unglued retry (#2965) is new and keeps its whole-token rule.
  const shortUla = g === null && SHORT_INTERNAL_LEAD.test(m[0]) && (glued || opts.splitUnknown);
  return { wideOnly: !glued && !unknown, keepRunsOn: shortUla, wordAfter: !opts.wholeToken };
}

/**
 * The IPv6 spans to set aside, in text order, never overlapping.
 *
 * `splitUnknown`: also retry inside a rejected match that is not glued to a word — "dc:fd00::1" is
 * a valid literal in unallocated space, and the internal address after the label must fail closed;
 * likewise a "weak" eight-group match whose colon run goes on ("2019:fd00:1:2:3:4:5:6:7"), for a
 * four-digit-opening internal address only. A custom-range caller passes false: a complete
 * address outside the range ("2001:fd00::1") must never have part of it hidden. It still retries a
 * short-opening or run-on match ("dc:fd00::1", "2019:fd00:1:2:3:4:5:6:7"), which no real address
 * can be the front of (#2965).
 * `wholeToken`: a match that does not end the token ("fd00::beef" out of "fd00::beefMethod") is
 * rejected. The IP category passes false so an internal address keeps failing CLOSED.
 */
export function findIpv6Literals(
  text: string,
  grade: (ip: string) => Ipv6Grade,
  opts: { splitUnknown: boolean; wholeToken: boolean },
): Ipv6Span[] {
  const out: Ipv6Span[] = [];
  const re = new RegExp(IPV6_RE.source, "giu"); // local: no lastIndex shared with other callers
  for (let m = re.exec(text); m; m = re.exec(text)) {
    const start = m.index;
    const span = { start, end: start + m[0].length };
    const g = opts.wholeToken && !endsToken(text, span.end) ? null : grade(m[0]);
    if (g === "keep") {
      out.push(span);
      continue;
    }
    const glued = start > 0 && WORD_CHAR.test(text[start - 1]);
    const rules = retryRules(text, m, g, glued, opts);
    if (rules) {
      // Glued "weak" match ("2019:fd00::1" out of "win2019:fd00::1"): only a "keep" address wins.
      // A full-form unknown match ("fd:fd00:1:2:3:4:5:6" out of "fd:fd00:1:2:3:4:5:6:7") yields
      // only an internal address, so a fingerprint never mints a public token (#2959).
      const compressed = m[0].includes("::");
      const ok = (x: Ipv6Grade) => x === "keep" || (g === null && (glued || compressed) && x !== null);
      const inner = retryInside(text, span, ok, grade, rules);
      if (inner) {
        out.push(inner);
        re.lastIndex = inner.end; // the real address can run past the rejected match
        continue;
      }
    }
    // "2019::" out of "Win2019:: x", and "2016::F" out of "Server2016::Foo" (#2959), are words.
    const inWord = glued && (m[0].endsWith("::") || /^\p{L}/u.test(text.slice(span.end, span.end + 1)));
    if (g === "weak" && !inWord) out.push(span);
  }
  return out;
}
