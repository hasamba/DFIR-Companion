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
type Grade = (ip: string) => Ipv6Grade;

export interface Ipv6Span {
  start: number;
  end: number;
  // Hide as an internal address whatever its value grades: the address after a word:: separator (#2976).
  failClosed?: true;
  // A fail-closed span read with the "::" in front before #2979 ("::a00:5" out of "Evtx::a00:5"); a
  // #2976 join was not, and keeps its extent everywhere.
  separated?: true;
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

/** How findIpv6Literals scans; see its doc comment. */
export interface ScanOptions {
  splitUnknown: boolean;
  wholeToken: boolean;
  publicRunsOn?: boolean;
}

interface RetryRules {
  // Only a hit that opens with a four-digit group counts (a "weak" match whose colon run goes on).
  wideOnly: boolean;
  // An internal address found inside need not end the token at all: it fails closed (#2959).
  keepRunsOn: boolean;
  // A "keep" hit that opens with a four-digit group may be followed by a word character, as an
  // unglued "fd00::1xyz" already is: "node12:fd00::1xyz" fails CLOSED too. Never by ":".
  wordAfter: boolean;
  // A public ("weak") hit may be followed by a word character, as the same address at token start
  // already is ("x 2001:db8::1Method"): only after a label ("dc:2001:db8::1Method", #2971; glued to a
  // word, "node12:2001:db8::1Method", #2974), never when the glued match is itself public
  // ("Server2016::Foo", #2959), and only with public masking on.
  publicRunsOn: boolean;
}

function hitEndsWell(text: string, end: number, hit: string, g: Ipv6Grade, rules: RetryRules): boolean {
  const keep = g === "keep";
  if (endsToken(text, end) || (keep && rules.keepRunsOn)) return true;
  if (!WORD_CHAR.test(text.slice(end, end + 1))) return false;
  if (g === "weak" && rules.publicRunsOn) return true;
  return rules.wordAfter && keep && INTERNAL_OPENING.test(hit);
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
    if (accept(g) && hitEndsWell(text, end, hit[0], g, rules)) return { start: p, end };
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
  opts: ScanOptions,
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
  // The ungraded, compressed match whose public hit the caller already accepts when it ends the token
  // (#2971); a full-form one ("dc:20:11:22:33:44:55:66") still never mints a public token.
  // Glued or not (#2974: "node12:2001:db8::1Method"): this outer match is ungraded, never the glued
  // PUBLIC match #2959 leaves alone ("2016::F" out of "Server2016::Foo").
  const publicRunsOn = opts.publicRunsOn === true && unknown && m[0].includes("::");
  return { wideOnly: !glued && !unknown, keepRunsOn: shortUla, wordAfter: !opts.wholeToken, publicRunsOn };
}

// A "::" glued to a word on its left is a separator ("Evtx::2001:db8::1", Velociraptor's
// artifact::field), not part of an address, when the address right after it runs PAST the match and
// the caller would take it. The detector otherwise cut it in two: "::2001:db8" (an IPv4-compatible
// spelling of a public IPv4) and "::1" (loopback) (#2974). Returns where to resume the scan, or null.
function separatorRestart(text: string, m: RegExpExecArray, grade: Grade, opts: ScanOptions): number | null {
  const k = m[0].indexOf("::");
  if (k < 0) return null;
  const at = m.index + k + 2;
  const next = stickyAt(text, at);
  if (!next) return null;
  const end = at + next[0].length;
  if (end <= m.index + m[0].length) return null;
  const g = opts.wholeToken && !endsToken(text, end) ? null : grade(next[0]);
  return g === null ? null : at;
}

// What precedes a "::" separator: a word ("Evtx::a00:5"), or a redacted secret that swallowed the word
// — \uE001 is the anonymizer's secret sentinel (anonymize.ts SECRET_SENTINEL), one way already (#2979).
const SEPARATOR_LEAD = /[\p{L}\p{N}_\uE001]/u;

/** One detector match's outcome: the spans it sets aside, and where the scan resumes. */
interface Step {
  spans: Ipv6Span[];
  resume: number;
}

// "Evtx::a00:5::1" (#2976), "Evtx::a00:5" and "Evtx::7f00:1::5" (#2979): the detector reads "::a00:5"
// (internal 10.0.0.5, IPv4-compatible) glued to the word, so "Evtx::" lost its separator. The address
// after the "::" is set aside instead, as ONE span that fails closed: by its value it may grade as
// nothing ("a00:5", "7f00:1::5"), and it must never be restored in clear.
// - Joined with an internal next match (#2976, after a word): the address read right after the "::"
//   ends exactly where the next match does.
// - Joined otherwise ("Evtx::7f00:1::5", or after a redacted secret): also today's scan of the next
//   match sets aside nothing outside it and resumes at its end, and the join ends at JOIN_END.
// - Alone ("Evtx::a00:5"): the rest of the match, when it has two groups or more. A bare "1"
//   ("Evtx::1") would be learned by screenshot auto-discovery and mask every "1" later.
// `separated` marks the two new shapes: today they were read with the "::" in front ("::a00:5"), and
// the restore and the passes that group what touches an address judge them that way (asDetectorRead).
// Same characters hidden, minus the separator colons, and the scan resumes where it would have. The two
// new shapes never apply to a "::" right after a span set aside ("xfd00::a00:5::1"): that follows an
// address, not a word.
function afterSeparator(text: string, m: RegExpExecArray, grade: Grade, opts: ScanOptions, prevEnd: number) {
  const start = m.index;
  const lead = text[start - 1] ?? "";
  if (!opts.splitUnknown || !SEPARATOR_LEAD.test(lead) || !m[0].startsWith("::")) return null;
  const at = start + 2;
  const end = start + m[0].length;
  const joined = stickyAt(text, at);
  const next = stickyAt(text, end);
  const joinEnd = joined ? at + joined[0].length : -1;
  const join = (span: Ipv6Span) => ({ spans: [span], resume: joinEnd });
  if (next && joinEnd === end + next[0].length) {
    const keepNext = gradeMatch(text, next, grade, opts) === "keep";
    // #2976, unchanged: the extent it has always had.
    if (keepNext && WORD_CHAR.test(lead)) return join({ start: at, end: joinEnd, failClosed: true });
    if (start !== prevEnd && joinsCleanly(text, scanMatch(text, next, grade, opts, end), end, joinEnd))
      return join({ start: at, end: joinEnd, failClosed: true, separated: true });
  }
  if (start === prevEnd || !text.slice(at, end).includes(":")) return null;
  return { spans: [{ start: at, end, failClosed: true as const, separated: true as const }], resume: end };
}

// Whether the next match can join (#2979): today's scan of it resumes at its end and sets aside nothing
// outside it, and the join ends the text or is followed by a space and a letter. A span is a blindfold
// to every later pass: one that ended inside "::10.0.0.5", or before " 1111 1111 1111" of a card
// number or ") 555-0100" of a phone number, would cut the value that pass masks today (or masks after
// a suppressed piece comes back in clear) and leave the rest of it in clear.
const JOIN_END = /^(?:$|\s(?=\p{L}))/u;
function joinsCleanly(text: string, after: Step, end: number, joinEnd: number): boolean {
  if (after.resume !== joinEnd || after.spans.some((s) => s.start < end || s.end > joinEnd)) return false;
  return JOIN_END.test(text.slice(joinEnd, joinEnd + 2));
}

// The grade the main loop gives a match: a whole-token caller rejects one that runs into a word.
function gradeMatch(text: string, m: RegExpExecArray, grade: Grade, opts: ScanOptions): Ipv6Grade {
  return opts.wholeToken && !endsToken(text, m.index + m[0].length) ? null : grade(m[0]);
}

// One detector match, as findIpv6Literals handles it. `prevEnd`: where the last span set aside ends.
function scanMatch(text: string, m: RegExpExecArray, grade: Grade, opts: ScanOptions, prevEnd: number): Step {
  const start = m.index;
  const span = { start, end: start + m[0].length };
  const g = gradeMatch(text, m, grade, opts);
  if (g === "keep")
    return afterSeparator(text, m, grade, opts, prevEnd) ?? { spans: [span], resume: span.end };
  const glued = start > 0 && WORD_CHAR.test(text[start - 1]);
  const rules = retryRules(text, m, g, glued, opts);
  // Glued "weak" match ("2019:fd00::1" out of "win2019:fd00::1"): only a "keep" address wins.
  // A full-form unknown match ("fd:fd00:1:2:3:4:5:6" out of "fd:fd00:1:2:3:4:5:6:7") yields
  // only an internal address, so a fingerprint never mints a public token (#2959).
  const compressed = m[0].includes("::");
  const ok = (x: Ipv6Grade) => x === "keep" || (g === null && (glued || compressed) && x !== null);
  const inner = rules ? retryInside(text, span, ok, grade, rules) : null;
  const restart = glued ? separatorRestart(text, m, grade, opts) : null;
  // An internal address found BEFORE the separator ("fd00::2001:db8" out of "xfd:fd00::2001:db8::1")
  // still wins: it fails closed (#2974 review). One found after it is the restart's to take whole.
  const innerFirst =
    inner &&
    restart !== null &&
    inner.start < restart &&
    grade(text.slice(inner.start, inner.end)) === "keep";
  // The address after the separator starts a token of its own.
  if (restart !== null && !innerFirst) return { spans: [], resume: restart };
  if (inner) return { spans: [inner], resume: inner.end }; // the real address can run past the match
  // "2019::" out of "Win2019:: x", and "2016::F" out of "Server2016::Foo" (#2959), are words.
  const inWord = glued && (m[0].endsWith("::") || /^\p{L}/u.test(text.slice(span.end, span.end + 1)));
  return { spans: g === "weak" && !inWord ? [span] : [], resume: span.end };
}

/**
 * A fail-closed span with its "::" separator in front, as the detector read it before the split
 * (#2979). The passes that join or group what TOUCHES an address — a custom value, a redacted secret —
 * use this, so "x:" or a secret that ran up to the separator still reaches the address it reached.
 */
export function asDetectorRead(span: Pick<Ipv6Span, "start" | "end" | "separated">): {
  start: number;
  end: number;
} {
  return span.separated ? { start: span.start - 2, end: span.end } : { start: span.start, end: span.end };
}

export type SeparatorFlags = Pick<Ipv6Span, "failClosed" | "separated">;

/**
 * Group the spans as the detector read them (asDetectorRead), then give back a fail-closed span that
 * was grouped with nothing at its own extent, separator in clear, with its flags (#2979).
 */
export function groupAsRead<G extends { start: number; end: number; category: unknown }>(
  found: readonly Ipv6Span[],
  group: (read: Array<{ start: number; end: number }>) => G[],
): Array<{ start: number; end: number; category: G["category"]; flags?: SeparatorFlags }> {
  const key = (f: Ipv6Span) => `${asDetectorRead(f).start}:${f.end}`;
  const closed = new Map(found.filter((f) => f.failClosed).map((f) => [key(f), f]));
  return group(found.map(asDetectorRead)).map((g) => {
    const f = g.category === null ? closed.get(`${g.start}:${g.end}`) : undefined;
    if (!f) return { start: g.start, end: g.end, category: g.category };
    const flags: SeparatorFlags = f.separated ? { failClosed: true, separated: true } : { failClosed: true };
    return { start: f.start, end: f.end, category: g.category, flags };
  });
}

/**
 * The original detector pieces behind a fail-closed span (#2979): the match that opened with the "::"
 * separator and, for a joined span, the match after it. The preview's leak hint judges these, as it
 * judged them before the separator was split off.
 */
export function separatorPieces(text: string, span: Ipv6Span): string[] {
  const head = stickyAt(text, span.start - 2);
  if (!head) return [];
  const headEnd = span.start - 2 + head[0].length;
  return headEnd < span.end ? [head[0], text.slice(headEnd, span.end)] : [head[0]];
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
 * `publicRunsOn`: the IP category with public masking on — a public address after a label may run
 * into a word ("dc:2001:db8::1Method", "node12:2001:db8::1Method"), as it already may at token start
 * (#2971, #2974). Off by default.
 */
export function findIpv6Literals(
  text: string,
  grade: (ip: string) => Ipv6Grade,
  opts: ScanOptions,
): Ipv6Span[] {
  const out: Ipv6Span[] = [];
  const re = new RegExp(IPV6_RE.source, "giu"); // local: no lastIndex shared with other callers
  for (let m = re.exec(text); m; m = re.exec(text)) {
    const step = scanMatch(text, m, grade, opts, out.length > 0 ? out[out.length - 1].end : -1);
    out.push(...step.spans);
    re.lastIndex = step.resume;
  }
  return out;
}
