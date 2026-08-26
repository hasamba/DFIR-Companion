// Network addresses named in a free-text log message, for aggregation fingerprinting (#640).
//
// WHY THIS EXISTS. msgFingerprint normalises a message before folding it into an aggregation key
// and strips every digit, so repeats differing only in a PID, port or record id collapse into one
// counted event. An IP address is also made of digits, so the strip erases it too — right for a
// PID, wrong for a peer address. For a network event the OTHER END IS THE EVENT: two connections
// to different destinations are two events, not one repeat. Rows differing only in TgtIP used to
// fingerprint identically, merge into one event holding the FIRST row's text, and leave every IOC
// scraped from the merged rows pointing at an event naming a different address. Domains and URLs
// are mostly letters and already survive the strip; only addresses need rescuing.
//
// A CANDIDATE IS BOUNDED by "not a letter, number or mark, in any script". Three details are
// load-bearing, and each was got wrong once:
//
//   - Not \b. A word boundary cannot anchor a match that begins or ends at "::" beside a numeric
//     group, so "::1" and "1::" were never extracted at all (#643).
//   - Marks count as identifier text. macOS stores filenames decomposed, so "café::1234" collected
//     from a Mac ends in a combining mark rather than a letter (#649).
//   - A ":" is NOT excluded, though excluding it looks right — it would stop a match starting
//     midway through an address. The greedy quantifier already prefers the whole address, and
//     excluding the colon instead made a label colon suppress the address behind it, so
//     "srcip:fe80::1" with no space yielded nothing.
//
// CONNECTOR PUNCTUATION IS A CHOSEN TRADE, not a derivation — do not "fix" it without reading
// this. "_" is U+005F, category Pc, and so are "＿" and "‿". A bound strict enough to reject
// "worker_::1234" also rejects "conn_::1", and nothing separates them: both are an identifier, a
// connector and a valid IPv6 literal, and "::1" is loopback. Splitting on token shape was tried
// and rescues only the hex-leading half. So connectors separate, and "worker_::1234" yields a
// token this module knows is not an address, because the two failures are not equal:
//
//   suppressing an address  merges two different destinations — the #640 defect, and a
//                           report-integrity failure the analyst cannot see.
//   inventing a token       leaves two identical records unmerged — timeline noise they can.
//
// Never suppress. Where the two directions meet, prefer the one that yields MORE tokens. Tests pin
// both halves, including the invented token, so the cost reads as accepted rather than missed.
//
// THE TOKEN IS THEN PARSED, not counted. "At least three colons" reads like a fair proxy and is
// not one: every four-field duration, timecode and uptime counter clears it, and those are
// volatile, so admitting one splits records that must merge. A MAC fallback was tried and removed
// for the same reason one level down — "00:00:5e:00:53:01" and "26:08:26:10:38:00" are the same
// shape. Parsing makes the whole class of colon look-alikes impossible instead of handling them
// one at a time.
//
// A lone leading or trailing colon is trimmed first: it is the label separator, not part of the
// address, and without the trim `"remote":fe80::1` and `"remote":"fe80::1"` yield two different
// tokens for one destination. "::1" and "1::" keep theirs — only a colon with no colon beside it
// goes.
//
// The leading bound CONSUMES a character rather than using a lookbehind, which measured 2.3x
// slower over a real collection's messages. Addresses are separated by spaces or field marks in
// this telemetry, so consuming one leading character never swallows a neighbouring one.
const IPV4_RE = /\b\d{1,3}(?:\.\d{1,3}){3}\b/g;
const COLON_ADDR_RE =
  /(?:^|[^\p{L}\p{N}\p{M}])((?:[0-9a-f]{1,4})?(?::{1,2}[0-9a-f]{0,4}){2,7})(?![\p{L}\p{N}\p{M}:])/giu;
const HAS_HEX_RE = /[0-9a-f]/i;
const LONE_LEADING_COLON_RE = /^:(?!:)/;
const LONE_TRAILING_COLON_RE = /(?<!:):$/;
const IPV6_GROUP_RE = /^[0-9a-f]{1,4}$/;

/**
 * Is `t` a real IPv6 literal? At most one "::"; every group 1-4 hex digits; exactly eight groups
 * when there is no "::", and at most seven when there is, since the "::" stands for the rest.
 */
function isIpv6(t: string): boolean {
  const halves = t.split("::");
  if (halves.length > 2) return false;
  const groups = (half: string): string[] => (half === "" ? [] : half.split(":"));
  if (halves.length === 1) {
    const g = groups(halves[0]);
    return g.length === 8 && g.every((x) => IPV6_GROUP_RE.test(x));
  }
  const left = groups(halves[0]);
  const right = groups(halves[1]);
  return left.length + right.length <= 7 && [...left, ...right].every((x) => IPV6_GROUP_RE.test(x));
}

/**
 * Every network address named in `msg`, lower-cased and de-duplicated.
 *
 * Sorted, so a fingerprint built from the result does not depend on the order the addresses happen
 * to appear in. Pure.
 */
export function networkTokens(msg: string): string[] {
  const out = new Set<string>();
  for (const m of msg.match(IPV4_RE) ?? []) {
    if (m.split(".").every((o) => Number(o) <= 255)) out.add(m.toLowerCase());
  }
  for (const match of msg.matchAll(COLON_ADDR_RE)) {
    const raw = match[1]; // group 1 — the address without the character the leading bound consumed
    if (!raw) continue;
    const m = raw.replace(LONE_LEADING_COLON_RE, "").replace(LONE_TRAILING_COLON_RE, "");
    if (!HAS_HEX_RE.test(m)) continue;
    // Cheap pre-check first: every real IPv6 has a "::" or seven colons, so this prunes the common
    // non-address candidate without parsing it.
    const colons = (m.match(/:/g) ?? []).length;
    if (!m.includes("::") && colons < 7) continue;
    const lower = m.toLowerCase();
    if (isIpv6(lower)) out.add(lower);
  }
  return [...out].sort();
}
