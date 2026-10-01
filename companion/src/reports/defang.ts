// Defang indicators in human-readable report output.
//
// The incident report is the artifact that travels furthest — to managers, to counsel, to the
// client — and it is read by people who click things. Standard DFIR practice is to render every
// indicator inert so a mis-click cannot reach attacker infrastructure from the reader's machine.
// Rendering them as `hxxp://evil[.]example` also stops the Markdown renderer autolinking them,
// so the same pass removes both the live text and the anchor it would have become. #883.
//
// This is the inverse of analysis/iocValue.refangIocValue, and deliberately mirrors its rule about
// scope: only the scheme and authority are rewritten, because that is the part a click acts on. The
// path, query and fragment are left exactly as found — they may legitimately contain the same
// character sequences, and rewriting them would change a string that correlation and retrieval
// depend on matching. A defanged value round-trips back through refangIocValue.
//
// Applies to the human-readable report only. The machine-consumed exports (CSV, STIX, the ATT&CK
// Navigator layer, the JSON state) keep live values, because the tools that ingest them match on
// the real indicator.

// One combined pattern so each indicator is rewritten exactly once, and text between matches is
// never touched. Order matters: a URL is tried before the email, bare-IPv4 and bare-domain forms,
// so a host inside a URL is handled by the URL branch — which leaves the path alone — rather than
// being matched again by the domain branch further along the same span.
import type { InvestigationState } from "../analysis/stateTypes.js";

/**
 * Domain values the case itself records as indicators, for defangIndicators' second argument.
 * Keeps the "is this a domain" decision on data the case already asserted, rather than on a guess
 * about the shape of a dotted token.
 */
export function caseDomains(state: InvestigationState): string[] {
  return state.iocs.filter((ioc) => ioc.type === "domain").map((ioc) => ioc.value);
}

/**
 * The part of a domain IOC value a click can reach: the value without the wrapper characters an
 * indicator list puts around a name — the `*.` of a wildcard, the root dot of `evil.example.`, a
 * stray leading `-` or `%` (#1909). `_` stays, because it is part of a label. Case is kept.
 */
export function domainCore(value: string): string {
  return trimEdges(value.trim(), (c) => !/[A-Za-z0-9_]/.test(c));
}

// Drop the characters `strip` accepts from both ends. An index walk, not a `^x+|x+$` regex: that
// regex's second branch restarts at every position of a long internal run and is quadratic on it.
function trimEdges(value: string, strip: (c: string) => boolean): string {
  let start = 0;
  let end = value.length;
  while (start < end && strip(value[start])) start++;
  while (end > start && strip(value[end - 1])) end--;
  return value.slice(start, end);
}

// Every quantifier in the email and domain branches is bounded (#1907). Unbounded, a branch that
// starts at each word boundary inside a long run (`a-a-a-…`, `a+a+…`, `1.1.1.…`) scanned to the end of
// the run before failing, which is quadratic: 200 KB of description froze the server for most of a
// minute. Bounded, a failing attempt costs a constant and the whole pass is linear. The bounds are the
// DNS limits (a label is at most 63 characters, a name at most 127 labels) and a generous local part;
// a longer local part still has its `@` and domain defanged, from a later start inside it.
//
// A label also takes `_` (#1909): C2 and DGA names (`c2_node.evil.example`) and service records
// (`_sip._tcp.…`) carry one, and without it such a name never matched as one token, so it never
// equalled the domain IOC the case recorded and reached the report live.
const LABEL = "[A-Za-z0-9_-]{1,63}";
const DOTTED_NAME = `${LABEL}(?:\\.${LABEL}){1,126}`;
const INDICATOR_RE = new RegExp(
  [
    // Not `\\b`: the GFM autolinker accepts a URL right after `_` (emphasis), and `_` is a word
    // character, so `\\b` let `_http://…_` through live. Any non-alphanumeric may come before.
    "(?<![A-Za-z0-9])https?:\\/\\/[^\\s<>\"'`|\\]),]+",
    `\\b[A-Za-z0-9._%+-]{1,256}@${DOTTED_NAME}`,
    "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b",
    `\\b${DOTTED_NAME}\\b`,
  ].join("|"),
  "gi",
);

const IPV4_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;

// Punctuation that ends a sentence rather than the indicator, so it is put back untouched. Found
// with a backwards walk, not a `[…]+$` regex: that regex restarts at every character of a long
// punctuation run inside the match and is quadratic on it (#1907).
const TRAILING_PUNCTUATION = new Set(".,;:!?'\")]}>");

function trailingPunctuationStart(match: string): number {
  let end = match.length;
  while (end > 0 && TRAILING_PUNCTUATION.has(match[end - 1])) end--;
  return end;
}

function defangHost(host: string): string {
  return host.replace(/\./g, "[.]");
}

function defangUrl(url: string): string {
  const scheme = /^(https?)(:\/\/)/i.exec(url);
  if (!scheme) return url;
  // http -> hxxp, https -> hxxps, preserving the case the report already used.
  const neutered = scheme[1].replace(/t/gi, (c) => (c === "T" ? "X" : "x"));
  const rest = url.slice(scheme[0].length);
  const pathStart = rest.search(/[/?#]/);
  const authority = pathStart === -1 ? rest : rest.slice(0, pathStart);
  const tail = pathStart === -1 ? "" : rest.slice(pathStart);
  return `${neutered}${scheme[2]}${defangHost(authority)}${tail}`;
}

function defangEmail(email: string): string {
  const at = email.indexOf("@");
  return `${email.slice(0, at)}[@]${defangHost(email.slice(at + 1))}`;
}

/**
 * Render every URL, email address and IPv4 address in `text` inert.
 *
 * Idempotent: already-defanged text contains no bare scheme, `@` or dotted quad for the pattern to
 * match, so running it twice is the same as running it once.
 */
export function defangIndicators(text: string, knownDomains: Iterable<string> = []): string {
  const known = new Set(
    [...knownDomains].flatMap((d) => [d.trim().toLowerCase(), domainCore(d).toLowerCase()]).filter(Boolean),
  );
  return text.replace(INDICATOR_RE, (match) => {
    const cut = trailingPunctuationStart(match);
    const trailing = match.slice(cut);
    const indicator = match.slice(0, cut);
    if (/^https?:\/\//i.test(indicator)) return defangUrl(indicator) + trailing;
    if (indicator.includes("@")) return defangEmail(indicator) + trailing;
    if (IPV4_RE.test(indicator)) return defangHost(indicator) + trailing;
    // A bare dotted token is only a domain when we can say so without guessing. Two cases qualify:
    // a `www.` host, which the Markdown autolinker turns into a live link on sight, and a value the
    // case itself records as a domain IOC. Guessing more widely would mangle the filenames a
    // forensic report is full of — `vitest.config.ts` and `History.db` have the shape of a domain
    // and a two-letter TLD, and analysis/textDomains deliberately accepts that class because for
    // IOC extraction a false positive is cheap. In a deliverable it is not.
    // `_` is part of a label, so a Markdown emphasis wrapper (`_evil.example_`) rides along inside
    // the token; the name is also tried without edge underscores.
    const lower = indicator.toLowerCase();
    const unwrapped = trimEdges(lower, (c) => c === "_");
    if (unwrapped.startsWith("www.") || known.has(lower) || known.has(unwrapped))
      return defangHost(indicator) + trailing;
    return match;
  });
}
