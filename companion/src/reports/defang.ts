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

const INDICATOR_RE =
  /\bhttps?:\/\/[^\s<>"'`|\]),]+|\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+|\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b/gi;

const IPV4_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;

// Punctuation that ends a sentence rather than the indicator, so it is put back untouched.
const TRAILING_PUNCTUATION_RE = /[.,;:!?'")\]}>]+$/;

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
  const known = new Set([...knownDomains].map((d) => d.trim().toLowerCase()).filter(Boolean));
  return text.replace(INDICATOR_RE, (match) => {
    const trailing = TRAILING_PUNCTUATION_RE.exec(match)?.[0] ?? "";
    const indicator = trailing ? match.slice(0, -trailing.length) : match;
    if (/^https?:\/\//i.test(indicator)) return defangUrl(indicator) + trailing;
    if (indicator.includes("@")) return defangEmail(indicator) + trailing;
    if (IPV4_RE.test(indicator)) return defangHost(indicator) + trailing;
    // A bare dotted token is only a domain when we can say so without guessing. Two cases qualify:
    // a `www.` host, which the Markdown autolinker turns into a live link on sight, and a value the
    // case itself records as a domain IOC. Guessing more widely would mangle the filenames a
    // forensic report is full of — `vitest.config.ts` and `History.db` have the shape of a domain
    // and a two-letter TLD, and analysis/textDomains deliberately accepts that class because for
    // IOC extraction a false positive is cheap. In a deliverable it is not.
    const lower = indicator.toLowerCase();
    if (lower.startsWith("www.") || known.has(lower)) return defangHost(indicator) + trailing;
    return match;
  });
}
