import { promptEntities, storableHosts, textFqdns } from "./pasteEntities.js";
import { isIdentifierToken, isNonHostValue } from "./rowTextVocab.js";
import type { WatsonMaskRoster } from "./superRoster.js";

// A host named only in free text: a raw row's description, a paste or a history excerpt. No host field
// names it, so neither the case anonymizer nor the roster's field rules know it, and promptEntities
// finds only FQDNs and internal-TLD names. Two conservative rules find it; their names join the
// persisted roster, so every later AI call on the case masks them. A wrong name hides evidence in all
// those calls, so each rule stays narrow. Accepted misses (see watson.md): a lowercase bare name, and
// a name with no hyphen (DC01).

// Rule 1: a host label, optional spaces, ":" or "=", an optional quote, then the value (any case or
// shape). Only spaces and tabs may sit around ":" or "=": a blank field never takes the next line.
const HOST_LABEL =
  /\b(?:workstation(?:\s?name)?|computer(?:\s?name)?|host(?:\s?name)?|machine\s?name|device\s?name|client\s?(?:name|hostname)|server\s?name|(?:source|src|destination|dst|target)\s?(?:host(?:name)?|workstation(?:\s?name)?|server\s?name))[ \t]*[:=][ \t]*"?([A-Za-z0-9][A-Za-z0-9._-]{0,252})/gi;
// A rule-1 value that names no host: a dash, N/A, null, none, unknown, localhost or an IPv4 literal.
const EMPTY_VALUE = /^(?:-+|n\/?a|n|null|none|unknown|localhost|\d{1,3}(?:\.\d{1,3}){3})$/i;
const TRAILING_PUNCT = /[._-]+$/;
// Rule 2: an uppercase token with a hyphen, not inside a path, a URL, an address or a longer word.
// A trailing "." then a space or the end is a sentence stop, not part of the name.
const MACHINE_NAME = /(?<![\w.$\\/@-])[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+(?![\w$\\/@-]|\.\w)/g;
const NETBIOS_MIN = 4;
const NETBIOS_MAX = 15;

/**
 * Whole identifier shapes that look like machine names, never a bare prefix: DEV-01, FIN-02, TA-01
 * and S1-DC01 are host names and stay maskable.
 */
export const NOT_A_HOST = new RegExp(
  "^(?:" +
    [
      "CVE-\\d{4}-\\d+",
      "CWE-\\d+",
      "CAPEC-\\d+",
      "GHSA(?:-[A-Z0-9]{4}){3}",
      "RFC-?\\d+",
      "ISO-?\\d+",
      "SHA-?\\d+",
      "MD-?\\d",
      "AES-\\d+(?:-[A-Z0-9]+)?",
      "RSA-\\d+",
      "UTF-\\d+",
      "UCS-\\d+",
      "TLS-?\\d",
      "SSL-?\\d",
      "IPV[46]-\\d+",
      "S-1-[\\d-]+",
      "APT-\\d+",
      "DEV-\\d{4}",
      "TA-?\\d{3,4}",
      "MS\\d{2}-\\d{3}",
      "KB-?\\d{6,7}",
      "T\\d{4}-\\d{3}",
      "TCP-\\d+",
      "UDP-\\d+",
      "HTTP-\\d{3}",
      "UTC-\\d{1,2}",
      "GMT-\\d{1,2}",
      "EID-\\d+",
      "ICSA-\\d{2}-\\d+-\\d+",
      "VU-\\d+",
      "COVID-\\d{2}",
    ].join("|") +
    ")$",
);

// A value followed by ":" (not a port number) is the next field's label, so the field was blank.
const NEXT_LABEL = /^:(?!\d)/;
/** Rule 1: each labelled value, cleaned, minus the stop words; only an internal FQDN gives its short label. */
function labelledHosts(text: string): string[] {
  const values = [...text.matchAll(HOST_LABEL)]
    .filter((m) => !NEXT_LABEL.test(text.slice(m.index + m[0].length)))
    .map((m) => (m[1] ?? "").replace(TRAILING_PUNCT, ""))
    .filter((v) => v.length >= 2 && !EMPTY_VALUE.test(v) && !isNonHostValue(v));
  return storableHosts(values);
}

/** Rule 2: machine-shaped bare tokens within the NetBIOS length, minus known identifier shapes. */
function machineNames(text: string): string[] {
  return [...text.matchAll(MACHINE_NAME)]
    .map((m) => m[0])
    .filter((t) => t.length >= NETBIOS_MIN && t.length <= NETBIOS_MAX)
    .filter((t) => /\d/.test(t) && !NOT_A_HOST.test(t) && !isIdentifierToken(t));
}

/** Each name once (case-insensitive), spelled as first printed. */
function distinctNames(names: readonly string[]): string[] {
  const seen = new Set<string>();
  return names.filter((n) => {
    const key = n.toLowerCase();
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/** The host names free text states, as printed (case kept; the roster lower-cases them on merge). */
export function descriptionHostNames(text: string | undefined): string[] {
  if (!text) return [];
  return distinctNames([...labelledHosts(text), ...machineNames(text)]);
}

/**
 * F7: the hosts and accounts a paste or history excerpt showed, by the rule the send masks with, plus
 * the free-text host names. They join the chat's roster like a super search's names, so a later
 * question masks them too. Undefined when the text names nothing.
 */
export function excerptRoster(text: string | undefined): WatsonMaskRoster | undefined {
  if (!text) return undefined;
  const { usernames } = promptEntities(text);
  const all = distinctNames([...storableHosts(textFqdns(text)), ...descriptionHostNames(text)]);
  return all.length || usernames.length ? { hosts: all, users: [...usernames], ips: [] } : undefined;
}
