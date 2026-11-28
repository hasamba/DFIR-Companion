import { INTERNAL_TLDS } from "../../anonymize.js";
import { collectUsernames, shortHostLabels } from "../../anonUsernames.js";
import { learnableAccounts } from "../../assetGraph.js";
import { extractDomains } from "../../textDomains.js";
import type { PromptEntities } from "../maskRequest.js";
import { IP_LIKE } from "./hostLabel.js";

// Every hostname and username in a Watson prompt (spec §8). The case anonymizer only knows entities
// derived from state, so a hostname that arrives in an analyst paste, that Watson repeats from one, or
// that sits only inside an event description would otherwise reach the model in clear. ALL of them go
// to the masking step for ONE call (it de-duplicates against what it knows); they are never saved.
// The cost: a public domain in the case context (adversary infrastructure the case anonymizer keeps
// readable) is a token for Watson. IPs and emails need nothing here: the anonymizer finds those by
// pattern already.

// extractDomains drops the internal suffixes on purpose (they are not IOCs), but for masking they
// are the names that matter most. Built from the anonymizer's own INTERNAL_TLDS set, longest first,
// with the label shape and bound of textDomains.ts TEXT_DOMAIN_RE.
const INTERNAL_HOST_RE = new RegExp(
  `\\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.){1,127}(?:${[...INTERNAL_TLDS]
    .sort((a, b) => b.length - a.length)
    .join("|")})\\b`,
  "gi",
);

const isInternalHost = (h: string): boolean =>
  INTERNAL_TLDS.has(h.slice(h.lastIndexOf(".") + 1).toLowerCase());

// The short name of an extracted FQDN (#2056: synthesis masks `WS-PAY-07` and `WS-PAY-07$` for a known
// `ws-pay-07.corp…`). Only for an internal host or a machine-like label (a digit or a hyphen), so
// `login` in login.microsoftonline.com or `api`/`cdn` never become tokens.
function shortLabels(hosts: readonly string[]): string[] {
  const candidates = hosts.filter((h) => isInternalHost(h) || /[\d-]/.test(h.slice(0, h.indexOf("."))));
  return shortHostLabels(candidates, []);
}

/**
 * Final review F1: the names a persisted roster may take from free text. Each name as given, and a
 * short label only of an internal FQDN. A public FQDN's label (www, login, c2-node1) is never stored:
 * a stored label would mask that word in every later call and inside the FQDN in the export.
 * promptEntities still rebuilds a machine-like label from the stored FQDN for each AI send.
 */
export function storableHosts(names: readonly string[]): string[] {
  const internal = names.filter((h) => h.includes(".") && !IP_LIKE.test(h) && isInternalHost(h));
  return [...new Set([...names, ...shortHostLabels(internal, [])])];
}

/** Every FQDN in `text`: the extracted domains and the internal-TLD names, lower-cased. */
export function textFqdns(text: string): string[] {
  const fqdns = new Set(extractDomains(text));
  for (const m of text.matchAll(INTERNAL_HOST_RE)) fqdns.add(m[0].toLowerCase());
  return [...fqdns];
}

const clean = (names: readonly string[]): string[] =>
  names.map((n) => n.trim().toLowerCase()).filter((n) => n !== "");

/**
 * The hostnames and usernames in `text`, for the masking step of one call. `knownHosts` and
 * `knownUsers` are names the prompt shows from a roster (the Velociraptor inventory, the hosts and
 * accounts of shown super-timeline rows, a chat's persisted roster): each is masked as it is, so a
 * name the case state never held still never reaches the model in clear. A known FQDN's short label
 * is masked by the same rule as an extracted one, and an IP never gives one ("10" in 10.9.8.7). IPs
 * need no roster: the anonymizer matches them by pattern.
 */
export function promptEntities(
  text: string,
  knownHosts: readonly string[] = [],
  knownUsers: readonly string[] = [],
): PromptEntities {
  const fqdns = textFqdns(text);
  const roster = clean(knownHosts);
  const rosterLabels = shortLabels(roster.filter((h) => !IP_LIKE.test(h)));
  return {
    // No cap: a cap would fail open on a dense paste, and the prompt itself is already bounded.
    hosts: [...new Set([...fqdns, ...shortLabels(fqdns), ...roster, ...rosterLabels])],
    usernames: [
      ...new Set([
        ...collectUsernames({ texts: [text], accountsOf: learnableAccounts, internalDomains: [] }),
        ...clean(knownUsers),
      ]),
    ],
  };
}
