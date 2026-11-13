import { INTERNAL_TLDS } from "../../anonymize.js";
import { collectUsernames, shortHostLabels } from "../../anonUsernames.js";
import { extractAccounts } from "../../assetGraph.js";
import { extractDomains } from "../../textDomains.js";
import type { PromptEntities } from "../maskRequest.js";

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

const isInternalHost = (h: string): boolean => INTERNAL_TLDS.has(h.slice(h.lastIndexOf(".") + 1));

// The short name of an extracted FQDN (#2056: synthesis masks `WS-PAY-07` and `WS-PAY-07$` for a known
// `ws-pay-07.corp…`). Only for an internal host or a machine-like label (a digit or a hyphen), so
// `login` in login.microsoftonline.com or `api`/`cdn` never become tokens.
function shortLabels(hosts: readonly string[]): string[] {
  const candidates = hosts.filter((h) => isInternalHost(h) || /[\d-]/.test(h.slice(0, h.indexOf("."))));
  return shortHostLabels(candidates, []);
}

/** The hostnames and usernames in `text`, for the masking step of one call. */
export function promptEntities(text: string): PromptEntities {
  const fqdns = new Set(extractDomains(text));
  for (const m of text.matchAll(INTERNAL_HOST_RE)) fqdns.add(m[0].toLowerCase());
  return {
    // No cap: a cap would fail open on a dense paste, and the prompt itself is already bounded.
    hosts: [...new Set([...fqdns, ...shortLabels([...fqdns])])],
    usernames: collectUsernames({ texts: [text], accountsOf: extractAccounts, internalDomains: [] }),
  };
}
