import { INTERNAL_TLDS } from "../../anonymize.js";
import { collectUsernames, shortHostLabels } from "../../anonUsernames.js";
import { extractAccounts } from "../../assetGraph.js";
import { escapeRegExp } from "../../regexEscape.js";
import { extractDomains } from "../../textDomains.js";
import type { PromptEntities } from "../maskRequest.js";

// Hostnames and usernames in a Watson prompt that the case has never seen (spec §8). The case
// anonymizer only knows entities derived from state, so a hostname that arrives in an analyst paste
// (or that Watson repeats from one later) would otherwise reach the model in clear. These go to the
// masking step for ONE call; they are never saved. IPs and emails need nothing here: the anonymizer
// finds those by pattern already.

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

function wholeWord(value: string): RegExp {
  return new RegExp(`(?<![\\p{L}\\p{N}_.-])${escapeRegExp(value)}(?![\\p{L}\\p{N}_-])`, "iu");
}

/** Entities in `text` that do not appear in `seen` (the case context the state already governs). */
export function unseenPromptEntities(text: string, seen: string): PromptEntities {
  const fqdns = new Set(extractDomains(text));
  for (const m of text.matchAll(INTERNAL_HOST_RE)) fqdns.add(m[0].toLowerCase());
  const hosts = new Set([...fqdns, ...shortLabels([...fqdns])]);
  const usernames = collectUsernames({ texts: [text], accountsOf: extractAccounts, internalDomains: [] });
  const unseen = (v: string): boolean => !wholeWord(v).test(seen);
  return {
    // No cap: a cap would fail open on a dense paste, and the prompt itself is already bounded.
    hosts: [...hosts].filter(unseen),
    usernames: usernames.filter(unseen),
  };
}
