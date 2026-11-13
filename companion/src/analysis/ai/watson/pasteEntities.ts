import { collectUsernames } from "../../anonUsernames.js";
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
// are the names that matter most. Same label shape and bound as textDomains.ts TEXT_DOMAIN_RE.
const INTERNAL_HOST_RE =
  /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,127}(?:local|localdomain|internal|lan|home|corp)\b/gi;

const MAX_ENTITIES = 500;

function wholeWord(value: string): RegExp {
  return new RegExp(`(?<![\\p{L}\\p{N}_.-])${escapeRegExp(value)}(?![\\p{L}\\p{N}_-])`, "iu");
}

/** Entities in `text` that do not appear in `seen` (the case context the state already governs). */
export function unseenPromptEntities(text: string, seen: string): PromptEntities {
  const hosts = new Set(extractDomains(text));
  for (const m of text.matchAll(INTERNAL_HOST_RE)) hosts.add(m[0].toLowerCase());
  const usernames = collectUsernames({ texts: [text], accountsOf: extractAccounts, internalDomains: [] });
  const unseen = (v: string): boolean => !wholeWord(v).test(seen);
  return {
    hosts: [...hosts].filter(unseen).slice(0, MAX_ENTITIES),
    usernames: usernames.filter(unseen).slice(0, MAX_ENTITIES),
  };
}
