// #1471 finding 6. An IOC carries one of three provenance stories, each with its own words:
// client-reported (#1266, a sender-controlled header), mentioned network (#1461, an address read
// out of free text — the host was TOLD about it, nothing says it CONTACTED it) and mentioned hash
// (#1459, a hash read out of free text — the author knew the hash, no file with it was seen).
// The words live in iocMentioned.ts and iocMentionedHash.ts, and each stays deliberately
// type-scoped because the false claim each note prevents is different.
//
// Codex review of #1471: every export that re-derives the three cases on its own is a consumer
// split waiting to be missed — Notion, MISP, IRIS and the dashboard table all carried the
// client-reported branch and none of the mentioned ones. This module composes the three into one
// answer for a value label so a consumer asks one question and cannot pick up one case alone.
// The strings are never re-typed here; they come from the constants the reports already use.
import type { IOC } from "./stateTypes.js";
import { isMentionedIoc, MENTIONED_NOTE } from "./iocMentioned.js";
import { isMentionedHash, MENTIONED_HASH_NOTE } from "./iocMentionedHash.js";

type ProvenanceInput = Pick<IOC, "type" | "provenance">;

/** The #1266 suffix, kept beside the other two so the three are visibly one set. */
const CLIENT_REPORTED_SUFFIX = " (client-reported)";

/**
 * The parenthesised provenance suffix for one IOC value, or "" for a plain sighting — so a caller
 * can append it unconditionally:
 *   " (client-reported)"                                            any type, provenance client-reported
 *   " (referenced in free text; no network record)"                 ip / domain / url, provenance mentioned
 *   " (mentioned in free text; no file with this hash was observed)" hash, provenance mentioned
 * The three are exclusive — an IOC carries one provenance — and a mentioned IOC of any other type
 * has no wording yet, so it comes back bare rather than with a note written for a different claim.
 */
export function iocProvenanceSuffix(ioc: ProvenanceInput): string {
  if (ioc.provenance === "client-reported") return CLIENT_REPORTED_SUFFIX;
  if (isMentionedIoc(ioc)) return ` (${MENTIONED_NOTE})`;
  if (isMentionedHash(ioc)) return ` (mentioned in free text; ${MENTIONED_HASH_NOTE})`;
  return "";
}

/**
 * The IOC table's Sources cell: the tool names, and for 2+ tools the corroboration marker "(⊕ N)".
 * A mentioned value (#1459 hash, #1461 network) has no structured sighting, so N tools that carry
 * it all parsed the same text — the cell says "(referenced in N)" and never ⊕ (#1474). "—" when
 * no sourced event references the value.
 */
export function iocSourcesLabel(ioc: ProvenanceInput, sources: readonly string[] | undefined): string {
  if (!sources || sources.length === 0) return "—";
  if (sources.length === 1) return sources[0];
  const mark = ioc.provenance === "mentioned" ? "referenced in" : "⊕";
  return `${sources.join(", ")} (${mark} ${sources.length})`;
}
