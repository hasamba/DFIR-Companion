import type { IOC } from "./stateTypes.js";

// #1461. A network IOC (ip / domain / url) whose value was read out of FREE TEXT — a command line,
// a script block, a message body — carries `provenance: "mentioned"` (#1459, stateTypes.ts). The
// host was TOLD about that address; nothing says it CONTACTED it. INC-2026-028 finding f25 wrote
// "Outbound contact with 91.191.209.46" from an IP that appeared only in three loader command
// lines (`--reported-meterpreter-stage 91.191.209.46:12385`) while the host only ever reached
// loopback. Every network consumer that turns an IOC into a pin, an edge, a backbone line or a
// table cell goes through these helpers, so the wording lives in one place and a plain IOC (a
// Sysmon EID 3 DestinationIp, a netstat row, a DNS answer, a proxy line) keeps today's verbs.
//
// Network-only on purpose: a mentioned HASH invites a different false claim ("the file was there")
// and has its own words in iocMentionedHash.ts (#1459). These helpers answer false for it.

/** The one sentence every surface appends to a mentioned network IOC. */
export const MENTIONED_NOTE = "referenced in free text; no network record";

type MentionInput = Pick<IOC, "type" | "provenance"> | undefined;

const NETWORK_TYPES: ReadonlySet<IOC["type"]> = new Set(["ip", "domain", "url"]);

/** True only for a network IOC (ip / domain / url) with the exact `mentioned` provenance. */
export function isMentionedIoc(ioc: MentionInput): boolean {
  return ioc !== undefined && NETWORK_TYPES.has(ioc.type) && ioc.provenance === "mentioned";
}

/** The note for a mentioned network IOC, "" for any other — so callers can append it unconditionally. */
export function mentionedNote(ioc: MentionInput): string {
  return isMentionedIoc(ioc) ? MENTIONED_NOTE : "";
}

/** The parenthesised note for a table cell or a label: " (referenced in free text; no network record)". */
export function mentionedSuffix(ioc: MentionInput): string {
  return isMentionedIoc(ioc) ? ` (${MENTIONED_NOTE})` : "";
}

/** `value` plus the suffix when `flagged` — for renderers that carry a derived boolean (a geo marker, a graph node). */
export function mentionedLabel(value: string, flagged: boolean | undefined): string {
  return flagged ? `${value} (${MENTIONED_NOTE})` : value;
}

/**
 * The value with its provenance suffix, for an IOC table cell: "(client-reported)" (#1266) or the
 * mentioned note (#1461). The two are exclusive — an IOC carries one provenance — so a plain value
 * comes back untouched.
 */
export function iocValueLabel(ioc: Pick<IOC, "type" | "value" | "provenance">): string {
  if (ioc.provenance === "client-reported") return `${ioc.value} (client-reported)`;
  return mentionedLabel(ioc.value, isMentionedIoc(ioc));
}
