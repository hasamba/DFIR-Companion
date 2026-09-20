// #1459: a hash the collector COMPUTED for a file (`Hashes: SHA256=…`, a `SHA256` column,
// `hashes_ex`) is evidence the file was on the host. A hash read out of FREE TEXT — a script block,
// a command line, a message — is evidence the author knew the hash, and nothing more. The importer
// marks the second kind `provenance: "mentioned"` (stateTypes.ts); this module is where every
// consumer that would otherwise read "verified hash" as "verified file" gets its words.
//
// INC-2026-028 finding f12 (Critical) said a CrowdStrike-confirmed Mimic sample was "present in
// the toolkit directory". No file with that hash existed: the simulation script assigned it to a
// variable (`$primaryHash = '…'`) inside an EID 4104 script block, the scrape made it a `hash`
// IOC, enrichment verified the string, and the synthesis read a verified hash as a verified file.
//
// Hash-only on purpose. The network half (ip / domain / url, #1461) has its own wording in
// iocMentioned.ts; a hash needs different words because the false claim it invites is different
// ("the file was there", not "the host contacted it").
import type { ForensicEvent, IOC } from "./stateTypes.js";

export const MENTIONED_HASH_NOTE = "no file with this hash was observed";
const EVENT_TEXT_MAX = 160;

/** True only for a `hash` IOC marked `mentioned`; absent provenance is an observed value. */
export function isMentionedHash(ioc: Pick<IOC, "type" | "provenance">): boolean {
  return ioc.type === "hash" && ioc.provenance === "mentioned";
}

// The event whose text carries the mention: the authoritative link first (extractedFrom, set by the
// importer), else the first in-scope event whose description contains the value. The description is
// what the analyst and the model both read, so quoting it is what lets either see the `$primaryHash =`
// around the string and judge it.
function mentionSource(
  ioc: Pick<IOC, "value" | "extractedFrom">,
  events: readonly ForensicEvent[],
): ForensicEvent | undefined {
  const linked = new Set(ioc.extractedFrom ?? []);
  if (linked.size) {
    const hit = events.find((e) => linked.has(e.id));
    if (hit) return hit;
  }
  const v = ioc.value.trim().toLowerCase();
  return v ? events.find((e) => (e.description ?? "").toLowerCase().includes(v)) : undefined;
}

function clip(text: string): string {
  const one = text.replace(/\s+/g, " ").trim();
  return one.length > EVENT_TEXT_MAX ? `${one.slice(0, EVENT_TEXT_MAX - 1)}…` : one;
}

/**
 * `mentioned in <event text>; no file with this hash was observed` for a mentioned hash, "" for
 * any other IOC — so a caller can append it unconditionally. Names the event so the reader can
 * tell "the script references a known sample" from "the sample was on the host".
 */
export function mentionedHashNote(
  ioc: Pick<IOC, "type" | "value" | "provenance" | "extractedFrom">,
  events: readonly ForensicEvent[],
): string {
  if (!isMentionedHash(ioc)) return "";
  const src = mentionSource(ioc, events);
  const where = src ? `"${clip(src.description)}"` : "free text (no source event in scope)";
  return `mentioned in ${where}; ${MENTIONED_HASH_NOTE}`;
}
