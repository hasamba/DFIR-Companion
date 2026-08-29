// Identity of ONE physical Windows event-log record, shared by every importer that reads EVTX —
// whether it read the file directly (evtx XML), or read a parser's verdicts about it (Hayabusa,
// Chainsaw, Velociraptor's parsed-eventlog rows).
//
// Why it exists (#688): an analyst routinely parses the same Security.evtx twice — once with
// Hayabusa, later with Chainsaw — and the two tools word their output completely differently, so
// the exact time+text dedup in correlate.ts step 0 cannot tell that both describe the same record.
// The result was a timeline that doubled every time the evidence was re-parsed with a second tool.
// A Windows record carries its own identity, so use that instead of guessing from prose.
//
// The pair (Channel, EventRecordID) is unique WITHIN one host's log: EventRecordID is a per-channel
// monotonic counter the Event Log service assigns. It is NOT unique across hosts — every machine
// has its own record 4711 — so callers add the host to the key (correlate.ts does exactly that).
//
// Pure, and deliberately strict: a value is minted only when BOTH parts are present and the record
// id is a plain positive integer. A half-identity would correlate records that are not the same.

/** The canonical prefix, so a future non-EVTX record identity cannot collide with these. */
const EVTX_PREFIX = "evtx";

/**
 * `evtx:<channel>:<recordId>` for a Windows event-log record, or undefined when either part is
 * missing or malformed. The channel is lowercased so "Security" and "security" agree; the record id
 * is kept verbatim after the digits check.
 */
export function evtxRecordIdentity(channel: unknown, recordId: unknown): string | undefined {
  const ch = String(channel ?? "")
    .trim()
    .toLowerCase();
  const id = String(recordId ?? "").trim();
  if (!ch) return undefined;
  if (!/^\d{1,20}$/.test(id)) return undefined;
  // "0" is what a parser emits when it had no record id to report, not a real record.
  if (/^0+$/.test(id)) return undefined;
  return `${EVTX_PREFIX}:${ch}:${id}`;
}
