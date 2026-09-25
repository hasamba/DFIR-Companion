// The two cross-row OS-behaviour rules of #1593, for every importer that holds the raw record (#1621).
//
// A parent's handle to its own child at creation (processParentage.ts) and an AppX package update's
// firewall rule swap (appxFirewallChurn.ts) each need two things a per-row grader cannot see: the raw
// EventData (Sysmon GUIDs, the firewall rule identity) and every other row of the import. #1593 ran
// them inside the collector ledger (collectorChildren.ts), which only the Velociraptor and Chainsaw
// importers use. This module is the one wrapper every importer shares, so the rules themselves are
// written once and every bound they carry holds on every path: the GUID link, the 1-second creation
// window, fail-closed on conflicting parents, the EID 8 / EID 25 exceptions, the delete/add pair
// within 10 minutes under MpsSvc, and never lowering a Critical.
//
// The rules read `eventId(raw)` and `eventData(raw)` and nothing else from the record. A path whose
// rows carry no EventData object — a plain `hayabusa csv-timeline`, whose Details cell is a rendered
// " ¦ "-joined string — gives them nothing, so they stay silent there. That is deliberate: the
// rendered string holds values the intruder chose (a command line), and a split on "¦" would let one
// forge a `ParentProcessGuid` key.

import { getCI, isObject, str, type MappedEvent } from "./siemImport.js";
import { eventData, eventId } from "./veloDetectionNoise.js";
import { recordComputer, shortHostName } from "./hostIdentity.js";
import { isInjectionEvidenceRow, ParentChildAccessLedger } from "./processParentage.js";
import { AppxFirewallChurnLedger, isAppxFirewallRow } from "./appxFirewallChurn.js";

type Row = Record<string, unknown>;

const SYSMON_PROCESS_ACCESS = 10;
const EVENT_WRAPPERS = ["_Event", "Event"] as const;
/** How far a wrapper's own timestamp may sit from the embedded record's TimeCreated. */
export const ENVELOPE_TIME_SLACK_MS = 1000;

// The names a row can be filed under: the host the importer resolved AND the name the record itself
// carries. A renamed lab box (#1489) writes its old name into every record until the rename, and a
// bulk import may resolve the spawn before the rename evidence is read and the child after it — so
// a claim is stored and looked up under both, and two spellings of one machine still meet.
export function ledgerHostKeys(raw: Row, m: MappedEvent): string[] {
  return [...new Set([shortHostName(m.asset ?? ""), shortHostName(recordComputer(raw))].filter(Boolean))];
}

/** Is this raw record one the rules may LOWER — a process access or an AppX firewall change? */
export function isOsBehaviourCandidateRow(raw: Row): boolean {
  return (eventId(raw) === SYSMON_PROCESS_ACCESS && !!eventData(raw)) || isAppxFirewallRow(raw);
}

/**
 * Order-independent, like the collector ledger: `note` every row (process creations, remote threads,
 * tampering records, firewall changes), `offer` every row (only process accesses and firewall
 * changes are held), then `resolve` once every row of the import has been noted.
 */
export class OsBehaviourLedger {
  private readonly parentage = new ParentChildAccessLedger();
  private readonly firewall = new AppxFirewallChurnLedger();

  note(raw: Row, events: readonly (MappedEvent | null)[]): void {
    for (const m of events) {
      if (!m) continue;
      const hosts = ledgerHostKeys(raw, m);
      this.parentage.note(raw, m, hosts);
      this.firewall.note(raw, m, hosts);
    }
  }

  /** Hold candidates for `resolve`. A collector row is the collector ledger's, never this one's. */
  offer(raw: Row, events: readonly (MappedEvent | null)[]): void {
    for (const m of events) {
      if (!m || m.origin === "collector") continue;
      const hosts = ledgerHostKeys(raw, m);
      this.parentage.offer(raw, m, hosts);
      this.firewall.offer(raw, m, hosts);
    }
  }

  resolve(): void {
    this.parentage.resolve();
    this.firewall.resolve();
  }
}

// The embedded record's TimeCreated in epoch ms: Velociraptor writes epoch seconds, an XML-derived
// document an ISO string or `{ SystemTime }`. NaN when it names none.
function embeddedTime(system: Row): number {
  const tc = getCI(system, "TimeCreated");
  const v = isObject(tc) ? getCI(tc, "SystemTime") : tc;
  if (typeof v === "number") return v * 1000;
  const s = str(v).trim();
  if (/^\d+(?:\.\d+)?$/.test(s)) return Number(s) * 1000;
  return s ? Date.parse(s) : NaN;
}

/**
 * Does a wrapped row's own envelope agree with the record it wraps? A Hayabusa verdict row carries
 * its EID, Computer and Timestamp at the top AND the parsed record under `_Event`; `eventId` reads
 * the top one and `eventData` the embedded one. A lowering rule must not join the GUIDs of one
 * record to the EID, host or time of another, so a row whose two halves disagree fails closed. A row
 * with no wrapper (an XML-derived record) has one envelope and agrees trivially.
 */
export function envelopeAgrees(raw: Row, timestamp: string): boolean {
  const wrapped = EVENT_WRAPPERS.map((w) => getCI(raw, w)).filter(isObject);
  if (wrapped.length === 0) return true;
  // Exactly one record, and the EventData the rules will read must be THAT record's: `eventData`
  // prefers a top-level EventData, which would let a row validate one record and link another's
  // GUIDs (Codex, review of #1621).
  const [inner] = wrapped;
  if (wrapped.length > 1 || eventData(raw) !== getCI(inner, "EventData")) return false;
  const system = getCI(inner, "System");
  if (!isObject(system)) return false;
  if (eventId({ System: system }) !== eventId(raw)) return false;
  const outerHost = str(getCI(raw, "Computer")).trim().toLowerCase();
  const innerHost = str(getCI(system, "Computer")).trim().toLowerCase();
  if (outerHost && innerHost && outerHost !== innerHost) return false;
  const at = embeddedTime(system);
  return !Number.isFinite(at) || Math.abs(at - Date.parse(timestamp)) <= ENVELOPE_TIME_SLACK_MS;
}

/**
 * A whole-file importer's one call: note every row, offer every row, resolve. Mutates the rows. A
 * row whose envelope disagrees with its record (`envelopeAgrees`) is never offered and never vouches
 * for a link; it still counts as a remote thread / tampering record, which can only KEEP a grade.
 */
export function applyOsBehaviourRules(rows: Iterable<{ raw: Row; m: MappedEvent }>): void {
  const list = [...rows].map((r) => ({ ...r, trusted: envelopeAgrees(r.raw, r.m.timestamp) }));
  const ledger = new OsBehaviourLedger();
  for (const { raw, m, trusted } of list) if (trusted || isInjectionEvidenceRow(raw)) ledger.note(raw, [m]);
  for (const { raw, m, trusted } of list) if (trusted) ledger.offer(raw, [m]);
  ledger.resolve();
}
