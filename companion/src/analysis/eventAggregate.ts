import { SEVERITY_RANK, type Severity } from "./stateTypes.js";
import type { MappedEvent, SiemEvent } from "./siemImport.js";

/**
 * The aggregation half of the shared import path: collapse mapped rows into counted events, apply
 * the severity floor, sort, and cap. Lifted out of siemImport.ts, which is one of the ledgered
 * oversized files (#385) — the mapping half and the counting half are separate concerns that only
 * ever met because they grew in the same file.
 *
 * The types stay in siemImport.ts and are imported here TYPE-ONLY, so nothing is imported back at
 * runtime and the two modules do not form a cycle. siemImport re-exports everything below, so every
 * existing importer keeps its unchanged import site.
 */

// Safety cap on emitted events, shared by every importer. Overridable via DFIR_MAX_EVENTS
// (must be a positive integer to take effect; unset/invalid/non-positive values keep the
// default so a typo or DFIR_MAX_EVENTS=0 can't silently reintroduce the cap analysts meant to lift).
const DEFAULT_MAX_EVENTS = 2000;
export function maxEventsDefault(): number {
  const n = Number(process.env.DFIR_MAX_EVENTS);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : DEFAULT_MAX_EVENTS;
}

// ───────────────────────────── aggregation (shared) ─────────────────────────────

// Incremental accumulator behind aggregateEvents — collapse mapped events by aggKey into counted
// rows, apply the severity floor, then sort + cap on finish(). Exposed as an accumulator (not just
// the one-shot function) so a STREAMING caller (e.g. the Plaso file importer reading a 555 MB
// super-timeline line-by-line) can feed events one at a time without ever materializing the full
// mapped[] array — memory stays bounded by the distinct-key set, not the row count. Stateful.
export interface EventAggregator {
  add(m: MappedEvent): void;
  finish(): { events: SiemEvent[]; groups: number };
}

// Copies the fields that identify and describe ONE underlying row — description, severity, and
// every "which specific thing is this" field — onto `target`. Deliberately excludes the group-level
// accumulator fields (id, timestamp/endTimestamp, count, aggKey, mitreTechniques, sources), which
// the caller manages separately across a merge. A field absent on `m` is cleared, not left over
// from whichever row `target` previously described — a stale path/hash from a DIFFERENT row would
// misattribute it to the row actually being shown.
function applyEventIdentity(target: SiemEvent, m: MappedEvent): void {
  target.description = m.description;
  target.severity = m.severity;
  if (m.canonical) target.canonical = m.canonical;
  else delete target.canonical;
  if (m.sha256) target.sha256 = m.sha256;
  else delete target.sha256;
  if (m.md5) target.md5 = m.md5;
  else delete target.md5;
  if (m.path) target.path = m.path;
  else delete target.path;
  if (m.asset) target.asset = m.asset;
  else delete target.asset;
  if (m.processName) target.processName = m.processName;
  else delete target.processName;
  if (m.parentName) target.parentName = m.parentName;
  else delete target.parentName;
  if (m.pid !== undefined) target.pid = m.pid;
  else delete target.pid;
  if (m.commandLine) target.commandLine = m.commandLine;
  else delete target.commandLine;
  if (m.srcIp) target.srcIp = m.srcIp;
  else delete target.srcIp;
  if (m.dstIp) target.dstIp = m.dstIp;
  else delete target.dstIp;
  if (m.port) target.port = m.port;
  else delete target.port;
  if (m.artifactName) target.artifactName = m.artifactName;
  else delete target.artifactName;
  if (m.message) target.message = m.message;
  else delete target.message;
  if (m.sourceRecordId) target.sourceRecordId = m.sourceRecordId;
  else delete target.sourceRecordId;
}

export function createEventAggregator(
  opts: { aggregate?: boolean; minSeverity?: Severity; maxEvents?: number } = {},
): EventAggregator {
  const aggregate = opts.aggregate ?? true;
  const maxEvents = opts.maxEvents ?? maxEventsDefault();
  const floorRank = opts.minSeverity ? SEVERITY_RANK[opts.minSeverity] : Infinity;

  const byKey = new Map<string, SiemEvent>();
  const order: string[] = [];

  return {
    add(m: MappedEvent): void {
      if (SEVERITY_RANK[m.severity] > floorRank) return; // below the severity floor
      const key = aggregate ? m.aggKey : `${order.length}`; // no-agg ⇒ unique key per row
      const existing = byKey.get(key);
      if (existing) {
        existing.count = (existing.count ?? 1) + 1;
        // STICKY, unlike every identity field below: a collapsed group whose rows disagree about
        // whether the year was recorded is ambiguous as a whole, so one year-less row makes the
        // group clamp-eligible and no later row can clear it. Deliberately NOT in
        // applyEventIdentity, which clears a field the incoming row lacks (#739).
        if (m.yearInferred) existing.yearInferred = true;
        const t = m.timestamp;
        if (t) {
          if (!existing.timestamp || t < existing.timestamp) existing.timestamp = t;
          if (!existing.endTimestamp || t > existing.endTimestamp) existing.endTimestamp = t;
        }
        for (const mt of m.mitre)
          if (!existing.mitreTechniques.includes(mt)) existing.mitreTechniques.push(mt);
        if (m.sources)
          for (const s of m.sources) {
            existing.sources ??= [];
            if (!existing.sources.includes(s)) existing.sources.push(s);
          }
        // Two rows can share an aggKey while differing meaningfully in risk (e.g. the same
        // PersistenceSniper startup-item name across two user SIDs, one signed and ordinary, one
        // an unsigned LOLBin — the digit-stripped key folds them together). worst()-ing only the
        // severity NUMBER left description/path/hashes pinned to whichever row was seen first, so
        // an analyst could see "High" attached to text that describes the benign twin, with
        // nothing in the row explaining the grade. When the incoming row is STRICTLY more severe,
        // promote the whole displayed record to it — never just the number.
        if (SEVERITY_RANK[m.severity] < SEVERITY_RANK[existing.severity]) {
          applyEventIdentity(existing, m);
        }
        // `count` records repeats; retaining one instance's identity avoids unbounded provenance arrays.
      } else {
        const e: SiemEvent = {
          id: "",
          timestamp: m.timestamp,
          description: "",
          severity: "Info",
          mitreTechniques: [...m.mitre],
          count: 1,
          aggKey: m.aggKey,
          ...(m.sources?.length ? { sources: [...m.sources] } : {}),
          ...(m.yearInferred ? { yearInferred: true } : {}),
        };
        applyEventIdentity(e, m);
        byKey.set(key, e);
        order.push(key);
      }
    },
    finish(): { events: SiemEvent[]; groups: number } {
      // Drop the synthetic count:1 marker on un-aggregated singletons for a cleaner timeline.
      const events = order.map((k) => byKey.get(k)!);
      for (const e of events) if (e.count === 1) delete e.count;
      // A group that collapsed several rows no longer stands for ONE log record, so the record
      // identity carried over from whichever row set the group's identity would be a lie — and
      // cross-parser correlation keys on it (#688). Only a singleton keeps it.
      for (const e of events) if ((e.count ?? 1) > 1) delete e.sourceRecordId;
      const groups = events.length;

      // Most-severe first, then noisiest, then earliest — then cap.
      events.sort(
        (a, b) =>
          SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] ||
          (b.count ?? 1) - (a.count ?? 1) ||
          (a.timestamp || "~").localeCompare(b.timestamp || "~"),
      );

      return { events: events.slice(0, maxEvents), groups };
    },
  };
}

// Collapse mapped events by their aggKey into counted rows, apply the severity floor,
// sort (most-severe → noisiest → earliest) and cap. Shared by the SIEM and Chainsaw/EVTX
// importers so both aggregate, sort, and cap identically. Returns the capped rows plus the
// group count BEFORE the cap (so callers can report "N over the cap"). Pure.
export function aggregateEvents(
  mapped: Iterable<MappedEvent>,
  opts: { aggregate?: boolean; minSeverity?: Severity; maxEvents?: number } = {},
): { events: SiemEvent[]; groups: number } {
  const agg = createEventAggregator(opts);
  for (const m of mapped) agg.add(m);
  return agg.finish();
}
