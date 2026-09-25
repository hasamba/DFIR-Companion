import { stampSourceArtifactHash } from "./canonicalEvent.js";
import { boundDnsVariants } from "./dnsRecord.js";
import { isOsBehaviourCandidateRow, OsBehaviourLedger } from "./osBehaviourRules.js";
import {
  createEventAggregator,
  type EventAggregator,
  mapGeneric,
  mapWindows,
  maxEventsDefault,
  mergeRowIocs,
  pickHost,
  type MappedEvent,
  type SiemImportOptions,
  type SiemIoc,
  type SiemParseResult,
} from "./siemImport.js";
import {
  collectWindowsConnCandidate,
  runWindowsDnsConnJoin,
  type SiemConnCandidate,
} from "./siemDnsConnJoin.js";

type Row = Record<string, unknown>;

const YIELD_CHUNK_SIZE = 250;
const PROGRESS_CHUNK_SIZE = 5000;

export function throwIfImportAborted(signal?: AbortSignal): void {
  if (!signal?.aborted) return;
  const error = new Error("import processing cancelled; stored evidence retained");
  error.name = "AbortError";
  throw error;
}

async function yieldToServer(signal?: AbortSignal): Promise<void> {
  throwIfImportAborted(signal);
  await new Promise<void>((resolve) => setImmediate(resolve));
  throwIfImportAborted(signal);
}

// One Windows-event row at a time: map it, note it for the OS-behaviour rules, and hand it to the
// streaming aggregator — except a row those rules may LOWER (a Sysmon process access, an AppX
// firewall change), which waits with its own IOC sink until every row has been noted (#1621). Its
// IOCs merge only after the rules ran, under the aggKey the row finally carries, so provenance still
// finds it. Shared by the progress builder and the sync parseEvtxXml, so both give one answer.
//
// A DNS row waits too (#1636): variant bounding and the DNS→connection join (buildSiemResult's two
// whole-upload steps) rewrite its aggKey, and the join needs every connection first. Its IOCs merge
// at once, as buildSiemResult does, and both steps follow the rewrite through the IOC sink. A
// connection row is aggregated at once; only its small join candidate is kept.
export class WindowsEventBuilder {
  private readonly iocSink = new Map<string, SiemIoc>();
  private readonly hostTally = new Map<string, number>();
  private readonly aggregator: EventAggregator;
  private readonly os = new OsBehaviourLedger();
  private held: { m: MappedEvent; rowSink: Map<string, SiemIoc>; ordinal: number }[] = [];
  private dnsHeld: MappedEvent[] = [];
  private dnsOrdinals: number[] = [];
  private readonly conns: SiemConnCandidate[] = [];
  private total = 0;

  constructor(
    private readonly format: string,
    private readonly opts: SiemImportOptions = {},
  ) {
    this.aggregator = createEventAggregator({
      aggregate: opts.aggregate,
      minSeverity: opts.minSeverity,
      maxEvents: opts.maxEvents ?? maxEventsDefault(),
    });
  }

  add(record: Row, recordIndex: number): void {
    this.total++;
    const host = pickHost(record);
    if (host) this.hostTally.set(host, (this.hostTally.get(host) ?? 0) + 1);
    const rowSink = new Map<string, SiemIoc>();
    const mapped =
      mapWindows(record, host, rowSink, { source: this.format, recordIndex }) ??
      mapGeneric(record, host, rowSink);
    this.os.note(record, [mapped]);
    collectWindowsConnCandidate(this.conns, mapped);
    if (isOsBehaviourCandidateRow(record)) {
      this.os.offer(record, [mapped]);
      this.held.push({ m: mapped, rowSink, ordinal: recordIndex });
      return;
    }
    mergeRowIocs(this.iocSink, rowSink, mapped.aggKey);
    if (mapped.canonical?.dns) {
      this.dnsHeld.push(mapped);
      this.dnsOrdinals.push(recordIndex);
    } else this.aggregator.add(mapped, recordIndex);
  }

  /** Judge the held rows, then add each to the aggregator, yielding the running count. Idempotent. */
  *drainHeld(): Generator<number> {
    this.os.resolve();
    const held = this.held;
    this.held = [];
    for (const [i, { m, rowSink, ordinal }] of held.entries()) {
      mergeRowIocs(this.iocSink, rowSink, m.aggKey);
      this.aggregator.add(m, ordinal);
      yield i + 1;
    }
  }

  /** Bound and join the held DNS rows, then add each to the aggregator, yielding the running count. Idempotent. */
  *drainDns(): Generator<number> {
    const [dns, ordinals] = [this.dnsHeld, this.dnsOrdinals];
    this.dnsHeld = [];
    this.dnsOrdinals = [];
    if (!dns.length) return;
    if (this.opts.aggregate !== false) boundDnsVariants(dns, this.iocSink); // dnsRecord.ts, #933 item 2
    runWindowsDnsConnJoin(dns, this.iocSink, this.conns); // #996 — always after boundDnsVariants
    for (const [i, m] of dns.entries()) {
      this.aggregator.add(m, ordinals[i]);
      yield i + 1;
    }
  }

  finish(sourceText?: string): SiemParseResult {
    Array.from(this.drainHeld()); // a no-op once the progress builder has drained them
    Array.from(this.drainDns()); // likewise
    const { events, groups } = this.aggregator.finish();
    const finalEvents = sourceText ? stampSourceArtifactHash(events, sourceText) : events;
    const represented = finalEvents.reduce((count, event) => count + (event.count ?? 1), 0);
    const hostname = [...this.hostTally.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] ?? "";
    return {
      events: finalEvents,
      iocs: [...this.iocSink.values()].slice(0, this.opts.maxIocs ?? 5000),
      total: this.total,
      kept: events.length,
      dropped: Math.max(0, this.total - represented),
      groups,
      format: this.format,
      hostname,
    };
  }
}

/** The sync twin of buildSiemResultProgress, for callers that need no progress or cancellation. */
export function buildWindowsEventResult(
  records: Row[],
  format: string,
  opts: SiemImportOptions = {},
  sourceText?: string,
): SiemParseResult {
  const builder = new WindowsEventBuilder(format, opts);
  for (const [i, record] of records.entries()) builder.add(record, i);
  return builder.finish(sourceText);
}

export async function buildSiemResultProgress(
  records: Row[],
  format: string,
  opts: SiemImportOptions = {},
  sourceText?: string,
  onProgress?: (done: number, total: number) => void | Promise<void>,
  signal?: AbortSignal,
): Promise<SiemParseResult> {
  const total = records.length;
  const builder = new WindowsEventBuilder(format, opts);

  throwIfImportAborted(signal);
  for (const [recordIndex, record] of records.entries()) {
    builder.add(record, recordIndex);
    const done = recordIndex + 1;
    if (done % PROGRESS_CHUNK_SIZE === 0) {
      await onProgress?.(done, total);
    }
    if (done % YIELD_CHUNK_SIZE === 0) {
      await yieldToServer(signal);
    }
  }
  if (total % PROGRESS_CHUNK_SIZE !== 0) await onProgress?.(total, total);
  throwIfImportAborted(signal);
  // The held rows: a Sysmon-heavy export can hold many, so this phase yields and cancels too.
  for (const n of builder.drainHeld()) if (n % YIELD_CHUNK_SIZE === 0) await yieldToServer(signal);
  await yieldToServer(signal);
  // The held DNS rows (#1636): one bound + join pass, then the adds yield and cancel like the rest.
  for (const n of builder.drainDns()) if (n % YIELD_CHUNK_SIZE === 0) await yieldToServer(signal);
  throwIfImportAborted(signal);
  return builder.finish(sourceText);
}
