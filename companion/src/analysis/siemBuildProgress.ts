import { stampSourceArtifactHash } from "./canonicalEvent.js";
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
export class WindowsEventBuilder {
  private readonly iocSink = new Map<string, SiemIoc>();
  private readonly hostTally = new Map<string, number>();
  private readonly aggregator: EventAggregator;
  private readonly os = new OsBehaviourLedger();
  private held: { m: MappedEvent; rowSink: Map<string, SiemIoc> }[] = [];
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
    if (isOsBehaviourCandidateRow(record)) {
      this.os.offer(record, [mapped]);
      this.held.push({ m: mapped, rowSink });
      return;
    }
    mergeRowIocs(this.iocSink, rowSink, mapped.aggKey);
    this.aggregator.add(mapped);
  }

  /** Judge the held rows, then add each to the aggregator, yielding the running count. Idempotent. */
  *drainHeld(): Generator<number> {
    this.os.resolve();
    const held = this.held;
    this.held = [];
    for (const [i, { m, rowSink }] of held.entries()) {
      mergeRowIocs(this.iocSink, rowSink, m.aggKey);
      this.aggregator.add(m);
      yield i + 1;
    }
  }

  finish(sourceText?: string): SiemParseResult {
    Array.from(this.drainHeld()); // a no-op once the progress builder has drained them
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
  throwIfImportAborted(signal);
  return builder.finish(sourceText);
}
