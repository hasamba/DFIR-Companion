import { stampSourceArtifactHash } from "./canonicalEvent.js";
import {
  createEventAggregator,
  mapGeneric,
  mapWindows,
  maxEventsDefault,
  mergeRowIocs,
  pickHost,
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

export async function buildSiemResultProgress(
  records: Row[],
  format: string,
  opts: SiemImportOptions = {},
  sourceText?: string,
  onProgress?: (done: number, total: number) => void | Promise<void>,
  signal?: AbortSignal,
): Promise<SiemParseResult> {
  const total = records.length;
  const maxIocs = opts.maxIocs ?? 5000;
  const iocSink = new Map<string, SiemIoc>();
  const hostTally = new Map<string, number>();
  const aggregator = createEventAggregator({
    aggregate: opts.aggregate,
    minSeverity: opts.minSeverity,
    maxEvents: opts.maxEvents ?? maxEventsDefault(),
  });

  throwIfImportAborted(signal);
  for (const [recordIndex, record] of records.entries()) {
    const host = pickHost(record);
    if (host) hostTally.set(host, (hostTally.get(host) ?? 0) + 1);
    const rowSink = new Map<string, SiemIoc>();
    const mapped =
      mapWindows(record, host, rowSink, { source: format, recordIndex }) ?? mapGeneric(record, host, rowSink);
    mergeRowIocs(iocSink, rowSink, mapped.aggKey);
    aggregator.add(mapped);

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

  const { events, groups } = aggregator.finish();
  const finalEvents = sourceText ? stampSourceArtifactHash(events, sourceText) : events;
  const represented = finalEvents.reduce((count, event) => count + (event.count ?? 1), 0);
  const hostname = [...hostTally.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] ?? "";

  return {
    events: finalEvents,
    iocs: [...iocSink.values()].slice(0, maxIocs),
    total,
    kept: events.length,
    dropped: Math.max(0, total - represented),
    groups,
    format,
    hostname,
  };
}
